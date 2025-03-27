// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
)

type progFlags struct {
	all         bool
	ids         map[uint32]string // progID -> funcName
	tags        map[string]string // tag -> funcName
	names       map[string]string // entryFuncName -> funcName
	pinnedPaths map[string]string // pinnedPath -> funcName
	pids        map[uint32]string // pid -> funcName
}

func newProgFlags(pflags []ProgFlag) progFlags {
	var pf progFlags
	pf.ids = make(map[uint32]string)
	pf.tags = make(map[string]string)
	pf.names = make(map[string]string)
	pf.pinnedPaths = make(map[string]string)
	pf.pids = make(map[uint32]string)

	for _, f := range pflags {
		if f.all {
			pf.all = true
			return pf
		}

		switch f.descriptor {
		case progFlagDescriptorID:
			pf.ids[f.progID] = f.funcName

		case progFlagDescriptorTag:
			pf.tags[f.tag] = f.funcName

		case progFlagDescriptorName:
			pf.names[f.name] = f.funcName

		case progFlagDescriptorPinned:
			pf.pinnedPaths[f.pinned] = f.funcName

		case progFlagDescriptorPid:
			pf.pids[f.pid] = f.funcName
		}
	}

	return pf
}

func (p progFlags) allID() bool {
	return len(p.ids) != 0 &&
		len(p.tags) == 0 &&
		len(p.names) == 0 &&
		len(p.pinnedPaths) == 0 &&
		len(p.pids) == 0 &&
		!p.all
}

func (p *bpfProgs) prepareProgInfoByID(id ebpf.ProgramID, funcName string) error {
	prog, err := ebpf.NewProgramFromID(id)
	if err != nil {
		return fmt.Errorf("failed to load prog %d: %w", id, err)
	}
	defer prog.Close()

	if funcName == "" {
		info, err := prog.Info()
		if err != nil {
			return fmt.Errorf("failed to get prog info: %w", err)
		}

		funcName, err = getProgEntryFuncName(info)
		if err != nil {
			return fmt.Errorf("failed to get prog entry func name: %w", err)
		}
	}

	return p.addTracing(id, funcName, prog)
}

func (p *bpfProgs) prepareProgInfosByIDs(pflags []ProgFlag) error {
	for i := range pflags {
		id := ebpf.ProgramID(pflags[i].progID)
		funcName := pflags[i].funcName
		if err := p.prepareProgInfoByID(id, funcName); err != nil {
			return err
		}
	}

	return nil
}

func (p *bpfProgs) prepareProgInfoByPinnedPath(pflag ProgFlag) error {
	prog, err := ebpf.LoadPinnedProgram(pflag.pinned, nil)
	if err != nil {
		return fmt.Errorf("failed to load pinned prog %s: %w", pflag.pinned, err)
	}
	defer prog.Close()

	info, err := prog.Info()
	if err != nil {
		return fmt.Errorf("failed to get prog info of prog %s: %w", pflag.pinned, err)
	}

	funcName, err := getProgFuncName(pflag.funcName, info)
	if err != nil {
		return fmt.Errorf("failed to get prog func name: %w", err)
	}

	id, ok := info.ID()
	if !ok {
		return fmt.Errorf("failed to get prog ID")
	}

	return p.addTracing(id, funcName, prog)
}

func (p *bpfProgs) addProgByID(id ebpf.ProgramID, funcName string) error {
	prog, err := ebpf.NewProgramFromID(id)
	if err != nil {
		return fmt.Errorf("failed to load prog from ID %d: %w", id, err)
	}
	defer prog.Close()

	info, err := prog.Info()
	if err != nil {
		return fmt.Errorf("failed to get prog info: %w", err)
	}

	funcName, err = getProgFuncName(funcName, info)
	if err != nil {
		return fmt.Errorf("failed to get prog func name: %w", err)
	}

	return p.addTracing(id, funcName, prog)
}

func (p *bpfProgs) prepareProgInfoByPid(pflag ProgFlag) error {
	dirpath := fmt.Sprintf("/proc/%d/fd", pflag.pid)
	return fs.WalkDir(os.DirFS(dirpath), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		filepath := filepath.Join(dirpath, d.Name())
		link, err := os.Readlink(filepath)
		if err != nil {
			return nil
		}

		if strings.TrimSpace(link) != "anon_inode:bpf-prog" {
			return nil
		}

		fdinfoPath := fmt.Sprintf("/proc/%d/fdinfo/%s", pflag.pid, d.Name())
		fd, err := os.Open(fdinfoPath)
		if err != nil {
			return nil
		}
		defer fd.Close()

		scanner := bufio.NewScanner(fd)
		for scanner.Scan() {
			line := scanner.Text()
			if !strings.HasPrefix(line, "prog_id:") {
				continue
			}

			progID := strings.Fields(line)[1]
			id, err := strconv.ParseUint(progID, 10, 32)
			if err != nil {
				return fmt.Errorf("failed to parse progID %s from %s: %w", progID, fdinfoPath, err)
			}

			err = p.addProgByID(ebpf.ProgramID(id), pflag.funcName)
			if err != nil {
				return err
			}

			break
		}

		if err = scanner.Err(); err != nil {
			return fmt.Errorf("failed to scan %s: %w", fdinfoPath, err)
		}

		return nil
	})
}

func (p *bpfProgs) prepareProgInfo(progID ebpf.ProgramID, pflags progFlags) error {
	prog, err := ebpf.NewProgramFromID(progID)
	if err != nil {
		return fmt.Errorf("failed to load prog %d: %w", progID, err)
	}
	defer prog.Close()

	info, err := prog.Info()
	if err != nil {
		return fmt.Errorf("failed to get prog info: %w", err)
	}

	if _, ok := info.BTFID(); !ok {
		// Skip non-BTF programs.
		return nil
	}

	entryFuncName, err := getProgEntryFuncName(info)
	if err != nil {
		return fmt.Errorf("failed to get prog entry func name: %w", err)
	}

	if pflags.all {
		return p.addTracing(progID, entryFuncName, prog)
	}

	tag := info.Tag

	if funcName, ok := pflags.ids[uint32(progID)]; ok {
		if funcName == "" {
			funcName = entryFuncName
		}
		if err := p.addTracing(progID, funcName, prog); err != nil {
			return err
		}
	}

	if funcName, ok := pflags.tags[tag]; ok {
		if funcName == "" {
			funcName = entryFuncName
		}
		if err := p.addTracing(progID, funcName, prog); err != nil {
			return err
		}
	}

	if funcName, ok := pflags.names[entryFuncName]; ok {
		if funcName == "" {
			funcName = entryFuncName
		}
		if err := p.addTracing(progID, funcName, prog); err != nil {
			return err
		}
	}

	return nil
}

func (p *bpfProgs) prepareProgInfos(pflags []ProgFlag) error {
	flags := newProgFlags(pflags)
	if flags.allID() {
		return p.prepareProgInfosByIDs(pflags)
	}

	for _, f := range pflags {
		switch f.descriptor {
		case progFlagDescriptorPinned:
			if err := p.prepareProgInfoByPinnedPath(f); err != nil {
				return err
			}

		case progFlagDescriptorPid:
			if err := p.prepareProgInfoByPid(f); err != nil {
				return err
			}
		}
	}

	for progID, err := ebpf.ProgramGetNextID(0); err == nil; progID, err = ebpf.ProgramGetNextID(progID) {
		if err := p.prepareProgInfo(progID, flags); err != nil {
			return err
		}
	}

	return nil
}

func getProgFuncName(funcName string, info *ebpf.ProgramInfo) (string, error) {
	if funcName != "" {
		return funcName, nil
	}

	return getProgEntryFuncName(info)
}

// getProgEntryFuncName returns the name of the entry function in the program.
func getProgEntryFuncName(info *ebpf.ProgramInfo) (string, error) {
	if _, ok := info.BTFID(); !ok {
		return "", errors.New("program does not have BTF ID")
	}

	insns, err := info.Instructions()
	if err != nil {
		return "", fmt.Errorf("failed to get program instructions: %w", err)
	}

	if sym := insns[0].Symbol(); sym != "" {
		return sym, nil
	}

	return "", errors.New("no entry func name found in program")
}
