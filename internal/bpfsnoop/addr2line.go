// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Asphaltt/addr2line"
	"github.com/klauspost/compress/zstd"
)

const (
	debugModulesPath = "/usr/lib/debug/lib/modules/"
)

type kmodAddr2line struct {
	*addr2line.Addr2Line
	kaslr Kaslr
}

// Addr2Line is a wrapper around addr2line.Addr2Line with a cache.
type Addr2Line struct {
	ready bool
	err   error
	done  chan struct{}

	vmlinux string
	a2l     *addr2line.Addr2Line
	kmods   map[string]kmodAddr2line
	cache   *dbgsymCache

	sysBPF   uint64
	stext    uint64
	kaslr    Kaslr
	buildDir string
}

func (a2l *Addr2Line) create() {
	__a2l, err := addr2line.New(a2l.vmlinux)
	if err != nil {
		a2l.err = fmt.Errorf("failed to create addr2line from %s: %w", a2l.vmlinux, err)
		return
	}

	eaddr := a2l.kaslr.effectiveAddr(a2l.sysBPF)
	sysBpfLineInfo, err := __a2l.Get(eaddr, true)
	if err != nil {
		a2l.err = fmt.Errorf("failed to get addr2line entry for __x64_sys_bpf: %w", err)
		return
	}

	const bpfSyscallFile = "kernel/bpf/syscall.c"
	if len(sysBpfLineInfo.File) < len(bpfSyscallFile) {
		a2l.err = fmt.Errorf("unexpected file name for __x64_sys_bpf: %s", sysBpfLineInfo.File)
		return
	}

	a2l.buildDir = sysBpfLineInfo.File[:len(sysBpfLineInfo.File)-len(bpfSyscallFile)]
	close(a2l.done)
	a2l.ready = true
	a2l.a2l = __a2l
}

func (a2l *Addr2Line) wait() error {
	if !a2l.ready {
		<-a2l.done
	}

	return a2l.err
}

// NewAddr2Line creates a new Addr2Line instance from the given vmlinux file.
func NewAddr2Line(vmlinux string, kaslr Kaslr, sysBPF, stext uint64) (*Addr2Line, error) {
	d, err := newDbgsymCache()
	if err != nil {
		return nil, fmt.Errorf("failed to create dbgsym cache: %w", err)
	}

	var a2l Addr2Line
	a2l.done = make(chan struct{})
	a2l.vmlinux = vmlinux
	a2l.kmods = make(map[string]kmodAddr2line)
	a2l.cache = d
	a2l.sysBPF = sysBPF
	a2l.stext = stext
	a2l.kaslr = kaslr
	go a2l.create()
	return &a2l, nil
}

func findKernelModuleFileUnderDir(mod, dir string) (string, error) {
	modKo, modKoZst, modKoFile := mod+".ko", mod+".ko.zst", ""

	errFound := errors.New("found")

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if slices.Contains([]string{modKo, modKoZst}, filepath.Base(path)) {
			modKoFile = path
			return errFound
		}

		return nil
	})

	if err == errFound {
		return modKoFile, nil
	}

	if err != nil {
		return "", fmt.Errorf("failed to walk %s: %w", dir, err)
	}

	return "", ErrNotFound
}

func findKernelModuleFile(mod string) (string, error) {
	rootDir := kernelVmlinuxDir
	if rootDir == "" {
		release, err := getRelease()
		if err != nil {
			return "", fmt.Errorf("failed to get release: %w", err)
		}

		rootDir = filepath.Join(debugModulesPath, release)
	}

	modKoFile, err := findKernelModuleFileUnderDir(mod, rootDir)
	if err != nil {
		return "", fmt.Errorf("failed to find %s: %w", mod, err)
	}

	return modKoFile, nil
}

func zst2readerAt(fd *os.File) (io.ReaderAt, error) {
	dec, err := zstd.NewReader(fd)
	if err != nil {
		return nil, fmt.Errorf("failed to create zstd reader for %s: %w", fd.Name(), err)
	}

	var buf bytes.Buffer
	_, err = dec.WriteTo(&buf)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress %s: %w", fd.Name(), err)
	}

	return newBufferReaderAt(&buf), nil
}

func findSectionInKmod(modKo, section string) (*elf.Section, error) {
	var elfFile *elf.File

	if strings.HasSuffix(modKo, ".ko.zst") {
		fd, err := os.Open(modKo)
		if err != nil {
			return nil, fmt.Errorf("failed to open file %s: %w", modKo, err)
		}
		defer fd.Close()

		r, err := zst2readerAt(fd)
		if err != nil {
			return nil, fmt.Errorf("failed to create zstd reader for %s: %w", modKo, err)
		}

		e, err := elf.NewFile(r)
		if err != nil {
			return nil, fmt.Errorf("failed to read ELF file %s: %w", modKo, err)
		}

		elfFile = e

	} else {
		file, err := os.Open(modKo)
		if err != nil {
			return nil, fmt.Errorf("failed to open file %s: %w", modKo, err)
		}
		defer file.Close()

		e, err := elf.NewFile(file)
		if err != nil {
			return nil, fmt.Errorf("failed to read ELF file %s: %w", modKo, err)
		}

		elfFile = e
	}

	elfSection := elfFile.Section(section)
	if elfSection != nil {
		return elfSection, nil
	}

	return nil, ErrNotFound
}

func (a2l *Addr2Line) addKmod(modName string) error {
	var modKo string

	kmod, ok := a2l.kmods[modName]
	if ok {
		return nil
	}

	modKo, err := findKernelModuleFile(modName)
	if err != nil {
		return fmt.Errorf("failed to find %s: %w", modName, err)
	}

	VerboseLog("Found %s at %s", modName, modKo)

	var li *addr2line.Addr2Line
	if strings.HasSuffix(modKo, ".ko.zst") {
		fd, err := os.Open(modKo)
		if err != nil {
			return fmt.Errorf("failed to open file %s: %w", modKo, err)
		}
		defer fd.Close()

		r, err := zst2readerAt(fd)
		if err != nil {
			return fmt.Errorf("failed to create zstd reader for %s: %w", modKo, err)
		}

		li, err = addr2line.NewAt(r, modKo)
		verboseLogIf(err != nil, "Failed to create addr2line for %s: %v", modName, err)
	} else {
		li, err = addr2line.New(modKo)
		verboseLogIf(err != nil, "Failed to create addr2line for %s: %v", modName, err)
	}

	sec, err := findSectionInKmod(modKo, ".text")
	if err != nil {
		return fmt.Errorf("failed to find section .text in %s: %w", modKo, err)
	}

	kmod = kmodAddr2line{}
	kmod.Addr2Line = li
	kmod.kaslr = NewKaslr(a2l.stext, sec.Addr)

	a2l.kmods[modName] = kmod

	return nil
}

func (a2l *Addr2Line) getMod(ksym *KsymEntry) (*addr2line.Addr2Line, Kaslr, error) {
	if ksym == nil || isKernelBuiltinMod(ksym.mod) {
		return a2l.a2l, a2l.kaslr, nil
	}

	modName := ksym.mod
	kmod, ok := a2l.kmods[modName]
	if ok {
		return kmod.Addr2Line, kmod.kaslr, nil
	}

	err := a2l.addKmod(modName)
	if errors.Is(err, ErrNotFound) {
		kmod := kmodAddr2line{}
		kmod.Addr2Line = nil
		kmod.kaslr = Kaslr{}
		a2l.kmods[modName] = kmod // cache the not-found result
		return nil, Kaslr{}, nil
	}
	if err != nil {
		return nil, Kaslr{}, fmt.Errorf("failed to find %s: %w", modName, err)
	}

	kmod = a2l.kmods[modName]
	return kmod.Addr2Line, kmod.kaslr, nil
}

// get returns the addr2line entry from the vmlinux file for the given address.
func (a2l *Addr2Line) get(addr uintptr, ksym *KsymEntry) (*addr2line.Addr2LineEntry, error) {
	if e, ok := a2l.cache.get(addr); ok {
		return e, nil
	}

	if err := a2l.wait(); err != nil {
		return nil, err
	}

	a2lMod, kaslr, err := a2l.getMod(ksym)
	if err != nil {
		return nil, fmt.Errorf("failed to get addr2line for %s: %w", ksym.mod, err)
	}

	if a2lMod == nil {
		return nil, ErrNotFound
	}

	eaddr := kaslr.effectiveAddr(uint64(addr))
	entry, err := a2lMod.Get(eaddr, true)
	if err != nil {
		return nil, fmt.Errorf("failed to get addr2line entry with KASLR offset %#x: %w", kaslr.offset(), err)
	}

	if ksym.mod != kmodBpf {
		return entry, a2l.cache.add(addr, entry)
	} else {
		return entry, nil
	}
}
