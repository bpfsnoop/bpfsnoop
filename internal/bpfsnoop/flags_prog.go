// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	progFlagDescriptorID     = "id"
	progFlagDescriptorPinned = "pinned"
	progFlagDescriptorTag    = "tag"
	progFlagDescriptorName   = "name"
	progFlagDescriptorPid    = "pid"
)

type ProgFlag struct {
	progID uint32
	pinned string
	tag    string
	name   string
	pid    uint32

	descriptor string
	funcName   string

	insn bool
	all  bool
}

func parseProgFlag(p string) (ProgFlag, error) {
	var pf ProgFlag

	if strings.HasPrefix(p, "(i)") {
		pf.insn = true
		p = p[3:]
	}

	if p == "*" {
		pf.all = true
		return pf, nil
	}

	id, funcName, ok := strings.Cut(p, ":")
	switch id {
	case "i", "id":
		id, funcName, ok = strings.Cut(funcName, ":")
		break

	case "p", "pinned":
		pf.descriptor = progFlagDescriptorPinned
		pf.pinned, pf.funcName, _ = strings.Cut(funcName, ":")
		if !fileExists(pf.pinned) {
			return pf, fmt.Errorf("pinned file %s does not exist", pf.pinned)
		}
		return pf, nil

	case "t", "tag":
		pf.descriptor = progFlagDescriptorTag
		pf.tag, pf.funcName, _ = strings.Cut(funcName, ":")
		if pf.tag == "" {
			return pf, errors.New("tag must not be empty")
		}
		return pf, nil

	case "n", "name":
		pf.descriptor = progFlagDescriptorName
		pf.name, pf.funcName, _ = strings.Cut(funcName, ":")
		if pf.name == "" {
			return pf, errors.New("name must not be empty")
		}
		return pf, nil

	case "pid":
		pf.descriptor = progFlagDescriptorPid
		id, pf.funcName, _ = strings.Cut(funcName, ":")
		pid, err := strconv.ParseUint(id, 10, 32)
		if err != nil {
			return pf, fmt.Errorf("failed to parse pid %s from %s: %w", funcName, p, err)
		}
		pf.pid = uint32(pid)
		return pf, nil

	default:
	}

	progID, err := strconv.ParseUint(id, 10, 32)
	if err != nil {
		return pf, fmt.Errorf("failed to parse progID %s from %s: %w", id, p, err)
	}

	pf.descriptor = progFlagDescriptorID
	pf.progID = uint32(progID)
	if ok {
		pf.funcName = funcName
	}

	return pf, nil
}

func parseProgsFlag(progs []string) ([]ProgFlag, error) {
	flags := make([]ProgFlag, 0, len(progs))
	for _, p := range progs {
		pf, err := parseProgFlag(p)
		if err != nil {
			return nil, err
		}

		flags = append(flags, pf)
	}

	return flags, nil
}
