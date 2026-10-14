// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bpfsnoop/bpfsnoop/internal/atomix"
	"github.com/bpfsnoop/bpfsnoop/internal/strx"
	"golang.org/x/sys/unix"
)

func uname() (*unix.Utsname, error) {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return nil, err
	}
	return &uts, nil
}

func getRelease() (string, error) {
	uts, err := uname()
	if err != nil {
		return "", fmt.Errorf("failed to get uname: %w", err)
	}
	return strx.NullTerminated(uts.Release[:]), nil
}

var vmlinuxPathOnce = atomix.NewOnce(findVmlinux)

// FindVmlinux tries to find vmlinux file from common locations.
func FindVmlinux() (string, error) {
	return vmlinuxPathOnce.Do()
}

func findVmlinux() (string, error) {
	if kernelVmlinuxDir != "" {
		vmlinux := filepath.Join(kernelVmlinuxDir, "vmlinux")
		if fileExists(vmlinux) {
			return vmlinux, nil
		}

		return "", fmt.Errorf("vmlinux file not found in %s", kernelVmlinuxDir)
	}

	release, err := getRelease()
	if err != nil {
		return "", fmt.Errorf("failed to get release: %w", err)
	}

	locations := []string{
		"/boot/vmlinux-%s",
		"/lib/modules/%s/vmlinux-%s",
		"/lib/modules/%s/build/vmlinux",
		"/usr/lib/modules/%s/kernel/vmlinux",
		"/usr/lib/debug/boot/vmlinux-%s",
		"/usr/lib/debug/boot/vmlinux-%s.debug",
		"/usr/lib/debug/lib/modules/%s/vmlinux",
	}

	for _, loc := range locations {
		var filepath string
		cnt := strings.Count(loc, "%s")
		switch cnt {
		case 1:
			filepath = fmt.Sprintf(loc, release)

		case 2:
			filepath = fmt.Sprintf(loc, release, release)

		default:
			panic(fmt.Sprintf("unexpected count %d of %%s in location %s", cnt, loc))
		}

		if fileExists(filepath) {
			return filepath, nil
		}
	}

	return "", ErrNotFound
}

var textAddrOnce = atomix.NewOnce(readTextAddrFromVmlinux)

// ReadTextAddrFromVmlinux reads .text section address from vmlinux file.
func ReadTextAddrFromVmlinux() (uint64, error) {
	return textAddrOnce.Do()
}

func readTextAddrFromVmlinux() (uint64, error) {
	vmlinux, err := FindVmlinux()
	if err != nil {
		return 0, fmt.Errorf("failed to find vmlinux: %w", err)
	}

	file, err := os.Open(vmlinux)
	if err != nil {
		return 0, fmt.Errorf("failed to open vmlinux file: %w", err)
	}
	defer file.Close()

	e, err := elf.NewFile(file)
	if err != nil {
		return 0, fmt.Errorf("failed to create elf file: %w", err)
	}

	textSection := e.Section(".text")
	if textSection == nil {
		return 0, errors.New("failed to find .text section from vmlinux file")
	}

	return textSection.Addr, nil
}
