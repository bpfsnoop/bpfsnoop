// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"fmt"
	"runtime"

	"github.com/bpfsnoop/bpfsnoop/internal/assert"
	"github.com/bpfsnoop/gapstone"
)

const (
	archAMD64 = "amd64"
	archARM64 = "arm64"

	archLoongArch64 = "loong64"
)

func createGapstoneEngine() (*gapstone.Engine, error) {
	arch, mode := gapstone.CS_ARCH_X86, gapstone.CS_MODE_64
	switch runtime.GOARCH {
	case archARM64:
		arch, mode = gapstone.CS_ARCH_ARM64, gapstone.CS_MODE_ARM
	}
	engine, err := gapstone.New(int(arch), int(mode))
	if err != nil {
		return nil, fmt.Errorf("failed to new gapstone engine: %w", err)
	}

	if !disasmIntelSyntax {
		err = engine.SetOption(uint(gapstone.CS_OPT_SYNTAX), uint(gapstone.CS_OPT_SYNTAX_ATT))
		if err != nil {
			_ = engine.Close()
			return nil, fmt.Errorf("failed to set att syntax: %w", err)
		}
	} else {
		assert.True(runtime.GOARCH == archAMD64, "Intel syntax only supports amd64 architecture")
	}

	return &engine, nil
}
