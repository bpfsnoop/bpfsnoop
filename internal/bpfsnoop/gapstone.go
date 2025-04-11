// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"fmt"

	"github.com/bpfsnoop/gapstone"
)

func createGapstoneEngine() (*gapstone.Engine, error) {
	engine, err := gapstone.New(int(gapstone.CS_ARCH_X86), int(gapstone.CS_MODE_64))
	if err != nil {
		return nil, fmt.Errorf("failed to new gapstone engine: %w", err)
	}

	if !disasmIntelSyntax {
		err = engine.SetOption(uint(gapstone.CS_OPT_SYNTAX), uint(gapstone.CS_OPT_SYNTAX_ATT))
		if err != nil {
			_ = engine.Close()
			return nil, fmt.Errorf("failed to set att syntax: %w", err)
		}
	}

	return &engine, nil
}
