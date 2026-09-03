// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/bpfsnoop/bpfsnoop/internal/bpfsnoop"
)

type readResult struct {
	Expression string `json:"expression" jsonschema:"kernel-memory C expression that was evaluated"`
	Type       string `json:"type" jsonschema:"resolved BTF type of the expression result"`
	Value      any    `json:"value" jsonschema:"structured value of the expression result"`
}

// ReadOutput contains ordered structured kernel-memory read results.
type ReadOutput struct {
	Results []readResult `json:"results" jsonschema:"results in the same order as the input expressions"`
}

// Read validates and evaluates typed kernel-memory expressions.
func Read(ctx context.Context, expressions []string) (ReadOutput, error) {
	if len(expressions) == 0 {
		return ReadOutput{}, errors.New("at least one kernel-memory expression is required")
	}
	for _, expression := range expressions {
		if strings.TrimSpace(expression) == "" {
			return ReadOutput{}, errors.New("kernel-memory expressions must not be empty")
		}
	}

	results, err := bpfsnoop.ReadKernelData(ctx, expressions)
	if err != nil {
		return ReadOutput{}, err
	}

	output := ReadOutput{Results: make([]readResult, 0, len(results))}
	for i := range results {
		result := &results[i]
		value, err := kernelReadValue(result)
		if err != nil {
			return ReadOutput{}, fmt.Errorf("failed to decode structured value for expression %q: %w", result.Expression, err)
		}
		output.Results = append(output.Results, readResult{
			Expression: result.Expression,
			Type:       result.Type,
			Value:      value,
		})
	}
	return output, nil
}
