// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"fmt"

	"golang.org/x/exp/slices"
	"rsc.io/c2go/cc"
)

func ExtractVarNames(expr string) ([]string, error) {
	e, err := cc.ParseExpr(expr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse expression: %w", err)
	}

	var names []string
	cc.Walk(e, func(node cc.Syntax) {
		if v, ok := node.(*cc.Expr); ok {
			if v.Op == cc.Name {
				names = append(names, v.Text)
			}
		}
	}, func(node cc.Syntax) {})

	slices.Sort(names)
	names = slices.Compact(names)
	return names, nil
}
