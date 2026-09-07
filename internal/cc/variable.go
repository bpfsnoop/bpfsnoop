// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"fmt"
	"slices"

	"rsc.io/c2go/cc"
)

var builtinVars = map[string]int64{
	"NULL":  0,
	"null":  0,
	"false": 0,
	"true":  1,
}

func isBuiltinVar(name string) bool {
	_, ok := builtinVars[name]
	return ok
}

func ExtractVarNames(expr string) ([]string, error) {
	e, err := cc.ParseExpr(expr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse expression: %w", err)
	}

	if e.Op == cc.Call {
		e = e.List[0]
	}

	var names []string
	cc.Walk(e, func(node cc.Syntax) {
		if v, ok := node.(*cc.Expr); ok {
			if v.Op == cc.Name {
				if !isBuiltinVar(v.Text) {
					names = append(names, v.Text)
				}
			}
		}
	}, func(node cc.Syntax) {})

	slices.Sort(names)
	names = slices.Compact(names)
	return names, nil
}
