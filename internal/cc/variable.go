// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"fmt"
	"slices"

	c2go "rsc.io/c2go/cc"
)

// ExprAnalysis contains the parser-facing form and variable metadata for an
// expression. RetvalCast is empty when the expression doesn't use $retval.
type ExprAnalysis struct {
	CompilerExpr string
	Vars         []string
	RetvalCast   string
	retvalExpr   *c2go.Expr
}

func AnalyzeExpr(expr string) (ExprAnalysis, error) {
	newExpr := rewriteRetval(expr)
	hasRetval := newExpr != expr

	var analysis ExprAnalysis
	analysis.CompilerExpr = newExpr

	e, err := c2go.ParseExpr(newExpr)
	if err != nil {
		return analysis, fmt.Errorf("failed to parse expression: %w", err)
	}

	// A top-level helper call's name is not a variable.
	varsExpr := e
	if e.Op == c2go.Call && len(e.List) != 0 {
		varsExpr = e.List[0]
	}

	var stack []*c2go.Expr
	uses, castUses := 0, 0
	var castErr error
	c2go.Walk(e, func(node c2go.Syntax) {
		v, ok := node.(*c2go.Expr)
		if !ok {
			return
		}
		stack = append(stack, v)
		if v.Op != c2go.Name || v.Text != retvalCompilerName {
			return
		}
		uses++

		for i := len(stack) - 2; i >= 0; i-- {
			parent := stack[i]
			if parent.Op == c2go.Paren {
				continue
			}
			if parent.Op != c2go.Cast || !enclosesThroughParens(parent.Left, v) {
				break
			}
			if !validRetvalCast(parent.Type) {
				castErr = fmt.Errorf("%s has invalid non-scalar cast %q", RetvalName, parent.Type.String())
				break
			}
			castUses++
			cast := parent.Type.String()
			if analysis.retvalExpr == nil {
				analysis.retvalExpr = parent
				analysis.RetvalCast = cast
			} else if analysis.RetvalCast != cast {
				castErr = fmt.Errorf("%s has conflicting casts %q and %q", RetvalName, analysis.RetvalCast, cast)
			}
			break
		}
	}, func(node c2go.Syntax) {
		if _, ok := node.(*c2go.Expr); ok {
			stack = stack[:len(stack)-1]
		}
	})

	if hasRetval {
		if castErr != nil {
			return analysis, castErr
		}
		if analysis.retvalExpr == nil || castUses != uses {
			return analysis, fmt.Errorf("%s requires an explicit concrete cast", RetvalName)
		}
	}

	var names []string
	c2go.Walk(varsExpr, func(node c2go.Syntax) {
		if v, ok := node.(*c2go.Expr); ok && v.Op == c2go.Name {
			name := v.Text
			if name == retvalCompilerName {
				name = RetvalName
			}
			names = append(names, name)
		}
	}, func(c2go.Syntax) {})
	slices.Sort(names)
	analysis.Vars = slices.Compact(names)
	return analysis, nil
}

func ExtractVarNames(expr string) ([]string, error) {
	analysis, err := AnalyzeExpr(expr)
	return analysis.Vars, err
}
