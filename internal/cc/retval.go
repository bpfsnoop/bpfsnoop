// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"strings"

	c2go "rsc.io/c2go/cc"
)

const (
	// RetvalName is the user-visible function return pseudo-variable.
	RetvalName = "$retval"
	// retvalCompilerName is deliberately not a valid user spelling. It is used
	// only after token-aware rewriting, since '$' isn't accepted by the C parser.
	retvalCompilerName = "____retval____"
)

func rewriteRetval(expr string) string {
	return strings.ReplaceAll(expr, RetvalName, retvalCompilerName)
}

func validRetvalCast(typ *c2go.Type) bool {
	if typ == nil {
		return false
	}
	if typ.Kind == c2go.TypedefType {
		if typ.Base == nil {
			return true
		}
		return validRetvalCast(typ.Base)
	}
	switch typ.Kind {
	case c2go.Char, c2go.Uchar, c2go.Short, c2go.Ushort,
		c2go.Int, c2go.Uint, c2go.Long, c2go.Ulong,
		c2go.Longlong, c2go.Ulonglong, c2go.Float, c2go.Double,
		c2go.Enum, c2go.Ptr:
		return true
	default:
		return false
	}
}

func enclosesThroughParens(expr, target *c2go.Expr) bool {
	for expr != nil && expr.Op == c2go.Paren {
		expr = expr.Left
	}
	return expr == target
}
