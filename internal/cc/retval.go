// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"fmt"
	"slices"
	"strings"

	"github.com/Asphaltt/mybtf"
	"github.com/cilium/ebpf/btf"
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

func matchRetvalType(analysis ExprAnalysis, returnType btf.Type, spec, kernel btfSpecer) (bool, error) {
	if analysis.retvalExpr == nil {
		return false, nil
	}

	c := &compiler{btfSpec: spec, krnlSpec: kernel}
	cast, err := c.cc2btf(analysis.retvalExpr)
	if err != nil {
		return false, fmt.Errorf("failed to resolve %s cast %q: %w", RetvalName, analysis.RetvalCast, err)
	}
	if _, void := mybtf.UnderlyingType(returnType).(*btf.Void); void {
		return false, nil
	}
	return sameUnderlyingType(cast, returnType), nil
}

func sameUnderlyingType(left, right btf.Type) bool {
	left, right = mybtf.UnderlyingType(left), mybtf.UnderlyingType(right)
	switch l := left.(type) {
	case *btf.Void:
		_, ok := right.(*btf.Void)
		return ok
	case *btf.Int:
		r, ok := right.(*btf.Int)
		return ok && l.Size == r.Size && l.Encoding == r.Encoding
	case *btf.Enum:
		r, ok := right.(*btf.Enum)
		return ok && l.Name == r.Name && l.Size == r.Size && l.Signed == r.Signed
	case *btf.Float:
		r, ok := right.(*btf.Float)
		return ok && l.Size == r.Size
	case *btf.Pointer:
		r, ok := right.(*btf.Pointer)
		return ok && sameUnderlyingType(l.Target, r.Target)
	case *btf.Struct:
		r, ok := right.(*btf.Struct)
		return ok && l.Name == r.Name
	case *btf.Union:
		r, ok := right.(*btf.Union)
		return ok && l.Name == r.Name
	default:
		return fmt.Sprintf("%v", left) == fmt.Sprintf("%v", right)
	}
}

// MatchRetvalType reports whether the typed $retval in expr matches a declared
// return type after typedef and qualifier wrappers are removed.
func MatchRetvalType(expr string, returnType btf.Type, spec, kernel *btf.Spec) (bool, error) {
	analysis, err := AnalyzeExpr(expr)
	if err != nil {
		return false, err
	}
	return matchRetvalType(analysis, returnType, spec, kernel)
}

func prepareCompileOptions(opts CompileExprOptions) (CompileExprOptions, error) {
	if !strings.Contains(opts.Expr, RetvalName) {
		return opts, nil
	}
	analysis, err := AnalyzeExpr(opts.Expr)
	if err != nil {
		return opts, err
	}
	opts.Expr = analysis.CompilerExpr
	if opts.RetvalType == nil {
		return opts, fmt.Errorf("expression uses %s without a declared return type", RetvalName)
	}
	matched, err := matchRetvalType(analysis, opts.RetvalType, opts.Spec, opts.Kernel)
	if err != nil {
		return opts, err
	}
	if !matched {
		return opts, fmt.Errorf("%s cast %q does not match declared return type %v", RetvalName, analysis.RetvalCast, opts.RetvalType)
	}
	opts.Params = append(slices.Clone(opts.Params), btf.FuncParam{Name: retvalCompilerName, Type: opts.RetvalType})
	return opts, nil
}
