// Copyright 2026 Liang Tang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/Asphaltt/mybtf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"rsc.io/c2go/cc"
)

const (
	// StrEqFunc is the C func in bpf/bpfsnoop_str.h that compares a string
	// with a literal.
	StrEqFunc = "bpfsnoop_str_eq"

	// StrLitSize is BPFSNOOP_STRLIT_SIZE in bpf/bpfsnoop_str.h: the most
	// bytes of a compared string with its NUL, and the bytes of each literal
	// in .rodata.strlit.
	StrLitSize = 256

	// maxStrCmpLen is the longest string literal str() can be compared with.
	// A longer string read to StrLitSize bytes has the same length as one of
	// StrLitSize-1 chars, so the length with the NUL is at most StrLitSize-1.
	maxStrCmpLen = StrLitSize - 2
)

// strLitMeta is the key of the metadata of the insn that loads the index of a
// string literal for bpfsnoop_str_eq(). Its value is the literal.
type strLitMeta struct{}

// IndexStrLits indexes the string literals that the str() comparisons in insns
// are compared with: it sets the index that each comparison loads, and returns
// the literals in the order of their indexes, for .rodata.strlit.
//
// The comparisons of a bpf prog are compiled apart, e.g. in its arg filter and
// outputs, but share its .rodata.strlit, so they're indexed in the prog.
func IndexStrLits(insns asm.Instructions) []string {
	var lits []string
	for i := range insns {
		lit, ok := insns[i].Metadata.Get(strLitMeta{}).(string)
		if !ok {
			continue
		}

		idx := slices.Index(lits, lit)
		if idx == -1 {
			idx = len(lits)
			lits = append(lits, lit)
		}
		insns[i].Constant = int64(idx)
	}
	return lits
}

func stripParens(expr *cc.Expr) *cc.Expr {
	for expr.Op == cc.Paren {
		expr = expr.Left
	}
	return expr
}

func isStrCall(expr *cc.Expr) bool {
	return expr.Op == cc.Call && expr.Left.Op == cc.Name && expr.Left.Text == strFn
}

// isByteType reports whether typ is a 1-byte integer, e.g. char, unsigned char
// or u8.
func isByteType(typ btf.Type) bool {
	i, ok := mybtf.UnderlyingType(typ).(*btf.Int)
	return ok && i.Size == 1
}

func unquoteStrLiteral(expr *cc.Expr) (string, error) {
	var sb strings.Builder
	for _, text := range expr.Texts {
		s, err := strconv.Unquote(text)
		if err != nil {
			return "", fmt.Errorf("invalid string literal %s: %w", text, err)
		}
		sb.WriteString(s)
	}

	s := sb.String()
	if strings.IndexByte(s, 0) != -1 {
		return "", fmt.Errorf("string literal %q must not contain NUL", s)
	}
	if len(s) > maxStrCmpLen {
		return "", fmt.Errorf("string literal of %d bytes is longer than %d bytes", len(s), maxStrCmpLen)
	}

	return s, nil
}

// strCmpOperands returns the str() call and the literal of 'str(x) == "lit"'
// or '"lit" == str(x)'. ok is false if expr doesn't compare strings.
func strCmpOperands(expr *cc.Expr) (str *cc.Expr, lit string, ok bool, err error) {
	left, right := stripParens(expr.Left), stripParens(expr.Right)
	if left.Op == cc.String {
		left, right = right, left
	}

	switch {
	case right.Op != cc.String && !isStrCall(left) && !isStrCall(right):
		return nil, "", false, nil

	case right.Op != cc.String:
		return nil, "", false, fmt.Errorf("%s() can only be compared with a string literal", strFn)

	case !isStrCall(left):
		return nil, "", false, fmt.Errorf("a string literal can only be compared with %s(), e.g. '%s(x) == \"...\"'", strFn, strFn)
	}

	lit, err = unquoteStrLiteral(right)
	if err != nil {
		return nil, "", false, err
	}

	return left, lit, true, nil
}

// evaluateStrCmpMaybe compiles expr with evaluateStrCmp if it compares
// strings. done is false if it doesn't, and expr is left to the caller.
func (c *compiler) evaluateStrCmpMaybe(expr *cc.Expr, eq bool) (val exprValue, done bool, err error) {
	str, lit, ok, err := strCmpOperands(expr)
	if err != nil {
		return exprValue{}, true, err
	}
	if !ok {
		return exprValue{}, false, nil
	}

	val, err = c.evaluateStrCmp(str, lit, eq)
	return val, true, err
}

// evaluateStrCmp compiles 'str(x) == lit', or 'str(x) != lit' if !eq, where
// str(x) is a char pointer or array, or str(x, size) a char array of size bytes.
//
// It calls bpfsnoop_str_eq() in bpf/bpfsnoop_str.h with the address of the
// string, the most bytes to read, and the index of lit, which IndexStrLits()
// sets. A full char array has no NUL, so at most its size is compared.
func (c *compiler) evaluateStrCmp(str *cc.Expr, lit string, eq bool) (exprValue, error) {
	val, err := c.evaluate(str)
	if err != nil {
		return exprValue{}, err
	}

	size := StrLitSize
	var elem btf.Type // str() is a pointer or an array
	switch typ := mybtf.UnderlyingType(val.btf).(type) {
	case *btf.Pointer:
		elem = typ.Target

	case *btf.Array:
		elem = typ.Type
		if len(lit) > int(typ.Nelems) {
			return exprValue{}, fmt.Errorf("string literal of %d bytes is longer than %v", len(lit), val.btf)
		}
		// Read no further than the end of the array, where the read puts the
		// NUL of a full array.
		size = min(size, int(typ.Nelems)+1)
	}
	if !isByteType(elem) {
		return exprValue{}, fmt.Errorf("%s() needs a char pointer or array, got %v", strFn, val.btf)
	}

	// The address of the string, which also holds the result in the end.
	addr := val.reg

	// The insn loading the index of lit holds lit, for IndexStrLits().
	idx := asm.Mov.Imm(asm.R3, 0)
	idx.Metadata.Set(strLitMeta{}, lit)

	c.pushUsedCallerSavedRegs()
	c.emit(
		asm.Mov.Reg(asm.R1, addr),
		asm.Mov.Imm(asm.R2, int32(size)),
		idx,
		asm.Call.Label(StrEqFunc),
		asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord),
	)
	c.popUsedCallerSavedRegs()

	c.emit(asm.LoadMem(addr, asm.RFP, -8, asm.DWord))
	if !eq {
		c.emit(asm.Xor.Imm(addr, 1))
	}

	return newMaterialized(addr, &btf.Int{Name: "bool", Size: 1, Encoding: btf.Bool}), nil
}
