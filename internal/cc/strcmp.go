// Copyright 2026 Liang Tang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/Asphaltt/mybtf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"rsc.io/c2go/cc"
)

const (
	strFn = "str"

	// maxStrCmpLen is the longest string literal str() can be compared with.
	maxStrCmpLen = 256
)

// strCmpLabelSeq makes the labels of string comparisons unique in a prog,
// which can have several compiled expressions.
var strCmpLabelSeq atomic.Uint64

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

// strCmpOperands returns x and the literal of 'str(x) == "lit"' or
// '"lit" == str(x)'. ok is false if expr doesn't compare strings.
func strCmpOperands(expr *cc.Expr) (x *cc.Expr, lit string, ok bool, err error) {
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

	case len(left.List) != 1:
		return nil, "", false, fmt.Errorf("%s() must have 1 argument when compared with a string literal", strFn)
	}

	lit, err = unquoteStrLiteral(right)
	if err != nil {
		return nil, "", false, err
	}

	return left.List[0], lit, true, nil
}

// evaluateStrCmpMaybe compiles expr with evaluateStrCmp if it compares
// strings. done is false if it doesn't, and expr is left to the caller.
func (c *compiler) evaluateStrCmpMaybe(expr *cc.Expr, eq bool) (val exprValue, done bool, err error) {
	x, lit, ok, err := strCmpOperands(expr)
	if err != nil {
		return exprValue{}, true, err
	}
	if !ok {
		return exprValue{}, false, nil
	}

	val, err = c.evaluateStrCmp(x, lit, eq)
	return val, true, err
}

// evaluateStrCmp compiles 'str(x) == lit', or 'str(x) != lit' if !eq, where x
// is a char pointer or array.
//
// The length of lit is known here, so the comparison is unrolled like
// bpftrace does: read the string in chunks of up to 8 bytes and compare each
// chunk with a constant, including the terminating NUL. A full char array has
// no NUL, so at most its size is compared. A failed read zeroes the chunk, so
// a NULL or unreadable string only equals "".
func (c *compiler) evaluateStrCmp(x *cc.Expr, lit string, eq bool) (exprValue, error) {
	val, err := c.evaluate(x)
	if err != nil {
		return exprValue{}, err
	}

	size := len(lit) + 1
	switch typ := mybtf.UnderlyingType(val.btf).(type) {
	case *btf.Pointer:
		if !isByteType(typ.Target) {
			return exprValue{}, fmt.Errorf("%s() needs a char pointer or array, got %v", strFn, val.btf)
		}

	case *btf.Array:
		if !isByteType(typ.Type) {
			return exprValue{}, fmt.Errorf("%s() needs a char pointer or array, got %v", strFn, val.btf)
		}
		if len(lit) > int(typ.Nelems) {
			return exprValue{}, fmt.Errorf("string literal of %d bytes is longer than %v", len(lit), val.btf)
		}
		size = min(size, int(typ.Nelems))

	default:
		return exprValue{}, fmt.Errorf("%s() needs a char pointer or array, got %v", strFn, val.btf)
	}

	// The address of the string, which also holds the result in the end.
	val, err = c.materialize(val)
	if err != nil {
		return exprValue{}, err
	}
	addr := val.reg

	labelNe := fmt.Sprintf("__label_strcmp_%d_ne", strCmpLabelSeq.Add(1))

	data := make([]byte, size+7) // zero NUL and padding
	copy(data, lit)
	for off := 0; off < size; off += 8 {
		c.emitStrChunkRead(addr, off, min(8, size-off))
		if err := c.emitStrChunkCmp(int64(binary.NativeEndian.Uint64(data[off:])), labelNe); err != nil {
			return exprValue{}, err
		}
	}

	c.emit(
		asm.Mov.Imm(addr, int32(bool2int(eq))),
		Ja(1),
		asm.Mov.Imm(addr, int32(bool2int(!eq))).WithSymbol(labelNe),
	)

	return newMaterialized(addr, &btf.Int{Name: "bool", Size: 1, Encoding: btf.Bool}), nil
}

// emitStrChunkCmp jumps to labelNe if the chunk read by emitStrChunkRead isn't
// want. Its registers are allocated after the read, so the helper call doesn't
// save them while they hold nothing.
func (c *compiler) emitStrChunkCmp(want int64, labelNe string) error {
	chunk, err := c.regalloc.Alloc()
	if err != nil {
		return err
	}
	defer c.regalloc.Free(chunk)

	wantReg, err := c.regalloc.Alloc()
	if err != nil {
		return err
	}
	defer c.regalloc.Free(wantReg)

	c.emit(
		asm.LoadMem(chunk, asm.RFP, -8, asm.DWord),
		asm.LoadImm(wantReg, want, asm.DWord),
		asm.JNE.Reg(chunk, wantReg, labelNe),
	)
	return nil
}

// emitStrChunkRead reads n (<= 8) bytes at addr+off to the stack slot r10-8.
// The slot is zeroed first if n < 8, so it can be compared as a whole.
func (c *compiler) emitStrChunkRead(addr asm.Register, off, n int) {
	c.pushUsedCallerSavedRegs()
	defer c.popUsedCallerSavedRegs()

	if n < 8 {
		// asm.StoreImm() doesn't take DWord.
		c.emit(
			asm.StoreImm(asm.RFP, -8, 0, asm.Word),
			asm.StoreImm(asm.RFP, -4, 0, asm.Word),
		)
	}

	c.emit(asm.Mov.Reg(asm.R3, addr))
	if off != 0 {
		c.emit(asm.Add.Imm(asm.R3, int32(off)))
	}

	c.emit(
		asm.Mov.Imm(asm.R2, int32(n)),
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, -8),
		asm.FnProbeReadKernel.Call(),
	)
}
