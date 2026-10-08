// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"encoding/binary"
	"fmt"

	"github.com/Asphaltt/mybtf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"rsc.io/c2go/cc"
)

const (
	byteOrderH2ns = "h2ns"
	byteOrderN2hs = "n2hs"
	byteOrderH2nl = "h2nl"
	byteOrderN2hl = "n2hl"

	mapLookupFn            = "map_lookup"
	bpfMapLookupElemHelper = "bpf_map_lookup_elem"

	arenaFn = "arena"
)

func isBuiltinFunc(name string) bool {
	switch name {
	case byteOrderH2ns, byteOrderN2hs, byteOrderH2nl, byteOrderN2hl,
		mapLookupFn, bpfMapLookupElemHelper, arenaFn:
		return true
	default:
		return false
	}
}

// isMapFunc reports whether a func takes a map as its first argument.
func isMapFunc(name string) bool {
	switch name {
	case mapLookupFn, bpfMapLookupElemHelper, arenaFn:
		return true
	default:
		return false
	}
}

func byteOrderFunc2size(name string) asm.Size {
	switch name {
	case byteOrderH2ns, byteOrderN2hs:
		return asm.Half
	default:
		return asm.Word
	}
}

func (c *compiler) evaluateCall(expr *cc.Expr) (exprValue, error) {
	if expr.Left.Op != cc.Name {
		return exprValue{}, fmt.Errorf("function call must have a constant name")
	}

	name := expr.Left.Text
	switch name {
	case byteOrderH2ns, byteOrderN2hs, byteOrderH2nl, byteOrderN2hl:
		return c.evaluateByteOrderCall(expr)

	case mapLookupFn, bpfMapLookupElemHelper:
		return c.evaluateMapCall(expr)

	case arenaFn:
		return c.evaluateArenaCall(expr)

	default:
		return exprValue{}, fmt.Errorf("unsupported function call in expression: %s", name)
	}
}

func (c *compiler) evaluateByteOrderCall(expr *cc.Expr) (exprValue, error) {
	name := expr.Left.Text
	if len(expr.List) != 1 {
		return exprValue{}, fmt.Errorf("%s() must have 1 argument", name)
	}

	val, err := c.evaluate(expr.List[0])
	if err != nil {
		return exprValue{}, fmt.Errorf("failed to evaluate %s() argument: %w", name, err)
	}
	if !val.isConstant() || val.btf != nil {
		if _, ok := mybtf.UnderlyingType(val.btf).(*btf.Int); !ok {
			return exprValue{}, fmt.Errorf("%s() argument must be an int, got %v", name, val.btf)
		}
	}

	size := byteOrderFunc2size(name)
	typ := &btf.Int{Name: "unsigned short", Size: uint32(size.Sizeof()), Encoding: btf.Unsigned}

	// Convert to the unsigned parameter width before changing byte order.
	// Narrowing discards high bits; signed inputs are extended by materialize.
	if val.isConstant() {
		if val.btf != nil {
			val.num = c.adjustNumForType(val.num, val.btf, val.mem)
		}

		var buf [4]byte
		if size == asm.Half {
			binary.NativeEndian.PutUint16(buf[:2], uint16(val.num))
			val.num = int64(binary.BigEndian.Uint16(buf[:2]))
		} else {
			binary.NativeEndian.PutUint32(buf[:], uint32(val.num))
			val.num = int64(binary.BigEndian.Uint32(buf[:]))
		}
		val.btf = typ
		return val, nil
	}

	val, err = c.materialize(val)
	if err != nil {
		return exprValue{}, fmt.Errorf("failed to materialize %s() argument: %w", name, err)
	}

	// BPF_END also truncates and zero-extends to the selected width. Host to
	// network and network to host are the same operation for these integers.
	c.emit(asm.HostTo(asm.BE, val.reg, size))

	return newMaterialized(val.reg, typ), nil
}
