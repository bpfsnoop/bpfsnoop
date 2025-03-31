// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package btfx

import (
	"fmt"
	"strings"
	"unsafe"

	"github.com/Asphaltt/mybtf"
	"github.com/cilium/ebpf/btf"
)

type findSymbol func(addr uint64) string

func IsPointer(t btf.Type) bool {
	t = mybtf.UnderlyingType(t)
	_, ok := t.(*btf.Pointer)
	return ok
}

func IsEnum(t btf.Type) bool {
	t = mybtf.UnderlyingType(t)
	_, ok := t.(*btf.Enum)
	return ok
}

func IsInt(t btf.Type) bool {
	t = mybtf.UnderlyingType(t)
	_, ok := t.(*btf.Int)
	return ok
}

func IsNumberPointer(t btf.Type) bool {
	t = mybtf.UnderlyingType(t)
	ptr, ok := t.(*btf.Pointer)
	if !ok {
		return false
	}

	t = mybtf.UnderlyingType(ptr.Target)
	switch t.(type) {
	case *btf.Int, *btf.Enum:
		return true
	default:
		return false
	}
}

func IsSigned(t btf.Type) bool {
	t = mybtf.UnderlyingType(t)
	i, ok := t.(*btf.Int)
	return ok && i.Encoding == btf.Signed
}

func IsBool(t btf.Type) bool {
	if mybtf.IsBool(t) {
		return true
	}

	t = mybtf.UnderlyingType(t)
	i, ok := t.(*btf.Int)
	return ok && i.Name == "_Bool"
}

func IsStr(t btf.Type) bool {
	return mybtf.IsConstCharPtr(t) || mybtf.IsCharArray(t)
}

func IsConst(t btf.Type) bool {
	for {
		switch v := t.(type) {
		case *btf.Typedef:
			t = v.Type
		case *btf.Volatile:
			t = v.Type
		case *btf.Const:
			return true
		case *btf.Restrict:
			t = v.Type
		default:
			return false
		}
	}
}

func IsFuncPtr(t btf.Type) bool {
	t = mybtf.UnderlyingType(t)
	ptr, ok := t.(*btf.Pointer)
	if !ok {
		return false
	}

	t = mybtf.UnderlyingType(ptr.Target)
	switch t.(type) {
	case *btf.Func, *btf.FuncProto:
		return true
	default:
		return false
	}
}

func GetStructBtfPointer(name string) (*btf.Pointer, error) {
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return nil, fmt.Errorf("failed to load kernel btf spec: %w", err)
	}

	typ, err := spec.AnyTypeByName(name)
	if err != nil {
		return nil, fmt.Errorf("failed to get type of %s: %w", name, err)
	}

	s, ok := typ.(*btf.Struct)
	if !ok {
		return nil, fmt.Errorf("type %s is not a struct", name)
	}

	return &btf.Pointer{Target: s}, nil
}

func Repr(t btf.Type) string {
	var sb strings.Builder

loop:
	for {
		switch v := t.(type) {
		case *btf.Typedef:
			t = v.Type
			return v.Name
		case *btf.Volatile:
			t = v.Type
			fmt.Fprint(&sb, "volatile ")
		case *btf.Const:
			t = v.Type
			fmt.Fprint(&sb, "const ")
		case *btf.Restrict:
			t = v.Type
			fmt.Fprint(&sb, "restrict ")
		case *btf.TypeTag:
			t = v.Type
			fmt.Fprint(&sb, v.Value, " ")
		default:
			break loop
		}
	}

	ptr, isPtr := t.(*btf.Pointer)
	if isPtr {
		t = ptr.Target
		r := Repr(t)
		fmt.Fprint(&sb, r)
		if r[len(r)-1] != '*' {
			fmt.Fprint(&sb, " *")
		} else {
			fmt.Fprint(&sb, "*") // pointer to pointer ...
		}
		return sb.String()
	}

	switch v := t.(type) {
	case *btf.Void:
		fmt.Fprint(&sb, "void")

	case *btf.Int:
		fmt.Fprint(&sb, v.Name)

	case *btf.Enum:
		fmt.Fprintf(&sb, "enum %s", v.Name)

	case *btf.Struct:
		fmt.Fprintf(&sb, "struct %s", v.Name)

	case *btf.Union:
		fmt.Fprintf(&sb, "union %s", v.Name)

	case *btf.Func:
		fmt.Fprintf(&sb, "func %s", v.Name)
	case *btf.FuncProto:
		fmt.Fprintf(&sb, "func")

	case *btf.Float:
		fmt.Fprint(&sb, "float")

	case *btf.Array:
		fmt.Fprintf(&sb, "array(%s[%d])", Repr(v.Type), v.Nelems)

	default:
		fmt.Fprintf(&sb, "%v", t)
	}

	return sb.String()
}

func ReprEnumValue(t btf.Type, val uint64) string {
	t = mybtf.UnderlyingType(t)
	enum, ok := t.(*btf.Enum)
	if !ok {
		return fmt.Sprintf("%d", val)
	}
	for _, v := range enum.Values {
		if v.Value == val {
			return fmt.Sprintf("%s", v.Name)
		}
	}
	return fmt.Sprintf("%d", val)
}

func reprMember(sb *strings.Builder, m *btf.Member, data []byte, find findSymbol) {
	if m.Name != "" {
		fmt.Fprintf(sb, "%s=", m.Name)
	}
	if m.BitfieldSize != 0 {
		fmt.Fprintf(sb, mybtf.DumpBitfield(m.Offset, m.BitfieldSize, data))
	} else {
		fmt.Fprintf(sb, "%s", ReprValue(m.Type, *(*uint64)(unsafe.Pointer(&data[m.Offset])), *(*uint64)(unsafe.Pointer(&data[m.Offset+8])), find))
	}
}

func reprStructUnion(sb *strings.Builder, name string, members []btf.Member, data []byte, find findSymbol) {
	fmt.Fprintf(sb, "%s{", name)
	for i, m := range members {
		if i > 0 {
			fmt.Fprint(sb, ",")
		}
		reprMember(sb, &m, data, find)
	}
	fmt.Fprint(sb, "}")
}

func ReprValue(t btf.Type, val, valNext uint64, find findSymbol) string {
	t = mybtf.UnderlyingType(t)

	var sb strings.Builder

	size, err := btf.Sizeof(t)
	if err != nil {
		fmt.Fprintf(&sb, "..ERR..")
		return sb.String()
	}

	if stt, ok := t.(*btf.Struct); ok {
		var data [24]byte
		*(*uint64)(unsafe.Pointer(&data[0])) = val
		*(*uint64)(unsafe.Pointer(&data[8])) = valNext
		reprStructUnion(&sb, stt.Name, stt.Members, data[:], find)
		return sb.String()
	}
	if unn, ok := t.(*btf.Union); ok {
		var data [24]byte
		*(*uint64)(unsafe.Pointer(&data[0])) = val
		*(*uint64)(unsafe.Pointer(&data[8])) = valNext
		reprStructUnion(&sb, unn.Name, unn.Members, data[:], find)
		return sb.String()
	}

	isSignedInt := IsSigned(t)

	switch size {
	case 8:
		if IsPointer(t) {
			fmt.Fprintf(&sb, "%#x", val)
			if IsFuncPtr(t) {
				if s := find(val); s != "" {
					fmt.Fprintf(&sb, "(%s)", s)
				}
			}
		} else {
			if isSignedInt {
				fmt.Fprintf(&sb, "%d", int64(val))
			} else {
				if int64(val) < 0 /* maybe kernel addr */ {
					fmt.Fprintf(&sb, "%#x", val)
				} else {
					fmt.Fprintf(&sb, "%#x/%d", val, val)
				}
			}
		}

	case 4:
		if IsEnum(t) {
			fmt.Fprint(&sb, ReprEnumValue(t, val))
		} else if isSignedInt {
			fmt.Fprintf(&sb, "%d", int32(val))
		} else {
			fmt.Fprintf(&sb, "%#x/%d", uint32(val), uint32(val))
		}
	case 2:
		if isSignedInt {
			fmt.Fprintf(&sb, "%d", int16(val))
		} else {
			fmt.Fprintf(&sb, "%#x/%d", uint16(val), uint16(val))
		}
	case 1:
		if isSignedInt {
			fmt.Fprintf(&sb, "%d", int8(val))
		} else if IsBool(t) {
			b := "false"
			if val != 0 {
				b = "true"
			}
			fmt.Fprint(&sb, b)
		} else {
			fmt.Fprintf(&sb, "%#x/%d", uint8(val), uint8(val))
		}
	default:
		fmt.Fprintf(&sb, "..UNK..")
	}

	return sb.String()
}

func reprValue(sb *strings.Builder, t btf.Type, isStr, isNumberPtr bool, data, data2, dataNext uint64, s string, f findSymbol) {
	if isStr {
		fmt.Fprintf(sb, "\"%s\"", s)
	} else if isNumberPtr {
		if data != 0 {
			t = mybtf.UnderlyingType(t).(*btf.Pointer).Target
			fmt.Fprintf(sb, "%#x(%s)", data, ReprValue(t, data2, dataNext, f))
		} else {
			fmt.Fprintf(sb, "%#x", data)
		}
	} else {
		fmt.Fprint(sb, ReprValue(t, data, dataNext, f))
	}
}

func ReprValueType(name string, t btf.Type, isStr, isNumberPtr bool, data, data2, dataNext uint64, s string, f findSymbol) string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "(%v)%s=", Repr(t), name)

	reprValue(&sb, t, isStr, isNumberPtr, data, data2, dataNext, s, f)

	return sb.String()
}

func ReprFuncParam(param *btf.FuncParam, i int, isStr, isNumberPtr bool, data, data2, dataNext uint64, s string, f findSymbol) string {
	return ReprValueType(param.Name, param.Type, isStr, isNumberPtr, data, data2, dataNext, s, f)
}

func ReprFuncReturn(typ btf.Type, isStr, isNumberPtr bool, data, data2 uint64, s string, f findSymbol) string {
	typ = mybtf.UnderlyingType(typ)
	if _, ok := typ.(*btf.Void); ok {
		return "(void)"
	}

	if isStr {
		return fmt.Sprintf("\"%s\"", s)
	}

	var sb strings.Builder

	fmt.Fprintf(&sb, "(%v)", Repr(typ))
	reprValue(&sb, typ, false, isNumberPtr, data, data2, 0, s, f)

	return sb.String()
}
