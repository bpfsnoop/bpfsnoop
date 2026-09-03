// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package btfx

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode"
	"unsafe"

	"github.com/Asphaltt/mybtf"
	"github.com/cilium/ebpf/btf"
)

type FindSymbol func(addr uint64) string

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

func GetStructBtfPointer(name string, spec *btf.Spec) (*btf.Pointer, error) {
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

func GetU64(data []byte, offset int) uint64 {
	return *(*uint64)(unsafe.Pointer(&data[offset]))
}

func SetU64(data []byte, val uint64) {
	*(*uint64)(unsafe.Pointer(&data[0])) = val
}

// DecodeValue converts native bytes for a BTF type into JSON-safe Go values.
func DecodeValue(typ btf.Type, data []byte) (any, error) {
	switch value := typ.(type) {
	case *btf.Typedef:
		return DecodeValue(value.Type, data)
	case *btf.Volatile:
		return DecodeValue(value.Type, data)
	case *btf.Const:
		return DecodeValue(value.Type, data)
	case *btf.Restrict:
		return DecodeValue(value.Type, data)
	case *btf.TypeTag:
		return DecodeValue(value.Type, data)
	case *btf.Var:
		decoded, err := DecodeValue(value.Type, data)
		if err != nil {
			return nil, err
		}
		return map[string]any{value.Name: decoded}, nil
	}

	size, err := btf.Sizeof(typ)
	if err != nil {
		return nil, fmt.Errorf("failed to get size of %T: %w", typ, err)
	}
	if len(data) < size {
		return nil, fmt.Errorf("data for %T is too short: got %d, need %d", typ, len(data), size)
	}
	data = data[:size]

	switch value := typ.(type) {
	case *btf.Int:
		return decodeInteger(value, data)
	case *btf.Pointer:
		if len(data) < 8 {
			return nil, fmt.Errorf("pointer data is too short: %d", len(data))
		}
		return fmt.Sprintf("%#x", binary.NativeEndian.Uint64(data)), nil
	case *btf.Enum:
		number, err := decodeUnsigned(data)
		if err != nil {
			return nil, err
		}
		result := map[string]any{"value": jsonUnsignedInteger(number)}
		if value.Signed {
			result["value"] = jsonSignedInteger(signedInteger(number, len(data)*8))
		}
		for _, enumValue := range value.Values {
			if enumValue.Value == number {
				result["name"] = enumValue.Name
				break
			}
		}
		return result, nil
	case *btf.Array:
		if mybtf.IsChar(value.Type) {
			length := len(data)
			if index := strings.IndexByte(string(data), 0); index >= 0 {
				length = index
			}
			return string(data[:length]), nil
		}
		elementSize, err := btf.Sizeof(value.Type)
		if err != nil {
			return nil, fmt.Errorf("failed to get array element size: %w", err)
		}
		values := make([]any, 0, value.Nelems)
		for i := uint32(0); i < value.Nelems; i++ {
			offset := int(i) * elementSize
			decoded, err := DecodeValue(value.Type, data[offset:offset+elementSize])
			if err != nil {
				return nil, fmt.Errorf("failed to decode array element %d: %w", i, err)
			}
			values = append(values, decoded)
		}
		return values, nil
	case *btf.Struct:
		return decodeMembers(value.Members, data)
	case *btf.Union:
		return decodeMembers(value.Members, data)
	case *btf.Float:
		switch value.Size {
		case 4:
			return math.Float32frombits(binary.NativeEndian.Uint32(data)), nil
		case 8:
			return math.Float64frombits(binary.NativeEndian.Uint64(data)), nil
		default:
			return nil, fmt.Errorf("unsupported float size %d", value.Size)
		}
	case *btf.Datasec:
		result := make(map[string]any, len(value.Vars))
		for i, variable := range value.Vars {
			start := int(variable.Offset)
			end := start + int(variable.Size)
			if start < 0 || end > len(data) {
				return nil, fmt.Errorf("data section entry %d is out of bounds", i)
			}
			decoded, err := DecodeValue(variable.Type, data[start:end])
			if err != nil {
				return nil, fmt.Errorf("failed to decode data section entry %d: %w", i, err)
			}
			name := fmt.Sprintf("$entry_%d", i)
			if variableValue, ok := variable.Type.(*btf.Var); ok && variableValue.Name != "" {
				name = variableValue.Name
				if nested, ok := decoded.(map[string]any); ok {
					decoded = nested[name]
				}
			}
			result[name] = decoded
		}
		return result, nil
	default:
		return nil, fmt.Errorf("unsupported BTF value type %T", typ)
	}
}

func decodeInteger(value *btf.Int, data []byte) (any, error) {
	number, err := decodeUnsigned(data)
	if err != nil {
		return nil, err
	}
	switch value.Encoding {
	case btf.Bool:
		return number != 0, nil
	case btf.Signed:
		return jsonSignedInteger(signedInteger(number, len(data)*8)), nil
	case btf.Char:
		r := rune(byte(number))
		if unicode.IsPrint(r) {
			return string(r), nil
		}
		return number, nil
	default:
		return jsonUnsignedInteger(number), nil
	}
}

func decodeUnsigned(data []byte) (uint64, error) {
	switch len(data) {
	case 1:
		return uint64(data[0]), nil
	case 2:
		return uint64(binary.NativeEndian.Uint16(data)), nil
	case 4:
		return uint64(binary.NativeEndian.Uint32(data)), nil
	case 8:
		return binary.NativeEndian.Uint64(data), nil
	default:
		return 0, fmt.Errorf("unsupported integer size %d", len(data))
	}
}

func signedInteger(value uint64, bits int) int64 {
	switch bits {
	case 8:
		return int64(int8(value))
	case 16:
		return int64(int16(value))
	case 32:
		return int64(int32(value))
	default:
		return int64(value)
	}
}

const maxJSONSafeInteger = uint64(1<<53 - 1)

func jsonUnsignedInteger(value uint64) any {
	if value <= maxJSONSafeInteger {
		return value
	}
	return strconv.FormatUint(value, 10)
}

func jsonSignedInteger(value int64) any {
	if value >= -int64(maxJSONSafeInteger) && value <= int64(maxJSONSafeInteger) {
		return value
	}
	return strconv.FormatInt(value, 10)
}

func decodeMembers(members []btf.Member, data []byte) (map[string]any, error) {
	result := make(map[string]any, len(members))
	for i, member := range members {
		name := member.Name
		if name == "" {
			name = fmt.Sprintf("$anonymous_%d", i)
		}
		var decoded any
		var err error
		if member.BitfieldSize != 0 {
			decoded, err = decodeBitfield(member, data)
		} else {
			start := int(member.Offset.Bytes())
			memberSize, sizeErr := btf.Sizeof(member.Type)
			if sizeErr != nil {
				return nil, fmt.Errorf("failed to get size of member %q: %w", name, sizeErr)
			}
			end := start + memberSize
			if start < 0 || end > len(data) {
				return nil, fmt.Errorf("member %q is out of bounds", name)
			}
			decoded, err = DecodeValue(member.Type, data[start:end])
		}
		if err != nil {
			return nil, fmt.Errorf("failed to decode member %q: %w", name, err)
		}
		result[name] = decoded
	}
	return result, nil
}

func decodeBitfield(member btf.Member, data []byte) (any, error) {
	size := int(member.BitfieldSize)
	if size <= 0 || size > 64 {
		return nil, fmt.Errorf("unsupported bitfield size %d", size)
	}
	offset := int(member.Offset)
	if offset+size > len(data)*8 {
		return nil, errors.New("bitfield is out of bounds")
	}
	var number uint64
	for bit := range size {
		absolute := offset + bit
		if data[absolute/8]&(1<<uint(absolute%8)) != 0 {
			number |= 1 << uint(bit)
		}
	}
	underlying := mybtf.UnderlyingType(member.Type)
	if integer, ok := underlying.(*btf.Int); ok && integer.Encoding == btf.Signed {
		if size < 64 && number&(1<<uint(size-1)) != 0 {
			number |= ^uint64(0) << uint(size)
		}
		return jsonSignedInteger(int64(number)), nil
	}
	return jsonUnsignedInteger(number), nil
}

func reprMember(sb *strings.Builder, m *btf.Member, data []byte, showMemberName bool, find FindSymbol) {
	if showMemberName && m.Name != "" {
		fmt.Fprintf(sb, "%s=", m.Name)
	}
	if m.BitfieldSize != 0 {
		fmt.Fprint(sb, mybtf.DumpBitfield(0, m.BitfieldSize, data))
	} else {
		offset := int(m.Offset.Bytes())
		val, valNext := GetU64(data, offset), GetU64(data, offset+8)
		fmt.Fprint(sb, ReprValue(m.Type, val, valNext, find))
	}
}

func reprStructUnionMembers(sb *strings.Builder, name string, members []btf.Member, data []byte, find FindSymbol) {
	fmt.Fprintf(sb, "%s{", name)
	defer fmt.Fprint(sb, "}")
	for i, m := range members {
		if i > 0 {
			fmt.Fprint(sb, ",")
		}
		reprMember(sb, &m, data, true, find)
	}
}

func ReprValue(t btf.Type, val, valNext uint64, find FindSymbol) string {
	t = mybtf.UnderlyingType(t)

	var sb strings.Builder

	size, err := btf.Sizeof(t)
	if err != nil {
		fmt.Fprintf(&sb, "..ERR..")
		return sb.String()
	}

	if stt, ok := t.(*btf.Struct); ok {
		var data [24]byte
		SetU64(data[:], val)
		SetU64(data[8:], valNext)
		reprStructUnionMembers(&sb, stt.Name, stt.Members, data[:], find)
		return sb.String()
	}
	if unn, ok := t.(*btf.Union); ok {
		var data [24]byte
		SetU64(data[:], val)
		SetU64(data[8:], valNext)
		reprStructUnionMembers(&sb, unn.Name, unn.Members, data[:], find)
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

func reprValue(sb *strings.Builder, t btf.Type, isStr, isNumberPtr bool, data, data2, dataNext uint64, s string, f FindSymbol) {
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

func ReprExprType(expr string, t btf.Type, mem *btf.Member, isStr, isNumberPtr bool, data, data2, dataNext uint64, s string, f FindSymbol) string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "(%s)'%s'=", Repr(t), expr)

	if mem != nil && mem.BitfieldSize != 0 {
		var memData [24]byte
		SetU64(memData[:], data)
		SetU64(memData[8:], data2)
		reprMember(&sb, mem, memData[:], false, f)
	} else {
		reprValue(&sb, t, isStr, isNumberPtr, data, data2, dataNext, s, f)
	}

	return sb.String()
}

func ReprValueType(name string, t btf.Type, isStr, isNumberPtr bool, data, data2, dataNext uint64, s string, f FindSymbol) string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "(%v)%s=", Repr(t), name)

	reprValue(&sb, t, isStr, isNumberPtr, data, data2, dataNext, s, f)

	return sb.String()
}

func ReprFuncParam(param *btf.FuncParam, i int, isStr, isNumberPtr bool, data, data2, dataNext uint64, s string, f FindSymbol) string {
	return ReprValueType(param.Name, param.Type, isStr, isNumberPtr, data, data2, dataNext, s, f)
}

func ReprFuncReturn(typ btf.Type, isStr, isNumberPtr bool, data, data2 uint64, s string, f FindSymbol) string {
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
