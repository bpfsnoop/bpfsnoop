// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"unicode"

	"github.com/Asphaltt/mybtf"
	"github.com/cilium/ebpf/btf"

	"github.com/bpfsnoop/bpfsnoop/internal/bpfsnoop"
	"github.com/bpfsnoop/bpfsnoop/internal/cc"
	"github.com/bpfsnoop/bpfsnoop/internal/strx"
)

func kernelReadValue(result *bpfsnoop.ReadKernelResult) (any, error) {
	if result.Size <= 0 || len(result.Buffer) < result.Size {
		return nil, fmt.Errorf("kernel read returned %d bytes, need %d", len(result.Buffer), result.Size)
	}
	if result.Buffer[result.Size-1] != 0 {
		return nil, nil
	}

	data := result.Buffer[:result.DataSize]
	switch {
	case result.String:
		return strx.NullTerminated(data), nil

	case result.BufferValue:
		return bytesAsNumbers(data), nil

	case result.Slice:
		size, err := btf.Sizeof(result.BTFType)
		if err != nil {
			return nil, fmt.Errorf("failed to get slice element size: %w", err)
		}
		if size <= 0 || len(data)%size != 0 {
			return nil, fmt.Errorf("invalid slice data size %d for element size %d", len(data), size)
		}
		values := make([]any, 0, len(data)/size)
		for offset := 0; offset < len(data); offset += size {
			value, err := decodeBTFValue(result.BTFType, data[offset:offset+size])
			if err != nil {
				return nil, fmt.Errorf("failed to decode slice element %d: %w", offset/size, err)
			}
			values = append(values, value)
		}
		return values, nil

	case result.Hex:
		return fmt.Sprintf("%x", data), nil

	case result.IntegerType != "":
		return decodeExplicitInteger(result.IntegerType, data)

	case result.AddressType != "":
		return decodeAddress(result.AddressType, data)

	case result.PortType != "":
		return decodePort(result.PortType, data)

	case result.Packet:
		return map[string]any{
			"type":  result.PacketType,
			"bytes": bytesAsNumbers(data),
		}, nil

	case result.NumericPointer:
		if len(data) < 8 {
			return nil, fmt.Errorf("numeric pointer data is too short: %d", len(data))
		}
		address := binary.NativeEndian.Uint64(data[:8])
		output := map[string]any{"address": fmt.Sprintf("%#x", address)}
		if address == 0 {
			output["value"] = nil
			return output, nil
		}
		ptr := mybtf.UnderlyingType(result.BTFType).(*btf.Pointer)
		value, err := decodeBTFValue(ptr.Target, data[8:])
		if err != nil {
			return nil, fmt.Errorf("failed to decode numeric pointer target: %w", err)
		}
		output["value"] = value
		return output, nil

	default:
		return decodeBTFValue(result.BTFType, data)
	}
}

func bytesAsNumbers(data []byte) []uint64 {
	values := make([]uint64, len(data))
	for i, value := range data {
		values[i] = uint64(value)
	}
	return values
}

func decodeExplicitInteger(kind string, data []byte) (any, error) {
	need := 0
	switch kind {
	case cc.IntTypeU8, cc.IntTypeS8:
		need = 1
	case cc.IntTypeU16, cc.IntTypeS16, cc.IntTypeLe16, cc.IntTypeBe16:
		need = 2
	case cc.IntTypeU32, cc.IntTypeS32, cc.IntTypeLe32, cc.IntTypeBe32:
		need = 4
	case cc.IntTypeU64, cc.IntTypeS64, cc.IntTypeLe64, cc.IntTypeBe64:
		need = 8
	default:
		return nil, fmt.Errorf("unknown explicit integer type %q", kind)
	}
	if len(data) < need {
		return nil, fmt.Errorf("integer data is too short: got %d, need %d", len(data), need)
	}

	var order binary.ByteOrder = binary.NativeEndian
	if strings.HasPrefix(kind, "le") {
		order = binary.LittleEndian
	} else if strings.HasPrefix(kind, "be") {
		order = binary.BigEndian
	}

	signed := strings.HasPrefix(kind, "s")
	switch need {
	case 1:
		if signed {
			return int8(data[0]), nil
		}
		return data[0], nil
	case 2:
		value := order.Uint16(data)
		if signed {
			return int16(value), nil
		}
		return value, nil
	case 4:
		value := order.Uint32(data)
		if signed {
			return int32(value), nil
		}
		return value, nil
	default:
		value := order.Uint64(data)
		if signed {
			return jsonSignedInteger(int64(value)), nil
		}
		return jsonUnsignedInteger(value), nil
	}
}

func decodeAddress(kind string, data []byte) (any, error) {
	var size, count int
	switch kind {
	case cc.AddrTypeEth:
		size, count = cc.EthAddrSize, 1
	case cc.AddrTypeEth2:
		size, count = cc.EthAddrSize, 2
	case cc.AddrTypeIP4:
		size, count = cc.IP4AddrSize, 1
	case cc.AddrTypeIP42:
		size, count = cc.IP4AddrSize, 2
	case cc.AddrTypeIP6:
		size, count = cc.IP6AddrSize, 1
	case cc.AddrTypeIP62:
		size, count = cc.IP6AddrSize, 2
	default:
		return nil, fmt.Errorf("unknown address type %q", kind)
	}
	if len(data) < size*count {
		return nil, fmt.Errorf("address data is too short: got %d, need %d", len(data), size*count)
	}

	values := make([]string, 0, count)
	for i := range count {
		value := data[i*size : (i+1)*size]
		if size == cc.EthAddrSize {
			values = append(values, net.HardwareAddr(value).String())
		} else {
			values = append(values, net.IP(value).String())
		}
	}
	if count == 1 {
		return values[0], nil
	}
	return values, nil
}

func decodePort(kind string, data []byte) (any, error) {
	count := 1
	if kind == cc.Port2 {
		count = 2
	} else if kind != cc.Port {
		return nil, fmt.Errorf("unknown port type %q", kind)
	}
	if len(data) < cc.PortSize*count {
		return nil, fmt.Errorf("port data is too short: got %d, need %d", len(data), cc.PortSize*count)
	}

	values := make([]uint16, count)
	for i := range count {
		values[i] = binary.BigEndian.Uint16(data[i*cc.PortSize : (i+1)*cc.PortSize])
	}
	if count == 1 {
		return values[0], nil
	}
	return values, nil
}

func decodeBTFValue(typ btf.Type, data []byte) (any, error) {
	switch value := typ.(type) {
	case *btf.Typedef:
		return decodeBTFValue(value.Type, data)
	case *btf.Volatile:
		return decodeBTFValue(value.Type, data)
	case *btf.Const:
		return decodeBTFValue(value.Type, data)
	case *btf.Restrict:
		return decodeBTFValue(value.Type, data)
	case *btf.TypeTag:
		return decodeBTFValue(value.Type, data)
	case *btf.Var:
		decoded, err := decodeBTFValue(value.Type, data)
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
		return decodeBTFInteger(value, data)

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
			decoded, err := decodeBTFValue(value.Type, data[offset:offset+elementSize])
			if err != nil {
				return nil, fmt.Errorf("failed to decode array element %d: %w", i, err)
			}
			values = append(values, decoded)
		}
		return values, nil

	case *btf.Struct:
		return decodeBTFMembers(value.Members, data)

	case *btf.Union:
		return decodeBTFMembers(value.Members, data)

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
			decoded, err := decodeBTFValue(variable.Type, data[start:end])
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

func decodeBTFInteger(value *btf.Int, data []byte) (any, error) {
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

func decodeBTFMembers(members []btf.Member, data []byte) (map[string]any, error) {
	result := make(map[string]any, len(members))
	for i, member := range members {
		name := member.Name
		if name == "" {
			name = fmt.Sprintf("$anonymous_%d", i)
		}

		var decoded any
		var err error
		if member.BitfieldSize != 0 {
			decoded, err = decodeBTFBitfield(member, data)
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
			decoded, err = decodeBTFValue(member.Type, data[start:end])
		}
		if err != nil {
			return nil, fmt.Errorf("failed to decode member %q: %w", name, err)
		}
		result[name] = decoded
	}
	return result, nil
}

func decodeBTFBitfield(member btf.Member, data []byte) (any, error) {
	size := int(member.BitfieldSize)
	if size <= 0 || size > 64 {
		return nil, fmt.Errorf("unsupported bitfield size %d", size)
	}
	offset := int(member.Offset)
	if offset+size > len(data)*8 {
		return nil, fmt.Errorf("bitfield is out of bounds")
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
