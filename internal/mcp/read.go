// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/Asphaltt/mybtf"
	"github.com/cilium/ebpf/btf"

	"github.com/bpfsnoop/bpfsnoop/internal/bpfsnoop"
	"github.com/bpfsnoop/bpfsnoop/internal/btfx"
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
			value, err := btfx.DecodeValue(result.BTFType, data[offset:offset+size])
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
		return map[string]any{"type": result.PacketType, "bytes": bytesAsNumbers(data)}, nil
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
		value, err := btfx.DecodeValue(ptr.Target, data[8:])
		if err != nil {
			return nil, fmt.Errorf("failed to decode numeric pointer target: %w", err)
		}
		output["value"] = value
		return output, nil
	default:
		return btfx.DecodeValue(result.BTFType, data)
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
