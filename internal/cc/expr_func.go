// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"fmt"
	"slices"

	"github.com/Asphaltt/mybtf"
	"github.com/cilium/ebpf/btf"
	"rsc.io/c2go/cc"
)

const (
	PktTypeEth   = "eth"
	PktTypeIP    = "ip"
	PktTypeIP4   = "ip4"
	PktTypeIP6   = "ip6"
	PktTypeICMP  = "icmp"
	PktTypeICMP6 = "icmp6"
	PktTypeTCP   = "tcp"
	PktTypeUDP   = "udp"
)

const (
	AddrTypeEth  = "eth"
	AddrTypeEth2 = "eth2"
	AddrTypeIP4  = "ip4"
	AddrTypeIP42 = "ip42"
	AddrTypeIP6  = "ip6"
	AddrTypeIP62 = "ip62"

	Port  = "port"
	Port2 = "port2"
)

const (
	EthAddrSize = 6
	IP4AddrSize = 4
	IP6AddrSize = 16

	PortSize = 2 // TCP/UDP port size
)

type funcCallValue struct {
	typ        EvalResultType
	expr       *cc.Expr
	dataOffset int64
	dataSize   int64
	pkt        string
	addr       string
	port       string
}

func parseExprNumber(expr *cc.Expr) (int64, error) {
	if expr.Op != cc.Number {
		return 0, fmt.Errorf("expected a number expression, got %s", expr.Op)
	}

	num, err := parseNumber(expr.Text)
	if err != nil {
		return 0, fmt.Errorf("failed to parse number: %w", err)
	}

	return num, nil
}

func compileFuncCall(expr *cc.Expr) (funcCallValue, error) {
	var (
		val funcCallValue
		err error
	)

	val.expr = expr.List[0]

	fnName := expr.Left.Text
	switch fnName {
	case "buf", "slice":
		switch len(expr.List) {
		case 2, 3:
			val.dataSize, err = parseExprNumber(expr.List[1])
			if err != nil {
				return val, fmt.Errorf("%s() second argument must be a number: %w", fnName, err)
			}

			if len(expr.List) == 3 {
				val.dataOffset = val.dataSize

				val.dataSize, err = parseExprNumber(expr.List[2])
				if err != nil {
					return val, fmt.Errorf("%s() third argument must be a number: %w", fnName, err)
				}
			}

		default:
			return val, fmt.Errorf("%s() must have 2 or 3 arguments", fnName)
		}

		if val.dataSize <= 0 {
			return val, fmt.Errorf("%s() size must be greater than 0", fnName)
		}

		val.typ = EvalResultTypeBuf
		if fnName == "slice" {
			val.typ = EvalResultTypeSlice
		}

	case "str":
		if len(expr.List) != 1 && len(expr.List) != 2 {
			return val, fmt.Errorf("%s() must have 1 or 2 arguments", fnName)
		}

		val.dataSize = -1
		if len(expr.List) == 2 {
			val.dataSize, err = parseExprNumber(expr.List[1])
			if err != nil {
				return val, fmt.Errorf("%s() second argument must be a number: %w", fnName, err)
			}
			if val.dataSize <= 0 {
				return val, fmt.Errorf("%s() size must be greater than 0", fnName)
			}
		}

		val.typ = EvalResultTypeString

	case "pkt":
		allowedPktTypes := []string{
			PktTypeEth,
			PktTypeIP, PktTypeIP4, PktTypeIP6,
			PktTypeICMP, PktTypeICMP6,
			PktTypeTCP, PktTypeUDP,
		}

		switch len(expr.List) {
		case 2:
			val.dataSize, err = parseExprNumber(expr.List[1])
			if err != nil {
				return val, fmt.Errorf("%s() second argument must be a number: %w", fnName, err)
			}

			val.pkt = PktTypeEth // default pkt type

		case 3:
			val.dataSize, err = parseExprNumber(expr.List[1])
			if err != nil {
				return val, fmt.Errorf("%s() second argument must be a number: %w", fnName, err)
			}

			switch expr.List[2].Op {
			case cc.Name:
				pktType := expr.List[2].Text
				if !slices.Contains(allowedPktTypes, pktType) {
					return val, fmt.Errorf("%s() third argument as pkt type must be one of %v", fnName, allowedPktTypes)
				}

				val.pkt = pktType

			case cc.Number:
				val.dataOffset = val.dataSize
				val.dataSize, err = parseNumber(expr.List[2].Text)
				if err != nil {
					return val, fmt.Errorf("%s() third argument must be a number: %w", fnName, err)
				}

				val.pkt = PktTypeEth // default pkt type

			default:
				return val, fmt.Errorf("%s() third argument must be pkt type or a number", fnName)
			}

		case 4:
			val.dataOffset, err = parseExprNumber(expr.List[1])
			if err != nil {
				return val, fmt.Errorf("%s() second argument must be a number: %w", fnName, err)
			}

			val.dataSize, err = parseExprNumber(expr.List[2])
			if err != nil {
				return val, fmt.Errorf("%s() third argument must be a number: %w", fnName, err)
			}

			if expr.List[3].Op != cc.Name {
				return val, fmt.Errorf("%s() fourth argument must be pkt type", fnName)
			}
			pktType := expr.List[3].Text
			if !slices.Contains(allowedPktTypes, pktType) {
				return val, fmt.Errorf("%s() fourth argument as pkt type must be one of %v", fnName, allowedPktTypes)
			}

			val.pkt = pktType

		default:
			return val, fmt.Errorf("%s() must have 2, 3 or 4 arguments", fnName)
		}

		if val.dataSize <= 0 {
			return val, fmt.Errorf("%s() size must be greater than 0", fnName)
		}

		val.typ = EvalResultTypePkt

	case AddrTypeEth, AddrTypeEth2,
		AddrTypeIP4, AddrTypeIP42,
		AddrTypeIP6, AddrTypeIP62,
		Port, Port2:
		switch len(expr.List) {
		case 1:
			break

		case 2:
			val.dataOffset, err = parseExprNumber(expr.List[1])
			if err != nil {
				return val, fmt.Errorf("%s() second argument must be a number: %w", fnName, err)
			}

		default:
			return val, fmt.Errorf("%s() must have 1 or 2 arguments", fnName)
		}

		switch fnName {
		case AddrTypeEth:
			val.dataSize = EthAddrSize // Ethernet address size
			val.addr = AddrTypeEth

		case AddrTypeEth2:
			val.dataSize = EthAddrSize * 2 // Ethernet address size * 2
			val.addr = AddrTypeEth2

		case AddrTypeIP4:
			val.dataSize = IP4AddrSize // IPv4 address size
			val.addr = AddrTypeIP4

		case AddrTypeIP42:
			val.dataSize = IP4AddrSize * 2 // IPv4 address size * 2
			val.addr = AddrTypeIP42

		case AddrTypeIP6:
			val.dataSize = IP6AddrSize // IPv6 address size
			val.addr = AddrTypeIP6

		case AddrTypeIP62:
			val.dataSize = IP6AddrSize * 2 // IPv6 address size * 2
			val.addr = AddrTypeIP62

		case Port:
			val.dataSize = PortSize // TCP/UDP port size
			val.port = Port

		case Port2:
			val.dataSize = PortSize * 2 // TCP/UDP port size * 2
			val.port = Port2
		}

		val.typ = EvalResultTypeAddr
		if fnName == Port || fnName == Port2 {
			val.typ = EvalResultTypePort
		}

	default:
		return val, fmt.Errorf("unknown function call: %s", fnName)
	}

	return val, err
}

func postCheckFuncCall(res *EvalResult, val evalValue, dataOffset, dataSize int64, fnName string) error {
	if res.Type != EvalResultTypeDefault && isMemberBitfield(val.mem) {
		return fmt.Errorf("disallow member bitfield for %s()", fnName)
	}

	switch res.Type {
	case EvalResultTypeDeref:
		t := mybtf.UnderlyingType(val.btf)
		ptr, ok := t.(*btf.Pointer)
		if !ok {
			return fmt.Errorf("disallow non-pointer type %v for pointer dereference", t)
		}

		size, _ := btf.Sizeof(ptr.Target)
		if size == 0 {
			return fmt.Errorf("disallow zero size type %v for pointer dereference", ptr.Target)
		}

		res.Btf = ptr.Target
		res.Size = size

	case EvalResultTypeBuf:
		t := mybtf.UnderlyingType(val.btf)
		_, isPtr := t.(*btf.Pointer)
		_, isArray := t.(*btf.Array)
		if !isPtr && !isArray {
			return fmt.Errorf("disallow non-{pointer,array} type %v for %s()", t, fnName)
		}

		res.Off = int(dataOffset)
		res.Size = int(dataSize)
		res.Btf = t

	case EvalResultTypeString:
		t := mybtf.UnderlyingType(val.btf)
		_, isPtr := t.(*btf.Pointer)
		arr, isArray := t.(*btf.Array)
		if !isPtr && !isArray {
			return fmt.Errorf("disallow non-{pointer,array} type %v for %s()", t, fnName)
		}

		if dataSize == -1 {
			if isPtr {
				dataSize = 64
			} else {
				size, _ := btf.Sizeof(arr.Type)
				if size != 1 {
					return fmt.Errorf("disallow non-1-byte-size type %v for %s()", arr.Type, fnName)
				}
				dataSize = int64(arr.Nelems)
			}
		}

		res.Size = int(dataSize)
		res.Btf = t

	case EvalResultTypePkt, EvalResultTypeAddr, EvalResultTypePort:
		t := mybtf.UnderlyingType(val.btf)
		_, isPtr := t.(*btf.Pointer)
		if !isPtr {
			return fmt.Errorf("disallow non-pointer type %v for %s()", t, fnName)
		}

		res.Off = int(dataOffset)
		res.Size = int(dataSize)
		res.Btf = t

	case EvalResultTypeSlice:
		t := mybtf.UnderlyingType(val.btf)
		ptr, isPtr := t.(*btf.Pointer)
		arr, isArray := t.(*btf.Array)
		if !isPtr && !isArray {
			return fmt.Errorf("disallow non-{pointer,array} type %v for %s()", t, fnName)
		}

		if isPtr {
			res.Btf = ptr.Target
		} else if isArray {
			res.Btf = arr.Type
		}
		size, _ := btf.Sizeof(res.Btf)
		if size == 0 {
			return fmt.Errorf("disallow zero size type %v for %s()", res.Btf, fnName)
		}

		res.Off = int(dataOffset) * size
		res.Size = int(dataSize) * size

	default:
		res.Btf = val.btf
		res.Mem = val.mem
	}

	return nil
}
