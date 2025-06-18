// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"unsafe"

	"github.com/Asphaltt/mybtf"
	"github.com/cilium/ebpf/btf"
	"github.com/fatih/color"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/bpfsnoop/bpfsnoop/internal/btfx"
	"github.com/bpfsnoop/bpfsnoop/internal/cc"
	"github.com/bpfsnoop/bpfsnoop/internal/strx"
)

func dumpOutputArgBuf(data []byte) string {
	sb := &strings.Builder{}

	fmt.Fprint(sb, "[")
	for i, b := range data {
		if i != 0 {
			fmt.Fprint(sb, ",")
		}

		fmt.Fprintf(sb, "%#02x", b)
	}
	fmt.Fprint(sb, "]")

	return sb.String()
}

func outputFuncArgAttrs(sb *strings.Builder, info *funcInfo, data []byte, f btfx.FindSymbol) error {
	fmt.Fprint(sb, "Arg attrs: ")

	gray := color.RGB(0x88, 0x88, 0x88 /* gray */)
	for i, arg := range info.args {
		if i != 0 {
			fmt.Fprint(sb, ", ")
		}

		exception := data[arg.size-1]
		if exception != 0 {
			data = data[arg.size:]
			s := fmt.Sprintf("(%s)'%s'=[NULL]", btfx.Repr(arg.t), arg.expr)
			if colorfulOutput {
				color.New(color.FgRed).Fprint(sb, s)
			} else {
				fmt.Fprint(sb, s)
			}
			continue
		}

		if arg.isDeref || arg.isBuf || arg.isPkt || arg.isAddr || arg.isString ||
			arg.isSlice || arg.isHex || arg.isNum {
			var (
				s   string
				err error
			)

			switch {
			case arg.isDeref:
				s, err = mybtf.DumpData(arg.t, data[:arg.trueDataSize])
				if err != nil {
					return fmt.Errorf("failed to dump deref data: %w", err)
				}

				s = fmt.Sprintf("(%s)'%s'=%s", btfx.Repr(arg.t), arg.expr, s)

			case arg.isBuf:
				s = fmt.Sprintf("(%s)'%s'=%s", btfx.Repr(arg.t), arg.expr,
					dumpOutputArgBuf(data[:arg.trueDataSize]))

			case arg.isHex:
				s = fmt.Sprintf("(%s)'%s'=%s", btfx.Repr(arg.t), arg.expr,
					hex.EncodeToString(data[:arg.trueDataSize]))

			case arg.isSlice:
				size, _ := btf.Sizeof(arg.t)
				cnt := arg.trueDataSize / size

				var sb strings.Builder
				sb.WriteString(fmt.Sprintf("(%s)'%s'=[", btfx.Repr(arg.t), arg.expr))
				for i := range cnt {
					dd, err := mybtf.DumpData(arg.t, data[i*size:(i+1)*size])
					if err != nil {
						return fmt.Errorf("failed to dump slice data: %w", err)
					}

					if i != 0 {
						sb.WriteString(",")
					}
					sb.WriteString(dd)
				}
				sb.WriteString("]")

				s = sb.String()

			case arg.isPkt:
				layer := layers.LayerTypeEthernet
				switch arg.pktType {
				case cc.PktTypeEth:
					layer = layers.LayerTypeEthernet
				case cc.PktTypeIP, cc.PktTypeIP4:
					layer = layers.LayerTypeIPv4
				case cc.PktTypeIP6:
					layer = layers.LayerTypeIPv6
				case cc.PktTypeICMP:
					layer = layers.LayerTypeICMPv4
				case cc.PktTypeICMP6:
					layer = layers.LayerTypeICMPv6
				case cc.PktTypeTCP:
					layer = layers.LayerTypeTCP
				case cc.PktTypeUDP:
					layer = layers.LayerTypeUDP
				}
				pkt := gopacket.NewPacket(data[:arg.trueDataSize], layer, gopacket.NoCopy)
				s = fmt.Sprintf("(%s)'%s'=%v", btfx.Repr(arg.t), arg.expr, pkt)

			case arg.isAddr:
				switch arg.AddrType {
				case cc.EvalResultTypeEthAddr:
					if arg.AddrNum == 1 {
						s = fmt.Sprintf("(%s)'%s'=%s", btfx.Repr(arg.t), arg.expr,
							net.HardwareAddr(data[:cc.EthAddrSize]))
					} else {
						s = fmt.Sprintf("(%s)'%s'=[%s,%s]", btfx.Repr(arg.t), arg.expr,
							net.HardwareAddr(data[:cc.EthAddrSize]),
							net.HardwareAddr(data[cc.EthAddrSize:cc.EthAddrSize*2]))
					}

				case cc.EvalResultTypeIP4Addr:
					if arg.AddrNum == 1 {
						s = fmt.Sprintf("(%s)'%s'=%s", btfx.Repr(arg.t), arg.expr,
							net.IP(data[:cc.IP4AddrSize]))
					} else {
						s = fmt.Sprintf("(%s)'%s'=[%s,%s]", btfx.Repr(arg.t), arg.expr,
							net.IP(data[:cc.IP4AddrSize]),
							net.IP(data[cc.IP4AddrSize:cc.IP4AddrSize*2]))
					}

				case cc.EvalResultTypeIP6Addr:
					if arg.AddrNum == 1 {
						s = fmt.Sprintf("(%s)'%s'=%s", btfx.Repr(arg.t), arg.expr,
							net.IP(data[:cc.IP6AddrSize]))
					} else {
						s = fmt.Sprintf("(%s)'%s'=[%s,%s]", btfx.Repr(arg.t), arg.expr,
							net.IP(data[:cc.IP6AddrSize]),
							net.IP(data[cc.IP6AddrSize:cc.IP6AddrSize*2]))
					}

				case cc.EvalResultTypePort:
					if arg.AddrNum == 1 {
						s = fmt.Sprintf("(%s)'%s'=%d", btfx.Repr(arg.t), arg.expr,
							uint16(data[0])<<8|uint16(data[1]))
					} else {
						s = fmt.Sprintf("(%s)'%s'=[%d,%d]", btfx.Repr(arg.t), arg.expr,
							uint16(data[0])<<8|uint16(data[1]),
							uint16(data[2])<<8|uint16(data[3]))
					}
				}

			case arg.isString:
				s = fmt.Sprintf(`(%s)'%s'="%s"`, btfx.Repr(arg.t), arg.expr,
					strx.NullTerminated(data[:arg.trueDataSize]))

			case arg.isNum:
				var sb strings.Builder
				sb.WriteString(fmt.Sprintf("(%s)'%s'=", btfx.Repr(arg.t), arg.expr))
				switch arg.numType {
				case "u8":
					n := data[0]
					sb.WriteString(fmt.Sprintf("%#x/%d", n, n))
				case "u16":
					u16 := *(*uint16)(unsafe.Pointer(&data[0]))
					sb.WriteString(fmt.Sprintf("%#x/%d", u16, u16))
				case "u32":
					u32 := *(*uint32)(unsafe.Pointer(&data[0]))
					sb.WriteString(fmt.Sprintf("%#x/%d", u32, u32))
				case "u64":
					u64 := *(*uint64)(unsafe.Pointer(&data[0]))
					sb.WriteString(fmt.Sprintf("%#x/%d", u64, u64))
				case "s8":
					n := int8(data[0])
					sb.WriteString(fmt.Sprintf("%d", n))
				case "s16":
					s16 := *(*int16)(unsafe.Pointer(&data[0]))
					sb.WriteString(fmt.Sprintf("%d", s16))
				case "s32":
					s32 := *(*int32)(unsafe.Pointer(&data[0]))
					sb.WriteString(fmt.Sprintf("%d", s32))
				case "s64":
					s64 := *(*int64)(unsafe.Pointer(&data[0]))
					sb.WriteString(fmt.Sprintf("%d", s64))
				case "be16":
					be16 := binary.BigEndian.Uint16(data[:2])
					sb.WriteString(fmt.Sprintf("%#x/%d", be16, be16))
				case "be32":
					be32 := binary.BigEndian.Uint32(data[:4])
					sb.WriteString(fmt.Sprintf("%#x/%d", be32, be32))
				case "be64":
					be64 := binary.BigEndian.Uint64(data[:8])
					sb.WriteString(fmt.Sprintf("%#x/%d", be64, be64))
				case "le16":
					le16 := binary.LittleEndian.Uint16(data[:2])
					sb.WriteString(fmt.Sprintf("%#x/%d", le16, le16))
				case "le32":
					le32 := binary.LittleEndian.Uint32(data[:4])
					sb.WriteString(fmt.Sprintf("%#x/%d", le32, le32))
				case "le64":
					le64 := binary.LittleEndian.Uint64(data[:8])
					sb.WriteString(fmt.Sprintf("%#x/%d", le64, le64))
				}

				s = sb.String()
			}

			if colorfulOutput {
				gray.Fprint(sb, s)
			} else {
				fmt.Fprint(sb, s)
			}

			data = data[arg.size:]
			continue
		}

		var argStr string
		var argVal, argVal2 uint64
		if arg.isStr {
			argStr, data = readStrN(data, arg.trueDataSize)
		} else {
			argVal, data = readUint64(data)
			if arg.isNumPtr {
				argVal2, data = readUint64(data)
			}
		}

		s := btfx.ReprExprType(arg.expr, arg.t, arg.mem, arg.isStr, arg.isNumPtr, argVal, argVal2, 0, argStr, f)
		if colorfulOutput {
			gray.Fprint(sb, s)
		} else {
			fmt.Fprint(sb, s)
		}

		data = data[1:] // skip the exception result
	}

	fmt.Fprintln(sb)

	return nil
}
