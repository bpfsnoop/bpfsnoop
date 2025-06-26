// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"fmt"
	"net"
	"strings"

	"github.com/Asphaltt/mybtf"
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

		case arg.isString:
			s = fmt.Sprintf(`(%s)'%s'="%s"`, btfx.Repr(arg.t), arg.expr,
				strx.NullTerminated(data[:arg.trueDataSize]))

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
			switch arg.addrType {
			case cc.AddrTypeEth:
				s = fmt.Sprintf("(%s)'%s'=%s", btfx.Repr(arg.t), arg.expr,
					net.HardwareAddr(data[:cc.EthAddrSize]))

			case cc.AddrTypeEth2:
				s = fmt.Sprintf("(%s)'%s'=[%s,%s]", btfx.Repr(arg.t), arg.expr,
					net.HardwareAddr(data[:cc.EthAddrSize]),
					net.HardwareAddr(data[cc.EthAddrSize:cc.EthAddrSize*2]))

			case cc.AddrTypeIP4:
				s = fmt.Sprintf("(%s)'%s'=%s", btfx.Repr(arg.t), arg.expr,
					net.IP(data[:cc.IP4AddrSize]))

			case cc.AddrTypeIP42:
				s = fmt.Sprintf("(%s)'%s'=[%s,%s]", btfx.Repr(arg.t), arg.expr,
					net.IP(data[:cc.IP4AddrSize]),
					net.IP(data[cc.IP4AddrSize:cc.IP4AddrSize*2]))

			case cc.AddrTypeIP6:
				s = fmt.Sprintf("(%s)'%s'=%s", btfx.Repr(arg.t), arg.expr,
					net.IP(data[:cc.IP6AddrSize]))

			case cc.AddrTypeIP62:
				s = fmt.Sprintf("(%s)'%s'=[%s,%s]", btfx.Repr(arg.t), arg.expr,
					net.IP(data[:cc.IP6AddrSize]),
					net.IP(data[cc.IP6AddrSize:cc.IP6AddrSize*2]))
			}

		case arg.isPort:
			switch arg.portType {
			case cc.Port:
				s = fmt.Sprintf("(%s)'%s'=%d", btfx.Repr(arg.t), arg.expr,
					be.Uint16(data[:cc.PortSize]))

			case cc.Port2:
				s = fmt.Sprintf("(%s)'%s'=[%d,%d]", btfx.Repr(arg.t), arg.expr,
					be.Uint16(data[:cc.PortSize]),
					be.Uint16(data[cc.PortSize:cc.PortSize*2]))
			}
		}

		if s != "" {
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

		s = btfx.ReprExprType(arg.expr, arg.t, arg.mem, arg.isStr, arg.isNumPtr, argVal, argVal2, 0, argStr, f)
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
