// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"testing"

	"github.com/bpfsnoop/bpfsnoop/internal/test"
	"github.com/cilium/ebpf/btf"
	"rsc.io/c2go/cc"
)

func TestParseExprNumber(t *testing.T) {
	t.Run("invalid expression", func(t *testing.T) {
		expr, err := cc.ParseExpr("skb->cb")
		test.AssertNoErr(t, err)

		_, err = parseExprNumber(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "expected a number expression")
	})
	t.Run("valid number", func(t *testing.T) {
		expr, err := cc.ParseExpr("0xFF")
		test.AssertNoErr(t, err)

		num, err := parseExprNumber(expr)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, num, int64(255))
	})

	t.Run("invalid number", func(t *testing.T) {
		expr, err := cc.ParseExpr("0xFFULL")
		test.AssertNoErr(t, err)

		_, err = parseExprNumber(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "failed to parse number")
	})
}

func TestCompileFuncCall(t *testing.T) {
	t.Run("buf", func(t *testing.T) {
		t.Run("buf(skb->cb, x)", func(t *testing.T) {
			expr, err := cc.ParseExpr("buf(skb->cb, x)")
			test.AssertNoErr(t, err)

			_, err = compileFuncCall(expr)
			test.AssertHaveErr(t, err)
			test.AssertErrorPrefix(t, err, "buf() second argument must be a number")
		})

		t.Run("buf(skb->cb, 0xFFULL)", func(t *testing.T) {
			expr, err := cc.ParseExpr("buf(skb->cb, 0xFFULL)")
			test.AssertNoErr(t, err)

			_, err = compileFuncCall(expr)
			test.AssertHaveErr(t, err)
			test.AssertErrorPrefix(t, err, "buf() second argument must be a number")
		})

		t.Run("buf(skb->cb, 0xFF, a)", func(t *testing.T) {
			expr, err := cc.ParseExpr("buf(skb->cb, 0xFF, a)")
			test.AssertNoErr(t, err)

			_, err = compileFuncCall(expr)
			test.AssertHaveErr(t, err)
			test.AssertErrorPrefix(t, err, "buf() third argument must be a number")
		})

		t.Run("buf(skb->cb, 0xFF, 0xFFULL)", func(t *testing.T) {
			expr, err := cc.ParseExpr("buf(skb->cb, 0xFF, 0xFFULL)")
			test.AssertNoErr(t, err)

			_, err = compileFuncCall(expr)
			test.AssertHaveErr(t, err)
			test.AssertErrorPrefix(t, err, "buf() third argument must be a number")
		})

		t.Run("buf(skb->cb)", func(t *testing.T) {
			expr, err := cc.ParseExpr("buf(skb->cb)")
			test.AssertNoErr(t, err)

			_, err = compileFuncCall(expr)
			test.AssertHaveErr(t, err)
			test.AssertErrorPrefix(t, err, "buf() must have 2 or 3 arguments")
		})

		t.Run("buf(skb->cb, 0)", func(t *testing.T) {
			expr, err := cc.ParseExpr("buf(skb->cb, 0)")
			test.AssertNoErr(t, err)

			_, err = compileFuncCall(expr)
			test.AssertHaveErr(t, err)
			test.AssertErrorPrefix(t, err, "buf() size must be greater than 0")
		})

		t.Run("buf(skb->cb, 14)", func(t *testing.T) {
			expr, err := cc.ParseExpr("buf(skb->cb, 14)")
			test.AssertNoErr(t, err)

			val, err := compileFuncCall(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, val.typ, EvalResultTypeBuf)
			test.AssertEqual(t, val.dataSize, 14)
			test.AssertEqual(t, val.dataOffset, 0)
		})
	})

	t.Run("str", func(t *testing.T) {
		t.Run("str(skb->cb, a, b)", func(t *testing.T) {
			expr, err := cc.ParseExpr("str(skb->cb, a, b)")
			test.AssertNoErr(t, err)

			_, err = compileFuncCall(expr)
			test.AssertHaveErr(t, err)
			test.AssertErrorPrefix(t, err, "str() must have 1 or 2 arguments")
		})

		t.Run("str(skb->cb, a)", func(t *testing.T) {
			expr, err := cc.ParseExpr("str(skb->cb, a)")
			test.AssertNoErr(t, err)

			_, err = compileFuncCall(expr)
			test.AssertHaveErr(t, err)
			test.AssertErrorPrefix(t, err, "str() second argument must be a number")
		})

		t.Run("str(skb->cb, 0xFFULL)", func(t *testing.T) {
			expr, err := cc.ParseExpr("str(skb->cb, 0xFFULL)")
			test.AssertNoErr(t, err)

			_, err = compileFuncCall(expr)
			test.AssertHaveErr(t, err)
			test.AssertErrorPrefix(t, err, "str() second argument must be a number")
		})

		t.Run("str(skb->cb, 0)", func(t *testing.T) {
			expr, err := cc.ParseExpr("str(skb->cb, 0)")
			test.AssertNoErr(t, err)

			_, err = compileFuncCall(expr)
			test.AssertHaveErr(t, err)
			test.AssertErrorPrefix(t, err, "str() size must be greater than 0")
		})
	})

	t.Run("pkt", func(t *testing.T) {
		t.Run("2 args", func(t *testing.T) {
			t.Run("pkt(skb->head, 0xFFULL)", func(t *testing.T) {
				expr, err := cc.ParseExpr("pkt(skb->head, 0xFFULL)")
				test.AssertNoErr(t, err)

				_, err = compileFuncCall(expr)
				test.AssertHaveErr(t, err)
				test.AssertErrorPrefix(t, err, "pkt() second argument must be a number")
			})

			t.Run("pkt(skb->head, 14)", func(t *testing.T) {
				expr, err := cc.ParseExpr("pkt(skb->head, 14)")
				test.AssertNoErr(t, err)

				val, err := compileFuncCall(expr)
				test.AssertNoErr(t, err)
				test.AssertEqual(t, val.typ, EvalResultTypePkt)
				test.AssertEqual(t, val.pkt, PktTypeEth)
			})
		})

		t.Run("3 args", func(t *testing.T) {
			t.Run("pkt(skb->head, ip4, 0xFFULL)", func(t *testing.T) {
				expr, err := cc.ParseExpr("pkt(skb->head, ip4, 0xFFULL)")
				test.AssertNoErr(t, err)

				_, err = compileFuncCall(expr)
				test.AssertHaveErr(t, err)
				test.AssertErrorPrefix(t, err, "pkt() second argument must be a number")
			})

			t.Run("pkt(skb->head, 14, xxx)", func(t *testing.T) {
				expr, err := cc.ParseExpr("pkt(skb->head, 14, xxx)")
				test.AssertNoErr(t, err)

				_, err = compileFuncCall(expr)
				test.AssertHaveErr(t, err)
				test.AssertErrorPrefix(t, err, "pkt() third argument as pkt type must be one of")
			})

			t.Run("pkt(skb->head, 14, ip4)", func(t *testing.T) {
				expr, err := cc.ParseExpr("pkt(skb->head, 14, ip4)")
				test.AssertNoErr(t, err)

				val, err := compileFuncCall(expr)
				test.AssertNoErr(t, err)
				test.AssertEqual(t, val.typ, EvalResultTypePkt)
				test.AssertEqual(t, val.pkt, PktTypeIP4)
			})

			t.Run("pkt(skb->head, 14, 0xFFULL)", func(t *testing.T) {
				expr, err := cc.ParseExpr("pkt(skb->head, 14, 0xFFULL)")
				test.AssertNoErr(t, err)

				_, err = compileFuncCall(expr)
				test.AssertHaveErr(t, err)
				test.AssertErrorPrefix(t, err, "pkt() third argument must be a number")
			})

			t.Run("pkt(skb->head, 14, 20)", func(t *testing.T) {
				expr, err := cc.ParseExpr("pkt(skb->head, 14, 20)")
				test.AssertNoErr(t, err)

				val, err := compileFuncCall(expr)
				test.AssertNoErr(t, err)
				test.AssertEqual(t, val.typ, EvalResultTypePkt)
				test.AssertEqual(t, val.pkt, PktTypeEth)
			})

			t.Run("pkt(skb->head, 14, a+b)", func(t *testing.T) {
				expr, err := cc.ParseExpr("pkt(skb->head, 14, a+b)")
				test.AssertNoErr(t, err)

				_, err = compileFuncCall(expr)
				test.AssertHaveErr(t, err)
				test.AssertErrorPrefix(t, err, "pkt() third argument must be pkt type or a number")
			})
		})

		t.Run("4 args", func(t *testing.T) {
			t.Run("pkt(skb->head, xx, 20, ip4)", func(t *testing.T) {
				expr, err := cc.ParseExpr("pkt(skb->head, xx, 20, ip4)")
				test.AssertNoErr(t, err)

				_, err = compileFuncCall(expr)
				test.AssertHaveErr(t, err)
				test.AssertErrorPrefix(t, err, "pkt() second argument must be a number")
			})

			t.Run("pkt(skb->head, 14, xx, ip4)", func(t *testing.T) {
				expr, err := cc.ParseExpr("pkt(skb->head, 14, xx, ip4)")
				test.AssertNoErr(t, err)

				_, err = compileFuncCall(expr)
				test.AssertHaveErr(t, err)
				test.AssertErrorPrefix(t, err, "pkt() third argument must be a number")
			})

			t.Run("pkt(skb->head, 14, 20, 40)", func(t *testing.T) {
				expr, err := cc.ParseExpr("pkt(skb->head, 14, 20, 40)")
				test.AssertNoErr(t, err)

				_, err = compileFuncCall(expr)
				test.AssertHaveErr(t, err)
				test.AssertErrorPrefix(t, err, "pkt() fourth argument must be pkt type")
			})

			t.Run("pkt(skb->head, 14, 20, ipxxx)", func(t *testing.T) {
				expr, err := cc.ParseExpr("pkt(skb->head, 14, 20, ipxxx)")
				test.AssertNoErr(t, err)

				_, err = compileFuncCall(expr)
				test.AssertHaveErr(t, err)
				test.AssertErrorPrefix(t, err, "pkt() fourth argument as pkt type must be one of")
			})

			t.Run("pkt(skb->head, 14, 20, ip4)", func(t *testing.T) {
				expr, err := cc.ParseExpr("pkt(skb->head, 14, 20, ip4)")
				test.AssertNoErr(t, err)

				val, err := compileFuncCall(expr)
				test.AssertNoErr(t, err)
				test.AssertEqual(t, val.typ, EvalResultTypePkt)
				test.AssertEqual(t, val.pkt, PktTypeIP4)
			})
		})

		t.Run("invalid args", func(t *testing.T) {
			t.Run("pkt(skb->head, 14, 20, ip4, 0)", func(t *testing.T) {
				expr, err := cc.ParseExpr("pkt(skb->head, 14, 20, ip4, 0)")
				test.AssertNoErr(t, err)

				_, err = compileFuncCall(expr)
				test.AssertHaveErr(t, err)
				test.AssertErrorPrefix(t, err, "pkt() must have 2, 3 or 4 arguments")
			})
		})

		t.Run("invalid dataSize", func(t *testing.T) {
			t.Run("pkt(skb->head, 0, ip4)", func(t *testing.T) {
				expr, err := cc.ParseExpr("pkt(skb->head, 0, ip4)")
				test.AssertNoErr(t, err)

				_, err = compileFuncCall(expr)
				test.AssertHaveErr(t, err)
				test.AssertErrorPrefix(t, err, "pkt() size must be greater than 0")
			})
		})
	})

	t.Run("addr", func(t *testing.T) {
		t.Run("eth(skb->data, 0xFFULL)", func(t *testing.T) {
			expr, err := cc.ParseExpr("eth(skb->data, 0xFFULL)")
			test.AssertNoErr(t, err)

			_, err = compileFuncCall(expr)
			test.AssertHaveErr(t, err)
			test.AssertErrorPrefix(t, err, "eth() second argument must be a number")
		})

		t.Run("eth(skb->data, 14, 20)", func(t *testing.T) {
			expr, err := cc.ParseExpr("eth(skb->data, 14, 20)")
			test.AssertNoErr(t, err)

			_, err = compileFuncCall(expr)
			test.AssertHaveErr(t, err)
			test.AssertErrorPrefix(t, err, "eth() must have 1 or 2 arguments")
		})

		t.Run("eth(skb->data)", func(t *testing.T) {
			expr, err := cc.ParseExpr("eth(skb->data)")
			test.AssertNoErr(t, err)

			val, err := compileFuncCall(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, val.typ, EvalResultTypeAddr)
			test.AssertEqual(t, val.addr, AddrTypeEth)
			test.AssertEqual(t, val.dataSize, EthAddrSize)
		})

		t.Run("eth2(skb->data)", func(t *testing.T) {
			expr, err := cc.ParseExpr("eth2(skb->data)")
			test.AssertNoErr(t, err)

			val, err := compileFuncCall(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, val.typ, EvalResultTypeAddr)
			test.AssertEqual(t, val.addr, AddrTypeEth2)
			test.AssertEqual(t, val.dataSize, EthAddrSize*2)
		})

		t.Run("ip4(skb->data)", func(t *testing.T) {
			expr, err := cc.ParseExpr("ip4(skb->data)")
			test.AssertNoErr(t, err)

			val, err := compileFuncCall(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, val.typ, EvalResultTypeAddr)
			test.AssertEqual(t, val.addr, AddrTypeIP4)
			test.AssertEqual(t, val.dataSize, IP4AddrSize)
		})

		t.Run("ip42(skb->data)", func(t *testing.T) {
			expr, err := cc.ParseExpr("ip42(skb->data)")
			test.AssertNoErr(t, err)

			val, err := compileFuncCall(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, val.typ, EvalResultTypeAddr)
			test.AssertEqual(t, val.addr, AddrTypeIP42)
			test.AssertEqual(t, val.dataSize, IP4AddrSize*2)
		})

		t.Run("ip6(skb->data)", func(t *testing.T) {
			expr, err := cc.ParseExpr("ip6(skb->data)")
			test.AssertNoErr(t, err)

			val, err := compileFuncCall(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, val.typ, EvalResultTypeAddr)
			test.AssertEqual(t, val.addr, AddrTypeIP6)
			test.AssertEqual(t, val.dataSize, IP6AddrSize)
		})

		t.Run("ip62(skb->data)", func(t *testing.T) {
			expr, err := cc.ParseExpr("ip62(skb->data)")
			test.AssertNoErr(t, err)

			val, err := compileFuncCall(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, val.typ, EvalResultTypeAddr)
			test.AssertEqual(t, val.addr, AddrTypeIP62)
			test.AssertEqual(t, val.dataSize, IP6AddrSize*2)
		})
	})

	t.Run("port", func(t *testing.T) {
		t.Run("port(skb->data + 14 + 20)", func(t *testing.T) {
			expr, err := cc.ParseExpr("port(skb->data + 14 + 20)")
			test.AssertNoErr(t, err)

			val, err := compileFuncCall(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, val.typ, EvalResultTypePort)
			test.AssertEqual(t, val.port, Port)
			test.AssertEqual(t, val.dataSize, PortSize)
		})

		t.Run("port2(skb->data + 14 + 20)", func(t *testing.T) {
			expr, err := cc.ParseExpr("port2(skb->data + 14 + 20)")
			test.AssertNoErr(t, err)

			val, err := compileFuncCall(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, val.typ, EvalResultTypePort)
			test.AssertEqual(t, val.port, Port2)
			test.AssertEqual(t, val.dataSize, PortSize*2)
		})
	})

	t.Run("slice", func(t *testing.T) {
		t.Run("slice(skb->cb, 4, 4)", func(t *testing.T) {
			expr, err := cc.ParseExpr("slice(skb->cb, 4, 4)")
			test.AssertNoErr(t, err)

			val, err := compileFuncCall(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, val.typ, EvalResultTypeSlice)
			test.AssertEqual(t, val.dataSize, int64(4))
			test.AssertEqual(t, val.dataOffset, int64(4))
		})
	})

	t.Run("hex", func(t *testing.T) {
		t.Run("hex(skb->cb, 14)", func(t *testing.T) {
			expr, err := cc.ParseExpr("hex(skb->cb, 14)")
			test.AssertNoErr(t, err)

			val, err := compileFuncCall(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, val.typ, EvalResultTypeHex)
			test.AssertEqual(t, val.dataSize, 14)
			test.AssertEqual(t, val.dataOffset, 0)
		})
	})

	t.Run("int", func(t *testing.T) {
		t.Run("u8(skb->cb, 0xFFULL)", func(t *testing.T) {
			expr, err := cc.ParseExpr("u8(skb->cb, 0xFFULL)")
			test.AssertNoErr(t, err)

			_, err = compileFuncCall(expr)
			test.AssertHaveErr(t, err)
			test.AssertErrorPrefix(t, err, "u8() second argument must be a number")
		})

		t.Run("u8(skb->cb, 4, 4)", func(t *testing.T) {
			expr, err := cc.ParseExpr("u8(skb->cb, 4, 4)")
			test.AssertNoErr(t, err)

			_, err = compileFuncCall(expr)
			test.AssertHaveErr(t, err)
			test.AssertErrorPrefix(t, err, "u8() must have 1 or 2 arguments")
		})

		t.Run("u8(skb->cb)", func(t *testing.T) {
			expr, err := cc.ParseExpr("u8(skb->cb)")
			test.AssertNoErr(t, err)

			val, err := compileFuncCall(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, val.typ, EvalResultTypeInt)
			test.AssertEqual(t, val.dataSize, 1)
		})

		t.Run("u16(skb->cb)", func(t *testing.T) {
			expr, err := cc.ParseExpr("u16(skb->cb)")
			test.AssertNoErr(t, err)

			val, err := compileFuncCall(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, val.typ, EvalResultTypeInt)
			test.AssertEqual(t, val.dataSize, 2)
		})

		t.Run("u32(skb->cb)", func(t *testing.T) {
			expr, err := cc.ParseExpr("u32(skb->cb)")
			test.AssertNoErr(t, err)

			val, err := compileFuncCall(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, val.typ, EvalResultTypeInt)
			test.AssertEqual(t, val.dataSize, 4)
		})

		t.Run("u64(skb->cb)", func(t *testing.T) {
			expr, err := cc.ParseExpr("u64(skb->cb)")
			test.AssertNoErr(t, err)

			val, err := compileFuncCall(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, val.typ, EvalResultTypeInt)
			test.AssertEqual(t, val.dataSize, 8)
		})
	})

	t.Run("unsupported func call", func(t *testing.T) {
		expr, err := cc.ParseExpr("unsupported(skb->cb)")
		test.AssertNoErr(t, err)

		_, err = compileFuncCall(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "unknown function call: unsupported")
	})
}

func TestPostCheckFuncCall(t *testing.T) {
	t.Run("disallow member bitfield", func(t *testing.T) {
		res := &EvalResult{
			Type: EvalResultTypeDeref,
		}
		val := evalValue{
			mem: &btf.Member{Offset: 0, BitfieldSize: 1},
		}

		err := postCheckFuncCall(res, val, 0, 0, "deref")
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "disallow member bitfield for deref()")
	})

	t.Run("deref", func(t *testing.T) {
		t.Run("invalid btf type", func(t *testing.T) {
			res := &EvalResult{
				Type: EvalResultTypeDeref,
			}
			val := evalValue{
				btf: &btf.Void{},
			}

			err := postCheckFuncCall(res, val, 0, 0, "deref")
			test.AssertHaveErr(t, err)
			test.AssertErrorPrefix(t, err, "disallow non-pointer type Void for pointer dereference")
		})

		t.Run("invalid ptr target btf type", func(t *testing.T) {
			res := &EvalResult{
				Type: EvalResultTypeDeref,
			}
			val := evalValue{
				btf: &btf.Pointer{
					Target: &btf.Void{},
				},
			}

			err := postCheckFuncCall(res, val, 0, 0, "deref")
			test.AssertHaveErr(t, err)
			test.AssertErrorPrefix(t, err, "disallow zero size type Void for pointer dereference")
		})

		t.Run("valid btf type", func(t *testing.T) {
			res := &EvalResult{
				Type: EvalResultTypeDeref,
			}
			typ, _ := testBtf.AnyTypeByName("unsigned int")
			val := evalValue{
				btf: &btf.Pointer{
					Target: typ,
				},
			}

			err := postCheckFuncCall(res, val, 0, 0, "deref")
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.Btf, val.btf.(*btf.Pointer).Target)
			test.AssertEqual(t, res.Size, int(4)) // int size
		})
	})

	t.Run("buf", func(t *testing.T) {
		t.Run("invalid btf type", func(t *testing.T) {
			res := &EvalResult{
				Type: EvalResultTypeBuf,
			}
			val := evalValue{
				btf: &btf.Void{},
			}

			err := postCheckFuncCall(res, val, 0, 0, "buf")
			test.AssertHaveErr(t, err)
			test.AssertErrorPrefix(t, err, "disallow non-{pointer,array} type Void for buf()")
		})

		t.Run("valid btf type", func(t *testing.T) {
			res := &EvalResult{
				Type: EvalResultTypeBuf,
			}
			typ, _ := testBtf.AnyTypeByName("unsigned char")
			val := evalValue{
				btf: &btf.Pointer{
					Target: typ,
				},
			}

			err := postCheckFuncCall(res, val, 0, 8, "buf")
			test.AssertNoErr(t, err)
			test.AssertEqualBtf(t, res.Btf, val.btf)
			test.AssertEqual(t, res.Size, int(8))
		})
	})

	t.Run("str", func(t *testing.T) {
		t.Run("invalid btf type", func(t *testing.T) {
			res := &EvalResult{
				Type: EvalResultTypeString,
			}
			val := evalValue{
				btf: &btf.Void{},
			}

			err := postCheckFuncCall(res, val, 0, 0, "str")
			test.AssertHaveErr(t, err)
			test.AssertErrorPrefix(t, err, "disallow non-{pointer,array} type Void for str()")
		})

		t.Run("ptr", func(t *testing.T) {
			res := &EvalResult{
				Type: EvalResultTypeString,
			}
			typ, _ := testBtf.AnyTypeByName("unsigned char")
			val := evalValue{
				btf: &btf.Pointer{
					Target: typ,
				},
			}

			err := postCheckFuncCall(res, val, 0, -1, "str")
			test.AssertNoErr(t, err)
			test.AssertEqualBtf(t, res.Btf, val.btf)
			test.AssertEqual(t, res.Size, int(64))
		})

		t.Run("invalid array type", func(t *testing.T) {
			res := &EvalResult{
				Type: EvalResultTypeString,
			}
			val := evalValue{
				btf: &btf.Array{
					Type:   &btf.Void{},
					Nelems: 8,
				},
			}

			err := postCheckFuncCall(res, val, 0, -1, "str")
			test.AssertHaveErr(t, err)
			test.AssertErrorPrefix(t, err, "disallow non-1-byte-size type Void for str()")
		})

		t.Run("arr", func(t *testing.T) {
			res := &EvalResult{
				Type: EvalResultTypeString,
			}
			val := evalValue{
				btf: &btf.Array{
					Type:   getU8Btf(t),
					Nelems: 8,
				},
			}

			err := postCheckFuncCall(res, val, 0, -1, "str")
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.Btf, val.btf)
			test.AssertEqual(t, res.Size, int(8))
		})
	})

	t.Run("pkt,...", func(t *testing.T) {
		t.Run("invalid btf type", func(t *testing.T) {
			res := &EvalResult{
				Type: EvalResultTypePkt,
			}
			val := evalValue{
				btf: &btf.Void{},
			}

			err := postCheckFuncCall(res, val, 0, 0, "pkt")
			test.AssertHaveErr(t, err)
			test.AssertErrorPrefix(t, err, "disallow non-pointer type Void for pkt()")
		})

		t.Run("valid btf type", func(t *testing.T) {
			res := &EvalResult{
				Type: EvalResultTypePkt,
			}
			typ, _ := testBtf.AnyTypeByName("unsigned char")
			val := evalValue{
				btf: &btf.Pointer{
					Target: typ,
				},
			}

			err := postCheckFuncCall(res, val, 0, 64, "pkt")
			test.AssertNoErr(t, err)
			test.AssertEqualBtf(t, res.Btf, val.btf)
			test.AssertEqual(t, res.Size, int(64))
		})
	})

	t.Run("slice", func(t *testing.T) {
		t.Run("invalid btf type", func(t *testing.T) {
			res := &EvalResult{
				Type: EvalResultTypeSlice,
			}
			val := evalValue{
				btf: &btf.Void{},
			}

			err := postCheckFuncCall(res, val, 0, 0, "slice")
			test.AssertHaveErr(t, err)
			test.AssertErrorPrefix(t, err, "disallow non-{pointer,array} type Void for slice()")
		})

		t.Run("zero size", func(t *testing.T) {
			res := &EvalResult{
				Type: EvalResultTypeSlice,
			}
			val := evalValue{
				btf: &btf.Pointer{
					Target: &btf.Void{},
				},
			}

			err := postCheckFuncCall(res, val, 0, 0, "slice")
			test.AssertHaveErr(t, err)
			test.AssertErrorPrefix(t, err, "disallow zero size type Void for slice()")
		})

		t.Run("ptr", func(t *testing.T) {
			res := &EvalResult{
				Type: EvalResultTypeSlice,
			}
			typ, _ := testBtf.AnyTypeByName("unsigned int")
			val := evalValue{
				btf: &btf.Pointer{
					Target: typ,
				},
			}

			err := postCheckFuncCall(res, val, 0, 8, "slice")
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.Btf, val.btf.(*btf.Pointer).Target)
			test.AssertEqual(t, res.Size, int(8*4))
		})

		t.Run("arr", func(t *testing.T) {
			res := &EvalResult{
				Type: EvalResultTypeSlice,
			}
			val := evalValue{
				btf: &btf.Array{
					Type:   getU32Btf(t),
					Nelems: 8,
				},
			}

			err := postCheckFuncCall(res, val, 0, 8, "slice")
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.Btf, val.btf.(*btf.Array).Type)
			test.AssertEqual(t, res.Size, int(8*4))
		})
	})

	t.Run("int", func(t *testing.T) {
		t.Run("invalid btf type", func(t *testing.T) {
			res := &EvalResult{
				Type: EvalResultTypeInt,
			}
			val := evalValue{
				btf: &btf.Void{},
			}

			err := postCheckFuncCall(res, val, 0, 0, "u8")
			test.AssertHaveErr(t, err)
			test.AssertErrorPrefix(t, err, "disallow non-{pointer,array} type Void for u8()")
		})

		t.Run("u8", func(t *testing.T) {
			res := &EvalResult{
				Type: EvalResultTypeInt,
			}
			typ, _ := testBtf.AnyTypeByName("unsigned char")
			val := evalValue{
				btf: &btf.Pointer{
					Target: typ,
				},
			}

			err := postCheckFuncCall(res, val, 0, 1, "u8")
			test.AssertNoErr(t, err)
			test.AssertEqualBtf(t, res.Btf, val.btf)
			test.AssertEqual(t, res.Size, int(1))
			test.AssertEqual(t, res.Int, "u8")
		})
	})

	t.Run("default", func(t *testing.T) {
		res := &EvalResult{
			Type: EvalResultTypeDefault,
		}
		val := evalValue{
			btf: &btf.Void{},
		}

		err := postCheckFuncCall(res, val, 0, 0, "default")
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.Btf, val.btf)
		test.AssertEqual(t, res.Size, int(0))
	})
}
