// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"slices"
	"testing"

	"github.com/Asphaltt/mybtf"
	"github.com/bpfsnoop/bpfsnoop/internal/test"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"rsc.io/c2go/cc"
)

func genInsnsWithN(reg asm.Register, pfx asm.Instructions, sfx asm.Instructions) asm.Instructions {
	return slices.Concat(pfx, asm.Instructions{
		asm.LoadMem(reg, argsReg, 40, dword),
		asm.LSh.Imm(reg, 32),
		asm.RSh.Imm(reg, 32),
	}, sfx)
}

func TestEvaluate(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("paren", func(t *testing.T) {
		defer c.reset()

		expr := prepareCcExpr(t, "(10)")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isConstant())
		test.AssertEqual(t, val.num, 10)
	})

	t.Run("plus", func(t *testing.T) {
		defer c.reset()

		expr := prepareCcExpr(t, "+10")

		v, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, v.num, int64(10))
	})

	t.Run("unsupported op", func(t *testing.T) {
		// Create an expression with unsupported operator
		expr := &cc.Expr{
			Op: cc.Comma, // Comma operator is not supported
		}

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertStrContains(t, err.Error(), "unsupported expression operator")
	})
}

func TestEvaluateName(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("special constants", func(t *testing.T) {
		defer c.reset()
		for name, want := range map[string]int64{"NULL": 0, "false": 0, "true": 1} {
			expr := &cc.Expr{Op: cc.Name, Text: name}
			v, err := c.evaluate(expr)
			test.AssertNoErr(t, err)
			test.AssertTrue(t, v.isConstant())
			test.AssertEqual(t, v.num, want)
		}
	})

	t.Run("valid variable", func(t *testing.T) {
		defer c.reset()
		expr := &cc.Expr{
			Op:   cc.Name,
			Text: "skb",
		}

		v, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, v.isPending())
		test.AssertEqual(t, v.varIndex, 0) // skb is at index 0
	})

	t.Run("maybe enum", func(t *testing.T) {
		defer c.reset()
		expr := &cc.Expr{
			Op:   cc.Name,
			Text: "MAYBE_ENUM_VALUE",
		}

		v, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, v.isEnumMaybe())
		test.AssertEqual(t, v.name, "MAYBE_ENUM_VALUE")
	})
}

func TestEvaluateNumber(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("parse number err", func(t *testing.T) {
		defer c.reset()

		expr := &cc.Expr{
			Text: "not_a_number",
			Op:   cc.Number,
		}

		_, err := c.evaluateNumber(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "failed to parse number")
	})

	t.Run("valid number", func(t *testing.T) {
		defer c.reset()

		expr := &cc.Expr{
			Op:   cc.Number,
			Text: "42",
		}

		v, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, v.isConstant())
		test.AssertEqual(t, v.num, int64(42))
	})
}

func TestEvaluateArrow(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("invalid left operand", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("skb->devx->ifindex")
		test.AssertNoErr(t, err)

		_, err = c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("var not found", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("not_found->len")
		test.AssertNoErr(t, err)

		_, err = c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertIsErr(t, err, ErrVarNotFound)
	})

	t.Run("valid arrow dereference", func(t *testing.T) {
		defer c.reset()

		// skb->len
		expr, err := cc.ParseExpr("skb->len")
		test.AssertNoErr(t, err)

		v, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, v.isPending())
		test.AssertEqual(t, len(v.offsets), 1)
		test.AssertTrue(t, v.offsets[0].deref)
	})
}

func TestEvaluateDot(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("invalid left operand", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("skb.len.ifindex")
		test.AssertNoErr(t, err)

		_, err = c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("var not found", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("not_found.len")
		test.AssertNoErr(t, err)

		_, err = c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertIsErr(t, err, ErrVarNotFound)
	})

	t.Run("valid dot access", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("skb->users.refs.counter")
		test.AssertNoErr(t, err)

		v, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, v.isPending())
	})
}

func TestAccessMember(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("bitfield member", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("skb->pkt_type->xxx")
		test.AssertNoErr(t, err)

		_, err = c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "cannot access member of a bitfield type")
	})

	t.Run("arrow access from non-ptr", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("skb->len->xxx")
		test.AssertNoErr(t, err)

		_, err = c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "arrow access requires pointer type")
	})

	t.Run("access struct pointer", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("skb->head")
		test.AssertNoErr(t, err)

		v, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, v.isPending())
	})

	t.Run("access union pointer", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("attr->batch.flags")
		test.AssertNoErr(t, err)

		v, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, v.isPending())
	})

	t.Run("access non-struct/union", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("skb->head->xxx")
		test.AssertNoErr(t, err)

		_, err = c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "cannot access member of type")
	})

	t.Run("member not found", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("skb->not_found")
		test.AssertNoErr(t, err)

		_, err = c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "failed to find member")
	})

	t.Run("kind pending", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("skb->len")
		test.AssertNoErr(t, err)

		v, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, v.isPending())
	})

	t.Run("kind materialized", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("((struct tcphdr *) (skb->head + skb->transport_header))->dest")
		test.AssertNoErr(t, err)

		v, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, v.isPending())
	})

	t.Run("kind enum maybe", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("skb")
		test.AssertNoErr(t, err)

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)

		val.kind = exprValueKindEnumMaybe // Force to EnumMaybe
		_, err = c.accessMember(val, "len", true)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "cannot access member on EnumMaybe value")
	})
}

func TestAccessMemberPending(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("dot access offsets", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("skb->users.refs.counter")
		test.AssertNoErr(t, err)

		v, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, v.isPending())
	})

	t.Run("dot access base variable", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("uattr.is_kernel")
		test.AssertNoErr(t, err)

		_, err = c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "disallow accessing member via dot on base variable")
	})

	t.Run("arrow access offsets", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("skb->dev->ifindex")
		test.AssertNoErr(t, err)

		v, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, v.isPending())
	})

	t.Run("access array", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("skb->cb[0]")
		test.AssertNoErr(t, err)

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isPending())
	})
}

func TestAccessMemberMaterialized(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("dot access", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("skb")
		test.AssertNoErr(t, err)

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)

		_, err = c.accessMemberMaterialized(val, nil, 0, false)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "disallow dot access on materialized value")
	})

	t.Run("access array", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("(skb + n)->cb[0]")
		test.AssertNoErr(t, err)

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isPending())
	})

	t.Run("access", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("skb->len")
		test.AssertNoErr(t, err)

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isPending())
	})
}

func TestEvaluateIndex(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("invalid left operand", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("not_found->xxx[5]")
		test.AssertNoErr(t, err)

		_, err = c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "failed to evaluate index base")
	})

	t.Run("bitfield", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("skb->pkt_type[3]")
		test.AssertNoErr(t, err)

		_, err = c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "disallow using bitfield for index")
	})

	t.Run("invalid right operand", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("skb->cb[not_found]")
		test.AssertNoErr(t, err)

		_, err = c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "index must be a constant number")
	})

	t.Run("invalid number", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("skb->cb[1ULL]")
		test.AssertNoErr(t, err)

		_, err = c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "failed to parse index")
	})

	t.Run("pointer index", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("skb->dev[2]")
		test.AssertNoErr(t, err)

		v, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, v.isPending())
	})

	t.Run("array index", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("skb->cb[2]")
		test.AssertNoErr(t, err)

		v, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, v.isPending())
	})

	t.Run("invalid base type", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("skb->users[2]")
		test.AssertNoErr(t, err)

		_, err = c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "cannot index type")
	})

	t.Run("zero elem size", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("ops->arr[0]")
		test.AssertNoErr(t, err)

		_, err = c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "cannot index element of zero size")
	})

	t.Run("kind pending", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("skb->cb[2]")
		test.AssertNoErr(t, err)

		v, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, v.isPending())
	})

	t.Run("kind materialized", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("((struct tcphdr *) (skb->head + skb->transport_header))[1]")
		test.AssertNoErr(t, err)

		v, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, v.isPending())
	})

	t.Run("kind enum maybe", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("((int *) UNK)[1]")
		test.AssertNoErr(t, err)

		_, err = c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "cannot index EnumMaybe value")
	})
}

func TestEvaluateIndir(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("invalid left operand", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("*(skb->xxx)")
		test.AssertNoErr(t, err)

		_, err = c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("bitfield", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("*(skb->pkt_type)")
		test.AssertNoErr(t, err)

		_, err = c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "cannot dereference bitfield")
	})

	t.Run("invalid base type", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("*(skb->len)")
		test.AssertNoErr(t, err)

		_, err = c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "cannot dereference non-pointer type")
	})

	t.Run("kind pending", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("*(skb->dev)")
		test.AssertNoErr(t, err)

		v, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, v.isPending())
	})

	t.Run("kind materialized", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("*((struct tcphdr *) (skb->head + skb->transport_header))")
		test.AssertNoErr(t, err)

		v, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, v.isPending())
	})

	t.Run("kind enum maybe", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("*((int *) UNK)")
		test.AssertNoErr(t, err)

		_, err = c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "cannot dereference EnumMaybe value")
	})
}

func TestEvaluateAddr(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("invalid left operand", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("&(skb + 0x42ULL)")
		test.AssertNoErr(t, err)

		_, err = c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("not pending", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("&10")
		test.AssertNoErr(t, err)

		_, err = c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "cannot take address of Constant value")
	})

	t.Run("no offsets", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("&skb")
		test.AssertNoErr(t, err)

		_, err = c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "cannot take address of variable directly")
	})

	t.Run("with offsets", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("&(skb->len)")
		test.AssertNoErr(t, err)

		v, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, v.isPending())
	})
}

func TestEvaluateCast(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("parse number", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("(int *) 42ULL")
		test.AssertNoErr(t, err)

		_, err = c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "failed to parse number for cast")
	})

	t.Run("invalid btf", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("(struct not_found *) 0x42")
		test.AssertNoErr(t, err)

		_, err = c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "failed to get cast target type")
	})

	t.Run("cast number", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("(int *) 0x1234")
		test.AssertNoErr(t, err)

		v, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, v.isPending())
		test.AssertEqual(t, v.uptr, uint64(0x1234))
	})

	t.Run("invalid left operand", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("(int *) (skb + 0x42ULL)")
		test.AssertNoErr(t, err)

		_, err = c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("invalid cast btf type", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("(struct unk *) skb")
		test.AssertNoErr(t, err)

		_, err = c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "failed to get cast target type")
	})

	t.Run("valid cast", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("(struct tcphdr *) skb->head")
		test.AssertNoErr(t, err)

		v, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, v.isPending())
	})
}

func TestEvaluateAdd(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("invalid left operand", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("skb->xx + 5")
		test.AssertNoErr(t, err)

		_, err = c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "failed to evaluate left operand of add")
	})

	t.Run("invalid right operand", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("5 + skb->xx")
		test.AssertNoErr(t, err)

		_, err = c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "failed to evaluate right operand of add")
	})

	t.Run("constant + constant", func(t *testing.T) {
		defer c.reset()
		// 10 + 5
		expr, err := cc.ParseExpr("10 + 5")
		test.AssertNoErr(t, err)

		v, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, v.isConstant())
		test.AssertEqual(t, v.num, int64(15))
	})

	t.Run("pending + constant", func(t *testing.T) {
		defer c.reset()
		// skb->len + 5
		expr, err := cc.ParseExpr("skb->len + 5")
		test.AssertNoErr(t, err)

		v, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		// This should still be pending as we add offset
		test.AssertTrue(t, v.isPending() || v.isMaterialized())
	})
}

func TestAddValues(t *testing.T) {
	c := prepareCompilerDirectRead(t)

	t.Run("resolve enums", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		left := prepareExprVal(t, c, "skb")
		right := prepareExprVal(t, c, "UNK")

		_, err := c.addValues(left, right)
		test.AssertHaveErr(t, err)
	})

	t.Run("const + const", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		l := prepareExprVal(t, c, "12")
		r := prepareExprVal(t, c, "34")

		v, err := c.addValues(l, r)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, v.isConstant())
		test.AssertEqual(t, v.num, 46)
	})

	t.Run("invalid left operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		l := prepareExprVal(t, c, "skb->users")
		r := prepareExprVal(t, c, "n")

		_, err := c.addValues(l, r)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "left operand cannot be used for add")
	})

	t.Run("invalid right operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		l := prepareExprVal(t, c, "n")
		r := prepareExprVal(t, c, "skb->users")

		_, err := c.addValues(l, r)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "right operand cannot be used for add")
	})

	t.Run("pending + const", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		l := prepareExprVal(t, c, "skb")
		r := prepareExprVal(t, c, "0x42")

		v, err := c.addValues(l, r)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, v.isPending())
	})

	t.Run("const + pending", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		l := prepareExprVal(t, c, "0x42")
		r := prepareExprVal(t, c, "skb")

		v, err := c.addValues(l, r)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, v.isPending())
	})

	t.Run("invalid left operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		l := prepareExprVal(t, c, "unk")
		r := prepareExprVal(t, c, "skb")

		l.kind = 0xFF
		_, err := c.addValues(l, r)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "failed to materialize left operand")
	})

	t.Run("invalid right operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		l := prepareExprVal(t, c, "skb")
		r := prepareExprVal(t, c, "unk")

		r.kind = 0xFF
		_, err := c.addValues(l, r)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "failed to materialize right operand")
	})

	t.Run("ptr + pending", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		l := prepareExprVal(t, c, "skb->dev")
		r := prepareExprVal(t, c, "n")

		v, err := c.addValues(l, r)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, v.isMaterialized())
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.LoadMem(r8, argsReg, 0, dword),
			asm.LoadMem(r8, r8, 16, dword),
			asm.LoadMem(r7, argsReg, 40, dword),
			asm.LSh.Imm(r7, 32),
			asm.RSh.Imm(r7, 32),
			asm.Mul.Imm(r7, 2512),
			asm.Add.Reg(r8, r7),
		})
	})

	t.Run("arr + pending", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		l := prepareExprVal(t, c, "prog->insns")
		r := prepareExprVal(t, c, "n")

		v, err := c.addValues(l, r)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, v.isMaterialized())
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.LoadMem(r8, argsReg, 8, dword),
			asm.Add.Imm(r8, 72),
			asm.LoadMem(r7, argsReg, 40, dword),
			asm.LSh.Imm(r7, 32),
			asm.RSh.Imm(r7, 32),
			asm.Mul.Imm(r7, 8),
			asm.Add.Reg(r8, r7),
		})
	})
}

func TestAddConstantToPending(t *testing.T) {
	c := prepareCompilerDirectRead(t)

	t.Run("zero num", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		val := prepareExprVal(t, c, "skb->len")

		val, err := c.addConstantToPending(val, 0)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isPending())
	})

	t.Run("void *", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		val := prepareExprVal(t, c, "prog->aux->jit_data")

		val, err := c.addConstantToPending(val, 42)
		test.AssertNoErr(t, err)
		test.AssertSliceLen(t, val.offsets, 3)
		test.AssertFalse(t, val.offsets[2].deref)
	})

	t.Run("func *", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		val := prepareExprVal(t, c, "prog->bpf_func")

		_, err := c.addConstantToPending(val, 42)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "cannot add to pointer of zero-size element")
	})

	t.Run("arr", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		val := prepareExprVal(t, c, "prog->aux->name")

		val, err := c.addConstantToPending(val, 42)
		test.AssertNoErr(t, err)
		test.AssertSliceLen(t, val.offsets, 3)
		test.AssertFalse(t, val.offsets[2].deref)
	})

	t.Run("arr func", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		val := prepareExprVal(t, c, "ops->arr")

		_, err := c.addConstantToPending(val, 42)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "cannot add to array of zero-size element")
	})

	t.Run("skb->len + 42", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		val := prepareExprVal(t, c, "skb->len")

		val, err := c.addConstantToPending(val, 42)
		test.AssertNoErr(t, err)
		test.AssertSliceLen(t, val.offsets, 2)
		test.AssertFalse(t, val.offsets[1].deref)
		test.AssertNil(t, val.mem)
	})
}

func TestEvaluateSub(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("invalid left operand", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("skb->xx - 42")
		test.AssertNoErr(t, err)

		_, err = c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "failed to evaluate left operand of sub")
	})

	t.Run("invalid right operand", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("42 - skb->xx")
		test.AssertNoErr(t, err)

		_, err = c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "failed to evaluate right operand of sub")
	})

	t.Run("pending - num", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("skb->len - 42")
		test.AssertNoErr(t, err)

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isPending())
	})
}

func TestSubValues(t *testing.T) {
	c := prepareCompilerDirectRead(t)

	t.Run("enums", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		l := prepareExprVal(t, c, "skb")
		r := prepareExprVal(t, c, "unk")

		_, err := c.subValues(l, r)
		test.AssertHaveErr(t, err)
	})

	t.Run("const + const", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr, err := cc.ParseExpr("42 - 31")
		test.AssertNoErr(t, err)

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isConstant())
		test.AssertEqual(t, val.num, 11)
	})

	t.Run("invalid left operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "skb->users - 42")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "left operand cannot be used for sub")
	})

	t.Run("invalid right operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "42 - skb->users")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "right operand cannot be used for sub")
	})

	t.Run("pending - const", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr, err := cc.ParseExpr("skb->len - 42")
		test.AssertNoErr(t, err)

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isPending())
		test.AssertSliceLen(t, val.offsets, 2)
		test.AssertEqual(t, val.offsets[1].offset, -42)
	})

	t.Run("invalid left operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		l := prepareExprVal(t, c, "(int *) (0x42)")
		r := prepareExprVal(t, c, "n")

		c.markRegisterAllUsed()

		_, err := c.subValues(l, r)
		test.AssertHaveErr(t, err)
	})

	t.Run("invalid right operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		l := prepareExprVal(t, c, "n")
		r := prepareExprVal(t, c, "(int *) (0x42)")

		r.kind = 0xFF

		_, err := c.subValues(l, r)
		test.AssertHaveErr(t, err)
	})

	t.Run("ptr - n", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "prog->aux - n")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isMaterialized())
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.LoadMem(r8, argsReg, 8, dword),
			asm.LoadMem(r8, r8, 56, dword),
			asm.LoadMem(r7, argsReg, 40, dword),
			asm.LSh.Imm(r7, 32),
			asm.RSh.Imm(r7, 32),
			asm.Mul.Imm(r7, 1072),
			asm.Sub.Reg(r8, r7),
		})
	})

	t.Run("arr - n", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "prog->insns - n")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isMaterialized())
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.LoadMem(r8, argsReg, 8, dword),
			asm.Add.Imm(r8, 72),
			asm.LoadMem(r7, argsReg, 40, dword),
			asm.LSh.Imm(r7, 32),
			asm.RSh.Imm(r7, 32),
			asm.Mul.Imm(r7, 8),
			asm.Sub.Reg(r8, r7),
		})
	})
}

func TestEvaluateMul(t *testing.T) {
	c := prepareCompilerDirectRead(t)

	t.Run("invalid left operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "0x42ULL * n")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("invalid right operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "n * 0x42ULL")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("resolve enums", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "n * unk")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("const * const", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "12 * 3")
		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isConstant())
	})

	t.Run("materialize left operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "12 * n")

		c.markRegisterAllUsed()

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("left operand is struct", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "skb->users * n")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "left operand cannot be used for multiply")
	})

	t.Run("materialize right operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)
		c.memMode = MemoryReadModeCoreRead

		expr := prepareCcExpr(t, "n * skb->len")

		spec := newSpec(t, testBtf)
		spec.typeID = spec.getTypeIDErr
		c.btfSpec = spec

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("right operand is struct", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "n * skb->users")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "right operand cannot be used for multiply")
	})

	t.Run("const * n", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "12 * n")
		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isMaterialized())
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Mov.Imm(r8, 12),
			asm.LoadMem(r7, argsReg, 40, dword),
			asm.LSh.Imm(r7, 32),
			asm.RSh.Imm(r7, 32),
			asm.Mul.Reg(r8, r7),
		})
	})
}

func TestEvaluateDiv(t *testing.T) {
	c := prepareCompilerDirectRead(t)

	t.Run("invalid left operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "0x42ULL / 42")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("invalid right operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "42 / 0x42ULL")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("resolve enums", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "n / unk")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("const / 0", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "42 / 0")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "division by zero")
	})

	t.Run("const / const", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "42 / 2")
		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isConstant())
		test.AssertEqual(t, val.num, 21)
	})

	t.Run("struct left operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "skb->users / 42")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "left operand cannot be used for div")
	})

	t.Run("struct right operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "42 / skb->users")

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "right operand cannot be used for div")
	})

	t.Run("materialize left operand failure", func(t *testing.T) {
		defer resetCompilerDirectRead(c)
		c.memMode = MemoryReadModeCoreRead

		expr := prepareCcExpr(t, "skb->len / 2")

		c.setBtfIDErr(t)

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("n / const", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "n / 2")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isMaterialized())
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.LoadMem(r8, argsReg, 40, dword),
			asm.LSh.Imm(r8, 32),
			asm.RSh.Imm(r8, 32),
			asm.Div.Imm(r8, 2),
		})
	})

	t.Run("materialize right operand failure", func(t *testing.T) {
		defer resetCompilerDirectRead(c)
		c.memMode = MemoryReadModeCoreRead

		expr := prepareCcExpr(t, "n / skb->len")

		c.setBtfIDErr(t)

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("skb->len / n", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "skb->len / n")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isMaterialized())
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.LoadMem(r8, argsReg, 0, dword),
			asm.LoadMem(r8, r8, 112, dword),
			asm.LSh.Imm(r8, 32),
			asm.RSh.Imm(r8, 32),
			asm.LoadMem(r7, argsReg, 40, dword),
			asm.LSh.Imm(r7, 32),
			asm.RSh.Imm(r7, 32),
			JmpOff(asm.JNE, r7, 0, 2),
			asm.Mov.Imm(r8, 0),
			Ja(1),
			asm.Div.Reg(r8, r7),
		})
	})
}

func TestEvaluateMod(t *testing.T) {
	c := prepareCompilerDirectRead(t)

	t.Run("invalid left operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "0x42ULL % 42")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("invalid right operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "42 % 0x42ULL")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("resolve enums", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "n % unk")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("const % 0", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "42 % 0")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "modulo by zero")
	})

	t.Run("const % const", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "42 % 2")
		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isConstant())
		test.AssertEqual(t, val.num, 0)
	})

	t.Run("struct left operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "skb->users % 42")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "left operand cannot be used for mod")
	})

	t.Run("struct right operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "42 % skb->users")

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "right operand cannot be used for mod")
	})

	t.Run("materialize left operand failure", func(t *testing.T) {
		defer resetCompilerDirectRead(c)
		c.memMode = MemoryReadModeCoreRead

		expr := prepareCcExpr(t, "skb->len % 2")

		c.setBtfIDErr(t)

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("n % const(1)", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "n % 1")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isMaterialized())
		test.AssertEqualSlice(t, c.insns, genInsnsWithN(r8, nil, asm.Instructions{
			asm.Mov.Imm(r8, 0),
		}))
	})

	t.Run("n % const(not 1)", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "n % 2")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isMaterialized())
		test.AssertEqualSlice(t, c.insns, genInsnsWithN(r8, nil, asm.Instructions{
			asm.Mod.Imm(r8, 2),
		}))
	})

	t.Run("materialize right operand failure", func(t *testing.T) {
		defer resetCompilerDirectRead(c)
		c.memMode = MemoryReadModeCoreRead

		expr := prepareCcExpr(t, "n % skb->len")

		c.setBtfIDErr(t)

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("skb->len % n", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "skb->len % n")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isMaterialized())
		test.AssertEqualSlice(t, c.insns, genInsnsWithN(
			r7,
			asm.Instructions{
				asm.LoadMem(r8, argsReg, 0, dword),
				asm.LoadMem(r8, r8, 112, dword),
				asm.LSh.Imm(r8, 32),
				asm.RSh.Imm(r8, 32),
			},
			asm.Instructions{
				JmpOff(asm.JNE, r7, 0, 2),
				asm.Mov.Imm(r8, 0),
				Ja(1),
				asm.Mod.Reg(r8, r7),
			},
		))
	})
}

func TestEvaluateAnd(t *testing.T) {
	c := prepareCompilerDirectRead(t)

	t.Run("invalid left operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "0x42ULL & 42")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("invalid right operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "42 & 0x42ULL")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("resolve enums", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "n & unk")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("const & const", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "42 & 2")
		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isConstant())
		test.AssertEqual(t, val.num, 2)
	})

	t.Run("struct left operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "skb->users & 42")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "left operand cannot be used for and")
	})

	t.Run("struct right operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "42 & skb->users")

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "right operand cannot be used for and")
	})

	t.Run("materialize left operand failure", func(t *testing.T) {
		defer resetCompilerDirectRead(c)
		c.memMode = MemoryReadModeCoreRead

		expr := prepareCcExpr(t, "skb->len & 2")

		c.setBtfIDErr(t)

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("n & const", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "n & 2")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isMaterialized())
		test.AssertEqualSlice(t, c.insns, genInsnsWithN(r8, nil, asm.Instructions{
			asm.And.Imm(r8, 2),
		}))
	})

	t.Run("materialize right operand failure", func(t *testing.T) {
		defer resetCompilerDirectRead(c)
		c.memMode = MemoryReadModeCoreRead

		expr := prepareCcExpr(t, "n & skb->len")

		c.setBtfIDErr(t)

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("skb->len & n", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "skb->len & n")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isMaterialized())
		test.AssertEqualSlice(t, c.insns, genInsnsWithN(
			r7,
			asm.Instructions{
				asm.LoadMem(r8, argsReg, 0, dword),
				asm.LoadMem(r8, r8, 112, dword),
				asm.LSh.Imm(r8, 32),
				asm.RSh.Imm(r8, 32),
			},
			asm.Instructions{
				asm.And.Reg(r8, r7),
			},
		))
	})
}

func TestEvaluateOr(t *testing.T) {
	c := prepareCompilerDirectRead(t)

	t.Run("invalid left operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "0x42ULL | 42")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("invalid right operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "42 | 0x42ULL")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("resolve enums", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "n | unk")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("const | const", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "42 | 2")
		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isConstant())
		test.AssertEqual(t, val.num, 42)
	})

	t.Run("struct left operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "skb->users | 42")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "left operand cannot be used for or")
	})

	t.Run("struct right operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "42 | skb->users")

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "right operand cannot be used for or")
	})

	t.Run("materialize left operand failure", func(t *testing.T) {
		defer resetCompilerDirectRead(c)
		c.memMode = MemoryReadModeCoreRead

		expr := prepareCcExpr(t, "skb->len | 2")

		c.setBtfIDErr(t)

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("n | const", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "n | 2")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isMaterialized())
		test.AssertEqualSlice(t, c.insns, genInsnsWithN(r8, nil, asm.Instructions{
			asm.Or.Imm(r8, 2),
		}))
	})

	t.Run("materialize right operand failure", func(t *testing.T) {
		defer resetCompilerDirectRead(c)
		c.memMode = MemoryReadModeCoreRead

		expr := prepareCcExpr(t, "n | skb->len")

		c.setBtfIDErr(t)

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("skb->len | n", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "skb->len | n")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isMaterialized())
		test.AssertEqualSlice(t, c.insns, genInsnsWithN(
			r7,
			asm.Instructions{
				asm.LoadMem(r8, argsReg, 0, dword),
				asm.LoadMem(r8, r8, 112, dword),
				asm.LSh.Imm(r8, 32),
				asm.RSh.Imm(r8, 32),
			},
			asm.Instructions{
				asm.Or.Reg(r8, r7),
			},
		))
	})
}

func TestEvaluateXor(t *testing.T) {
	c := prepareCompilerDirectRead(t)

	t.Run("invalid left operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "0x42ULL ^ 42")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("invalid right operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "42 ^ 0x42ULL")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("resolve enums", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "n ^ unk")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("const ^ const", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "42 ^ 2")
		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isConstant())
		test.AssertEqual(t, val.num, 40)
	})

	t.Run("struct left operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "skb->users ^ 42")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "left operand cannot be used for xor")
	})

	t.Run("struct right operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "42 ^ skb->users")

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "right operand cannot be used for xor")
	})

	t.Run("materialize left operand failure", func(t *testing.T) {
		defer resetCompilerDirectRead(c)
		c.memMode = MemoryReadModeCoreRead

		expr := prepareCcExpr(t, "skb->len ^ 2")

		c.setBtfIDErr(t)

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("n ^ const", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "n ^ 2")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isMaterialized())
		test.AssertEqualSlice(t, c.insns, genInsnsWithN(r8, nil, asm.Instructions{
			asm.Xor.Imm(r8, 2),
		}))
	})

	t.Run("materialize right operand failure", func(t *testing.T) {
		defer resetCompilerDirectRead(c)
		c.memMode = MemoryReadModeCoreRead

		expr := prepareCcExpr(t, "n ^ skb->len")

		c.setBtfIDErr(t)

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("skb->len ^ n", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "skb->len ^ n")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isMaterialized())
		test.AssertEqualSlice(t, c.insns, genInsnsWithN(
			r7,
			asm.Instructions{
				asm.LoadMem(r8, argsReg, 0, dword),
				asm.LoadMem(r8, r8, 112, dword),
				asm.LSh.Imm(r8, 32),
				asm.RSh.Imm(r8, 32),
			},
			asm.Instructions{
				asm.Xor.Reg(r8, r7),
			},
		))
	})
}

func TestEvaluateLsh(t *testing.T) {
	c := prepareCompilerDirectRead(t)

	t.Run("invalid left operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "0x42ULL << 42")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("invalid right operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "42 << 0x42ULL")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("resolve enums", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "n << unk")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("const << const", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "42 << 2")
		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isConstant())
		test.AssertEqual(t, val.num, 42<<2)
	})

	t.Run("struct left operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "skb->users << 42")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "left operand cannot be used for lsh")
	})

	t.Run("struct right operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "42 << skb->users")

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "right operand cannot be used for lsh")
	})

	t.Run("materialize left operand failure", func(t *testing.T) {
		defer resetCompilerDirectRead(c)
		c.memMode = MemoryReadModeCoreRead

		expr := prepareCcExpr(t, "skb->len << 2")

		c.setBtfIDErr(t)

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("n << -1", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "n << -1")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "shift count is negative")
	})

	t.Run("n << 0", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "n << 0")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, val.reg, r8)
		test.AssertEqualSlice(t, c.insns, genInsnsWithN(r8, nil, nil))
	})

	t.Run("n << const", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "n << 2")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isMaterialized())
		test.AssertEqualSlice(t, c.insns, genInsnsWithN(r8, nil, asm.Instructions{
			asm.LSh.Imm(r8, 2),
		}))
	})

	t.Run("materialize right operand failure", func(t *testing.T) {
		defer resetCompilerDirectRead(c)
		c.memMode = MemoryReadModeCoreRead

		expr := prepareCcExpr(t, "n << skb->len")

		c.setBtfIDErr(t)

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("skb->len << n", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "skb->len << n")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isMaterialized())
		test.AssertEqualSlice(t, c.insns, genInsnsWithN(
			r7,
			asm.Instructions{
				asm.LoadMem(r8, argsReg, 0, dword),
				asm.LoadMem(r8, r8, 112, dword),
				asm.LSh.Imm(r8, 32),
				asm.RSh.Imm(r8, 32),
			},
			asm.Instructions{
				JmpOff(asm.JLE, r7, 0, 1),
				asm.LSh.Reg(r8, r7),
			},
		))
	})
}

func TestEvaluateRsh(t *testing.T) {
	c := prepareCompilerDirectRead(t)

	t.Run("invalid left operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "0x42ULL >> 42")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("invalid right operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "42 >> 0x42ULL")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("resolve enums", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "n >> unk")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("const >> const", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "42 >> 2")
		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isConstant())
		test.AssertEqual(t, val.num, 42>>2)
	})

	t.Run("struct left operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "skb->users >> 42")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "left operand cannot be used for rsh")
	})

	t.Run("struct right operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "42 >> skb->users")

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "right operand cannot be used for rsh")
	})

	t.Run("materialize left operand failure", func(t *testing.T) {
		defer resetCompilerDirectRead(c)
		c.memMode = MemoryReadModeCoreRead

		expr := prepareCcExpr(t, "skb->len >> 2")

		c.setBtfIDErr(t)

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("n >> -1", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "n >> -1")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "shift count is negative")
	})

	t.Run("n >> 0", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "n >> 0")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, val.reg, r8)
		test.AssertEqualSlice(t, c.insns, genInsnsWithN(r8, nil, nil))
	})

	t.Run("n >> const", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "n >> 2")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isMaterialized())
		test.AssertEqualSlice(t, c.insns, genInsnsWithN(r8, nil, asm.Instructions{
			asm.RSh.Imm(r8, 2),
		}))
	})

	t.Run("materialize right operand failure", func(t *testing.T) {
		defer resetCompilerDirectRead(c)
		c.memMode = MemoryReadModeCoreRead

		expr := prepareCcExpr(t, "n >> skb->len")

		c.setBtfIDErr(t)

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("skb->len >> n", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "skb->len >> n")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isMaterialized())
		test.AssertEqualSlice(t, c.insns, genInsnsWithN(
			r7,
			asm.Instructions{
				asm.LoadMem(r8, argsReg, 0, dword),
				asm.LoadMem(r8, r8, 112, dword),
				asm.LSh.Imm(r8, 32),
				asm.RSh.Imm(r8, 32),
			},
			asm.Instructions{
				JmpOff(asm.JLE, r7, 0, 1),
				asm.RSh.Reg(r8, r7),
			},
		))
	})
}

func TestEvaluateTwid(t *testing.T) {
	c := prepareCompilerDirectRead(t)

	t.Run("invalid operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "~0x42ULL")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("~const", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "~0x42")
		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isConstant())
		test.AssertEqual(t, val.num, ^0x42)
	})

	t.Run("~struct", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "~skb->users")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "the operand cannot be used for twid")
	})

	t.Run("materialize operand failure", func(t *testing.T) {
		defer resetCompilerDirectRead(c)
		c.memMode = MemoryReadModeCoreRead

		expr := prepareCcExpr(t, "~skb->len")

		c.setBtfIDErr(t)

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("~n", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "~n")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isMaterialized())
		test.AssertEqualSlice(t, c.insns, genInsnsWithN(r8, nil, asm.Instructions{
			asm.Xor.Imm(r8, -1),
		}))
	})
}

func TestEvaluateEqEq(t *testing.T) {
	c := prepareCompilerDirectRead(t)

	t.Run("invalid left operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "0x42ULL == 42")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("invalid right operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "42 == 0x42ULL")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("resolve enums", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "n == unk")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("const == const", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "42 == 2")
		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isConstant())
		test.AssertEqual(t, val.num, 0)
	})

	t.Run("struct left operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "skb->users == 42")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "left operand cannot be used for eqeq")
	})

	t.Run("struct right operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "42 == skb->users")

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "right operand cannot be used for eqeq")
	})

	t.Run("materialize left operand failure", func(t *testing.T) {
		defer resetCompilerDirectRead(c)
		c.memMode = MemoryReadModeCoreRead

		expr := prepareCcExpr(t, "skb->len == 2")

		c.setBtfIDErr(t)

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("n == 0x42", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "n == 0x42")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isMaterialized())
		test.AssertEqualSlice(t, c.insns, genInsnsWithN(r8, nil, asm.Instructions{
			JmpOff(asm.JNE, r8, 0x42, 2),
			asm.Mov.Imm(r8, 1),
			Ja(1),
			asm.Xor.Reg(r8, r8),
		}))
	})

	t.Run("materialize right operand failure", func(t *testing.T) {
		defer resetCompilerDirectRead(c)
		c.memMode = MemoryReadModeCoreRead

		expr := prepareCcExpr(t, "n == skb->len")

		c.setBtfIDErr(t)

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("skb->len == n", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "skb->len == n")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isMaterialized())
		test.AssertEqualSlice(t, c.insns, genInsnsWithN(
			r7,
			asm.Instructions{
				asm.LoadMem(r8, argsReg, 0, dword),
				asm.LoadMem(r8, r8, 112, dword),
				asm.LSh.Imm(r8, 32),
				asm.RSh.Imm(r8, 32),
			},
			asm.Instructions{
				JmpReg(asm.JNE, r8, r7, 2),
				asm.Mov.Imm(r8, 1),
				Ja(1),
				asm.Xor.Reg(r8, r8),
			},
		))
	})
}

func TestEvaluateNotEq(t *testing.T) {
	c := prepareCompilerDirectRead(t)

	t.Run("invalid left operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "0x42ULL != 42")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("invalid right operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "42 != 0x42ULL")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("resolve enums", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "n != unk")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("const != const", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "42 != 2")
		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isConstant())
		test.AssertEqual(t, val.num, 1)
	})

	t.Run("struct left operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "skb->users != 42")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "left operand cannot be used for noteq")
	})

	t.Run("struct right operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "42 != skb->users")

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "right operand cannot be used for noteq")
	})

	t.Run("materialize left operand failure", func(t *testing.T) {
		defer resetCompilerDirectRead(c)
		c.memMode = MemoryReadModeCoreRead

		expr := prepareCcExpr(t, "skb->len != 2")

		c.setBtfIDErr(t)

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("n != 0x42", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "n != 0x42")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isMaterialized())
		test.AssertEqualSlice(t, c.insns, genInsnsWithN(r8, nil, asm.Instructions{
			JmpOff(asm.JEq, r8, 0x42, 2),
			asm.Mov.Imm(r8, 1),
			Ja(1),
			asm.Xor.Reg(r8, r8),
		}))
	})

	t.Run("materialize right operand failure", func(t *testing.T) {
		defer resetCompilerDirectRead(c)
		c.memMode = MemoryReadModeCoreRead

		expr := prepareCcExpr(t, "n != skb->len")

		c.setBtfIDErr(t)

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("skb->len != n", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "skb->len != n")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isMaterialized())
		test.AssertEqualSlice(t, c.insns, genInsnsWithN(
			r7,
			asm.Instructions{
				asm.LoadMem(r8, argsReg, 0, dword),
				asm.LoadMem(r8, r8, 112, dword),
				asm.LSh.Imm(r8, 32),
				asm.RSh.Imm(r8, 32),
			},
			asm.Instructions{
				JmpReg(asm.JEq, r8, r7, 2),
				asm.Mov.Imm(r8, 1),
				Ja(1),
				asm.Xor.Reg(r8, r8),
			},
		))
	})
}

func TestEvaluateLt(t *testing.T) {
	c := prepareCompilerDirectRead(t)

	t.Run("invalid left operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "0x42ULL < 42")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("invalid right operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "42 < 0x42ULL")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("resolve enums", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "n < unk")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("const < const", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "42 < 2")
		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isConstant())
		test.AssertEqual(t, val.num, 0)
	})

	t.Run("struct left operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "skb->users < 42")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "left operand cannot be used for lt")
	})

	t.Run("struct right operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "42 < skb->users")

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "right operand cannot be used for lt")
	})

	t.Run("materialize left operand failure", func(t *testing.T) {
		defer resetCompilerDirectRead(c)
		c.memMode = MemoryReadModeCoreRead

		expr := prepareCcExpr(t, "skb->len < 2")

		c.setBtfIDErr(t)

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("n < 0x42", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "n < 0x42")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isMaterialized())
		test.AssertEqualSlice(t, c.insns, genInsnsWithN(r8, nil, asm.Instructions{
			JmpOff(asm.JGE, r8, 0x42, 2),
			asm.Mov.Imm(r8, 1),
			Ja(1),
			asm.Xor.Reg(r8, r8),
		}))
	})

	t.Run("materialize right operand failure", func(t *testing.T) {
		defer resetCompilerDirectRead(c)
		c.memMode = MemoryReadModeCoreRead

		expr := prepareCcExpr(t, "n < skb->len")

		c.setBtfIDErr(t)

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("skb->len < n", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "skb->len < n")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isMaterialized())
		test.AssertEqualSlice(t, c.insns, genInsnsWithN(
			r7,
			asm.Instructions{
				asm.LoadMem(r8, argsReg, 0, dword),
				asm.LoadMem(r8, r8, 112, dword),
				asm.LSh.Imm(r8, 32),
				asm.RSh.Imm(r8, 32),
			},
			asm.Instructions{
				JmpReg(asm.JGE, r8, r7, 2),
				asm.Mov.Imm(r8, 1),
				Ja(1),
				asm.Xor.Reg(r8, r8),
			},
		))
	})
}

func TestEvaluateLtEq(t *testing.T) {
	c := prepareCompilerDirectRead(t)

	t.Run("invalid left operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "0x42ULL <= 42")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("invalid right operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "42 <= 0x42ULL")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("resolve enums", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "n <= unk")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("const <= const", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "42 <= 2")
		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isConstant())
		test.AssertEqual(t, val.num, 0)
	})

	t.Run("struct left operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "skb->users <= 42")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "left operand cannot be used for lteq")
	})

	t.Run("struct right operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "42 <= skb->users")

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "right operand cannot be used for lteq")
	})

	t.Run("materialize left operand failure", func(t *testing.T) {
		defer resetCompilerDirectRead(c)
		c.memMode = MemoryReadModeCoreRead

		expr := prepareCcExpr(t, "skb->len <= 2")

		c.setBtfIDErr(t)

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("n <= 0x42", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "n <= 0x42")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isMaterialized())
		test.AssertEqualSlice(t, c.insns, genInsnsWithN(r8, nil, asm.Instructions{
			JmpOff(asm.JGT, r8, 0x42, 2),
			asm.Mov.Imm(r8, 1),
			Ja(1),
			asm.Xor.Reg(r8, r8),
		}))
	})

	t.Run("materialize right operand failure", func(t *testing.T) {
		defer resetCompilerDirectRead(c)
		c.memMode = MemoryReadModeCoreRead

		expr := prepareCcExpr(t, "n <= skb->len")

		c.setBtfIDErr(t)

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("skb->len <= n", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "skb->len <= n")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isMaterialized())
		test.AssertEqualSlice(t, c.insns, genInsnsWithN(
			r7,
			asm.Instructions{
				asm.LoadMem(r8, argsReg, 0, dword),
				asm.LoadMem(r8, r8, 112, dword),
				asm.LSh.Imm(r8, 32),
				asm.RSh.Imm(r8, 32),
			},
			asm.Instructions{
				JmpReg(asm.JGT, r8, r7, 2),
				asm.Mov.Imm(r8, 1),
				Ja(1),
				asm.Xor.Reg(r8, r8),
			},
		))
	})
}

func TestEvaluateGt(t *testing.T) {
	c := prepareCompilerDirectRead(t)

	t.Run("invalid left operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "0x42ULL > 42")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("invalid right operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "42 > 0x42ULL")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("resolve enums", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "n > unk")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("const > const", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "42 > 2")
		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isConstant())
		test.AssertEqual(t, val.num, 1)
	})

	t.Run("struct left operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "skb->users > 42")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "left operand cannot be used for gt")
	})

	t.Run("struct right operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "42 > skb->users")

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "right operand cannot be used for gt")
	})

	t.Run("materialize left operand failure", func(t *testing.T) {
		defer resetCompilerDirectRead(c)
		c.memMode = MemoryReadModeCoreRead

		expr := prepareCcExpr(t, "skb->len > 2")

		c.setBtfIDErr(t)

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("n > 0x42", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "n > 0x42")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isMaterialized())
		test.AssertEqualSlice(t, c.insns, genInsnsWithN(r8, nil, asm.Instructions{
			JmpOff(asm.JLE, r8, 0x42, 2),
			asm.Mov.Imm(r8, 1),
			Ja(1),
			asm.Xor.Reg(r8, r8),
		}))
	})

	t.Run("materialize right operand failure", func(t *testing.T) {
		defer resetCompilerDirectRead(c)
		c.memMode = MemoryReadModeCoreRead

		expr := prepareCcExpr(t, "n > skb->len")

		c.setBtfIDErr(t)

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("skb->len > n", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "skb->len > n")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isMaterialized())
		test.AssertEqualSlice(t, c.insns, genInsnsWithN(
			r7,
			asm.Instructions{
				asm.LoadMem(r8, argsReg, 0, dword),
				asm.LoadMem(r8, r8, 112, dword),
				asm.LSh.Imm(r8, 32),
				asm.RSh.Imm(r8, 32),
			},
			asm.Instructions{
				JmpReg(asm.JLE, r8, r7, 2),
				asm.Mov.Imm(r8, 1),
				Ja(1),
				asm.Xor.Reg(r8, r8),
			},
		))
	})
}

func TestEvaluateGtEq(t *testing.T) {
	c := prepareCompilerDirectRead(t)

	t.Run("invalid left operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "0x42ULL >= 42")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("invalid right operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "42 >= 0x42ULL")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("resolve enums", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "n >= unk")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("const >= const", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "42 >= 2")
		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isConstant())
		test.AssertEqual(t, val.num, 1)
	})

	t.Run("struct left operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "skb->users >= 42")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "left operand cannot be used for gteq")
	})

	t.Run("struct right operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "42 >= skb->users")

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "right operand cannot be used for gteq")
	})

	t.Run("materialize left operand failure", func(t *testing.T) {
		defer resetCompilerDirectRead(c)
		c.memMode = MemoryReadModeCoreRead

		expr := prepareCcExpr(t, "skb->len >= 2")

		c.setBtfIDErr(t)

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("n >= 0x42", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "n >= 0x42")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isMaterialized())
		test.AssertEqualSlice(t, c.insns, genInsnsWithN(r8, nil, asm.Instructions{
			JmpOff(asm.JLT, r8, 0x42, 2),
			asm.Mov.Imm(r8, 1),
			Ja(1),
			asm.Xor.Reg(r8, r8),
		}))
	})

	t.Run("materialize right operand failure", func(t *testing.T) {
		defer resetCompilerDirectRead(c)
		c.memMode = MemoryReadModeCoreRead

		expr := prepareCcExpr(t, "n >= skb->len")

		c.setBtfIDErr(t)

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("skb->len >= n", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "skb->len >= n")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isMaterialized())
		test.AssertEqualSlice(t, c.insns, genInsnsWithN(
			r7,
			asm.Instructions{
				asm.LoadMem(r8, argsReg, 0, dword),
				asm.LoadMem(r8, r8, 112, dword),
				asm.LSh.Imm(r8, 32),
				asm.RSh.Imm(r8, 32),
			},
			asm.Instructions{
				JmpReg(asm.JLT, r8, r7, 2),
				asm.Mov.Imm(r8, 1),
				Ja(1),
				asm.Xor.Reg(r8, r8),
			},
		))
	})
}

func TestEvaluateSignedComparisons(t *testing.T) {
	i32 := &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}
	u32 := &btf.Int{Name: "unsigned int", Size: 4, Encoding: btf.Unsigned}
	tests := []struct {
		name   string
		expr   string
		op     asm.JumpOp
		source asm.Source
	}{
		{name: "less than immediate", expr: "n < 0", op: asm.JSGE, source: asm.ImmSource},
		{name: "less than or equal immediate", expr: "n <= 0", op: asm.JSGT, source: asm.ImmSource},
		{name: "greater than immediate", expr: "n > 0", op: asm.JSLE, source: asm.ImmSource},
		{name: "greater than or equal immediate", expr: "n >= 0", op: asm.JSLT, source: asm.ImmSource},
		{name: "constant left", expr: "0 < n", op: asm.JSGE, source: asm.RegSource},
		{name: "signed registers", expr: "n < m", op: asm.JSGE, source: asm.RegSource},
		{name: "mixed register types", expr: "n < u", op: asm.JGE, source: asm.RegSource},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			insns, err := CompileFilterExpr(CompileExprOptions{
				Expr:      tt.expr,
				LabelExit: "exit",
				Spec:      testBtf,
				Kernel:    testBtf,
				Params: []btf.FuncParam{
					{Name: "n", Type: i32},
					{Name: "m", Type: i32},
					{Name: "u", Type: u32},
				},
			})
			test.AssertNoErr(t, err)

			for _, insn := range insns {
				if insn.OpCode.JumpOp() == tt.op && insn.OpCode.Source() == tt.source {
					return
				}
			}
			t.Fatalf("%q did not emit %v with %v source: %v", tt.expr, tt.op, tt.source, insns)
		})
	}
}

func TestEvaluateAndAnd(t *testing.T) {
	c := prepareCompilerDirectRead(t)

	t.Run("invalid left operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "0x42ULL && 42")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("invalid right operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "42 && 0x42ULL")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("resolve enums", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "n && unk")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("const && const", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "42 && 2")
		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isConstant())
		test.AssertEqual(t, val.num, 1)
	})

	t.Run("struct left operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "skb->users && 42")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "left operand cannot be used for andand")
	})

	t.Run("struct right operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "42 && skb->users")

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "right operand cannot be used for andand")
	})

	t.Run("0 && n", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "0 && n")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isConstant())
		test.AssertEqual(t, val.num, 0)
		test.AssertEmptySlice(t, c.insns)
	})

	t.Run("left is const && materialize right operand failure", func(t *testing.T) {
		defer resetCompilerDirectRead(c)
		c.memMode = MemoryReadModeCoreRead

		expr := prepareCcExpr(t, "1 && skb->len")

		c.setBtfIDErr(t)

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("0x42 && n", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "0x42 && n")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isMaterialized())
		test.AssertEqualSlice(t, c.insns, genInsnsWithN(r8, nil, asm.Instructions{
			JmpOff(asm.JEq, r8, 0, 2),
			asm.Mov.Imm(r8, 1),
			Ja(1),
			asm.Xor.Reg(r8, r8),
		}))
	})

	t.Run("(n + n) && 0", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "(n + n) && 0")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isConstant())
		test.AssertEqual(t, val.num, 0)
	})

	t.Run("right is const && materialize left operand failure", func(t *testing.T) {
		defer resetCompilerDirectRead(c)
		c.memMode = MemoryReadModeCoreRead

		expr := prepareCcExpr(t, "skb->len && 1")

		c.setBtfIDErr(t)

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("n && 0x42", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "n && 0x42")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isMaterialized())
		test.AssertEqualSlice(t, c.insns, genInsnsWithN(r8, nil, asm.Instructions{
			JmpOff(asm.JEq, r8, 0, 2),
			asm.Mov.Imm(r8, 1),
			Ja(1),
			asm.Xor.Reg(r8, r8),
		}))
	})

	t.Run("materialize left operand failure", func(t *testing.T) {
		defer resetCompilerDirectRead(c)
		c.memMode = MemoryReadModeCoreRead

		expr := prepareCcExpr(t, "skb->len && n")

		c.setBtfIDErr(t)

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("materialize right operand failure", func(t *testing.T) {
		defer resetCompilerDirectRead(c)
		c.memMode = MemoryReadModeCoreRead

		expr := prepareCcExpr(t, "n && skb->len")

		c.setBtfIDErr(t)

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("skb->len && n", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "skb->len && n")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isMaterialized())
		test.AssertEqualSlice(t, c.insns, genInsnsWithN(
			r7,
			asm.Instructions{
				asm.LoadMem(r8, argsReg, 0, dword),
				asm.LoadMem(r8, r8, 112, dword),
				asm.LSh.Imm(r8, 32),
				asm.RSh.Imm(r8, 32),
			},
			asm.Instructions{
				JmpOff(asm.JEq, r8, 0, 3),
				JmpOff(asm.JEq, r7, 0, 2),
				asm.Mov.Imm(r8, 1),
				Ja(1),
				asm.Xor.Reg(r8, r8),
			},
		))
	})
}

func TestEvaluateOrOr(t *testing.T) {
	c := prepareCompilerDirectRead(t)

	t.Run("invalid left operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "0x42ULL || 42")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("invalid right operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "42 || 0x42ULL")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("resolve enums", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "n || unk")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("const || const", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "42 || 2")
		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isConstant())
		test.AssertEqual(t, val.num, 1)
	})

	t.Run("struct left operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "skb->users || 42")
		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "left operand cannot be used for oror")
	})

	t.Run("struct right operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "42 || skb->users")

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "right operand cannot be used for oror")
	})

	t.Run("1 || n", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "1 || n")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isConstant())
		test.AssertEqual(t, val.num, 1)
		test.AssertEmptySlice(t, c.insns)
	})

	t.Run("left is const || materialize right operand failure", func(t *testing.T) {
		defer resetCompilerDirectRead(c)
		c.memMode = MemoryReadModeCoreRead

		expr := prepareCcExpr(t, "0 || skb->len")

		c.setBtfIDErr(t)

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("0 || n", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "0 || n")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isMaterialized())
		test.AssertEqualSlice(t, c.insns, genInsnsWithN(r8, nil, asm.Instructions{
			JmpOff(asm.JEq, r8, 0, 2),
			asm.Mov.Imm(r8, 1),
			Ja(1),
			asm.Xor.Reg(r8, r8),
		}))
	})

	t.Run("(n + n) || 1", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "(n + n) || 1")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isConstant())
		test.AssertEqual(t, val.num, 1)
	})

	t.Run("right is const || materialize left operand failure", func(t *testing.T) {
		defer resetCompilerDirectRead(c)
		c.memMode = MemoryReadModeCoreRead

		expr := prepareCcExpr(t, "skb->len || 0")

		c.setBtfIDErr(t)

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("n || 0", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "n || 0")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isMaterialized())
		test.AssertEqualSlice(t, c.insns, genInsnsWithN(r8, nil, asm.Instructions{
			JmpOff(asm.JEq, r8, 0, 2),
			asm.Mov.Imm(r8, 1),
			Ja(1),
			asm.Xor.Reg(r8, r8),
		}))
	})

	t.Run("materialize left operand failure", func(t *testing.T) {
		defer resetCompilerDirectRead(c)
		c.memMode = MemoryReadModeCoreRead

		expr := prepareCcExpr(t, "skb->len || n")

		c.setBtfIDErr(t)

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("materialize right operand failure", func(t *testing.T) {
		defer resetCompilerDirectRead(c)
		c.memMode = MemoryReadModeCoreRead

		expr := prepareCcExpr(t, "n || skb->len")

		c.setBtfIDErr(t)

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("skb->len || n", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "skb->len || n")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isMaterialized())
		test.AssertEqualSlice(t, c.insns, genInsnsWithN(
			r7,
			asm.Instructions{
				asm.LoadMem(r8, argsReg, 0, dword),
				asm.LoadMem(r8, r8, 112, dword),
				asm.LSh.Imm(r8, 32),
				asm.RSh.Imm(r8, 32),
			},
			asm.Instructions{
				JmpOff(asm.JNE, r8, 0, 3),
				JmpOff(asm.JNE, r7, 0, 2),
				asm.Xor.Reg(r8, r8),
				Ja(1),
				asm.Mov.Imm(r8, 1),
			},
		))
	})
}

func TestEvaluateNot(t *testing.T) {
	c := prepareCompilerDirectRead(t)

	t.Run("invalid operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "!0x42ULL")

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("!0", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "!0")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isConstant())
		test.AssertEqual(t, val.num, 1)
	})

	t.Run("materialize operand failure", func(t *testing.T) {
		defer resetCompilerDirectRead(c)
		c.memMode = MemoryReadModeCoreRead

		expr := prepareCcExpr(t, "!skb->len")

		c.setBtfIDErr(t)

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("!n", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "!n")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isMaterialized())
		test.AssertEqualSlice(t, c.insns, genInsnsWithN(r8, nil, asm.Instructions{
			JmpOff(asm.JNE, r8, 0, 2),
			asm.Mov.Imm(r8, 1),
			Ja(1),
			asm.Xor.Reg(r8, r8),
		}))
	})
}

func TestEvaluateMinus(t *testing.T) {
	c := prepareCompilerDirectRead(t)

	t.Run("invalid operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "-0x42ULL")

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("-0x42", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "-0x42")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isConstant())
		test.AssertEqual(t, val.num, -0x42)
	})

	t.Run("materialize operand failure", func(t *testing.T) {
		defer resetCompilerDirectRead(c)
		c.memMode = MemoryReadModeCoreRead

		expr := prepareCcExpr(t, "-skb->len")

		c.setBtfIDErr(t)

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("-n", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "-n")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isMaterialized())
		test.AssertEqualSlice(t, c.insns, genInsnsWithN(r8, nil, asm.Instructions{
			asm.Neg.Reg(r8, r8),
		}))
	})
}

func TestEvaluatePreInc(t *testing.T) {
	c := prepareCompilerDirectRead(t)

	t.Run("invalid operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "++0x42ULL")

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("++0x42", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "++0x42")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isConstant())
		test.AssertEqual(t, val.num, 0x43)
	})

	t.Run("materialize operand failure", func(t *testing.T) {
		defer resetCompilerDirectRead(c)
		c.memMode = MemoryReadModeCoreRead

		expr := prepareCcExpr(t, "++skb->len")

		c.setBtfIDErr(t)

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("++n", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "++n")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isMaterialized())
		test.AssertEqualSlice(t, c.insns, genInsnsWithN(r8, nil, asm.Instructions{
			asm.Add.Imm(r8, 1),
		}))
	})
}

func TestEvaluatePreDec(t *testing.T) {
	c := prepareCompilerDirectRead(t)

	t.Run("invalid operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "--0x42ULL")

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("--0x42", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "--0x42")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isConstant())
		test.AssertEqual(t, val.num, 0x41)
	})

	t.Run("materialize operand failure", func(t *testing.T) {
		defer resetCompilerDirectRead(c)
		c.memMode = MemoryReadModeCoreRead

		expr := prepareCcExpr(t, "--skb->len")

		c.setBtfIDErr(t)

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("--n", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "--n")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isMaterialized())
		test.AssertEqualSlice(t, c.insns, genInsnsWithN(r8, nil, asm.Instructions{
			asm.Sub.Imm(r8, 1),
		}))
	})
}

func TestEvaluateCond(t *testing.T) {
	c := prepareCompilerDirectRead(t)

	t.Run("invalid list len", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := &cc.Expr{
			Op:   cc.Cond,
			List: nil,
		}

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "conditional expression requires 3 operands")
	})

	t.Run("evaluate cond operand failure", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "0x42ULL ? a : b")

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("evaluate left operand failure", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "0 ? 0x42ULL : n")

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("evaluate right operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "0 ? 1 : 0x42ULL")

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("invalid cond operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "skb->users ? 1 : n")

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "invalid cond operand")
	})

	t.Run("invalid left operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "n ? skb->users : x")

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "left operand cannot be used for cond")
	})

	t.Run("invalid right operand", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "n ? 1 : skb->users")

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "right operand cannot be used for cond")
	})

	t.Run("cond is 0", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "0 ? 1 : n")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isPending())
	})

	t.Run("cond is 1", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "1 ? 1 : n")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isConstant())
		test.AssertEqual(t, val.num, 1)
	})

	t.Run("materialize cond operand failure", func(t *testing.T) {
		defer resetCompilerDirectRead(c)
		c.setBtfIDErr(t)

		expr := prepareCcExpr(t, "skb->len ? 1 : n")

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("left is const && right is const", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "n ? 1 : 2")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isMaterialized())
		test.AssertEqualSlice(t, c.insns, genInsnsWithN(r8, nil, asm.Instructions{
			JmpOff(asm.JEq, r8, 0, 2),
			asm.Mov.Imm(r8, 1),
			Ja(1),
			asm.Mov.Imm(r8, 2),
		}))
	})

	t.Run("materialize left operand failure", func(t *testing.T) {
		defer resetCompilerDirectRead(c)
		c.setBtfIDErr(t)

		expr := prepareCcExpr(t, "n ? skb->len : 2")

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("left is n && right is const", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "n ? n : 2")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isMaterialized())
		test.AssertEqualSlice(t, c.insns, genInsnsWithN(r8, nil, asm.Instructions{
			JmpOff(asm.JEq, r8, 0, 5),
			asm.LoadMem(r7, argsReg, 40, dword),
			asm.LSh.Imm(r7, 32),
			asm.RSh.Imm(r7, 32),
			asm.Mov.Reg(r8, r7),
			Ja(1),
			asm.Mov.Imm(r8, 2),
		}))
	})

	t.Run("materiaze right operand failure", func(t *testing.T) {
		defer resetCompilerDirectRead(c)
		c.setBtfIDErr(t)

		expr := prepareCcExpr(t, "n ? n : skb->len")

		_, err := c.evaluate(expr)
		test.AssertHaveErr(t, err)
	})

	t.Run("left is skb->len && right is skb->truesize", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		expr := prepareCcExpr(t, "n ? skb->len : skb->truesize")

		val, err := c.evaluate(expr)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isMaterialized())
		test.AssertEqualSlice(t, c.insns, genInsnsWithN(r8, nil, asm.Instructions{
			JmpOff(asm.JEq, r8, 0, 6),
			asm.LoadMem(r7, argsReg, 0, dword),
			asm.LoadMem(r7, r7, 112, dword),
			asm.LSh.Imm(r7, 32),
			asm.RSh.Imm(r7, 32),
			asm.Mov.Reg(r8, r7),
			Ja(5),
			asm.LoadMem(r7, argsReg, 0, dword),
			asm.LoadMem(r7, r7, 216, dword),
			asm.LSh.Imm(r7, 32),
			asm.RSh.Imm(r7, 32),
			asm.Mov.Reg(r8, r7),
		}))
	})
}

func TestResolveEnums(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("invalid left enum && right is materialized", func(t *testing.T) {
		defer c.reset()
		progType := getBpfProgTypeBtf(t)

		l := newEnumMaybe("INVALID_ENUM")
		r := newMaterialized(asm.R0, progType)

		_, _, err := c.resolveEnums(l, r)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "failed to resolve enum")
	})

	t.Run("left enum && right is materialized", func(t *testing.T) {
		defer c.reset()

		progType := getBpfProgTypeBtf(t)

		l := newEnumMaybe("BPF_PROG_TYPE_XDP")
		r := newMaterialized(asm.R0, progType)

		resolvedL, resolvedR, err := c.resolveEnums(l, r)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, resolvedL.isConstant())
		test.AssertEqual(t, resolvedL.num, int64(6)) // BPF_PROG_TYPE_XDP = 6
		test.AssertTrue(t, resolvedR.isMaterialized())
	})

	t.Run("left is materialized && invalid right enum", func(t *testing.T) {
		defer c.reset()
		progType := getBpfProgTypeBtf(t)

		l := newMaterialized(asm.R0, progType)
		r := newEnumMaybe("INVALID_ENUM")

		_, _, err := c.resolveEnums(l, r)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "failed to resolve enum")
	})

	t.Run("left is materialized && right enum", func(t *testing.T) {
		defer c.reset()

		progType := getBpfProgTypeBtf(t)

		l := newMaterialized(asm.R0, progType)
		r := newEnumMaybe("BPF_PROG_TYPE_XDP")

		resolvedL, resolvedR, err := c.resolveEnums(l, r)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, resolvedL.isMaterialized())
		test.AssertTrue(t, resolvedR.isConstant())
		test.AssertEqual(t, resolvedR.num, int64(6)) // BPF_PROG_TYPE_XDP = 6
	})

	t.Run("invalid left enum && right is pending", func(t *testing.T) {
		defer c.reset()
		progType := getBpfProgTypeBtf(t)

		l := newEnumMaybe("INVALID_ENUM")
		r := newPendingReg(asm.R0, progType)

		_, _, err := c.resolveEnums(l, r)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "failed to resolve enum")
	})

	t.Run("left enum && right is pending", func(t *testing.T) {
		defer c.reset()

		progType := getBpfProgTypeBtf(t)

		l := newEnumMaybe("BPF_PROG_TYPE_XDP")
		r := newPendingReg(asm.R0, progType)

		resolvedL, resolvedR, err := c.resolveEnums(l, r)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, resolvedL.isConstant())
		test.AssertEqual(t, resolvedL.num, int64(6)) // BPF_PROG_TYPE_XDP = 6
		test.AssertTrue(t, resolvedR.isPending())
	})

	t.Run("left is pending && invalid right enum", func(t *testing.T) {
		defer c.reset()
		progType := getBpfProgTypeBtf(t)

		l := newPendingReg(asm.R0, progType)
		r := newEnumMaybe("INVALID_ENUM")

		_, _, err := c.resolveEnums(l, r)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "failed to resolve enum")
	})

	t.Run("left is pending && right enum", func(t *testing.T) {
		defer c.reset()

		progType := getBpfProgTypeBtf(t)

		l := newPendingReg(asm.R0, progType)
		r := newEnumMaybe("BPF_PROG_TYPE_XDP")

		resolvedL, resolvedR, err := c.resolveEnums(l, r)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, resolvedL.isPending())
		test.AssertTrue(t, resolvedR.isConstant())
		test.AssertEqual(t, resolvedR.num, int64(6)) // BPF_PROG_TYPE_XDP = 6
	})
}

func TestAdjustNums(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("left is const && right is materialized", func(t *testing.T) {
		defer c.reset()

		l := newConstant(257)
		r := newMaterialized(r0, getU8Btf(t))

		l, r = c.adjustNums(l, r)
		test.AssertEqual(t, l.num, 257&0xFF)
	})

	t.Run("left is materialized && right is const", func(t *testing.T) {
		defer c.reset()

		l := newMaterialized(r0, getU8Btf(t))
		r := newConstant(257)

		l, r = c.adjustNums(l, r)
		test.AssertEqual(t, r.num, 257&0xFF)
	})
}

func TestIsSignedBTFType(t *testing.T) {
	signedInt := &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}
	tests := []struct {
		name string
		typ  btf.Type
		want bool
	}{
		{name: "signed int", typ: signedInt, want: true},
		{name: "signed typedef", typ: &btf.Typedef{Name: "status_t", Type: signedInt}, want: true},
		{name: "unsigned int", typ: &btf.Int{Name: "unsigned int", Size: 4, Encoding: btf.Unsigned}},
		{name: "signed enum", typ: &btf.Enum{Name: "state", Size: 4, Signed: true}, want: true},
		{name: "unsigned enum", typ: &btf.Enum{Name: "state", Size: 4}},
		{name: "pointer", typ: &btf.Pointer{Target: signedInt}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			test.AssertEqual(t, isSignedBTFType(tt.typ), tt.want)
		})
	}
}

func TestAdjustNumForType(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("bitfield", func(t *testing.T) {
		defer c.reset()

		skb := getSkbBtf(t)
		mem, err := mybtf.FindStructMember(skb.Target.(*btf.Struct), "pkt_type")
		test.AssertNoErr(t, err)

		n := c.adjustNumForType(14, skb, mem)
		test.AssertEqual(t, n, 6)
	})

	t.Run("1 size", func(t *testing.T) {
		defer c.reset()

		n := c.adjustNumForType(257, getU8Btf(t), nil)
		test.AssertEqual(t, n, 257&0xFF)
	})

	t.Run("2 size", func(t *testing.T) {
		defer c.reset()

		n := c.adjustNumForType(65537, getU16Btf(t), nil)
		test.AssertEqual(t, n, 1)
	})

	t.Run("4 size", func(t *testing.T) {
		defer c.reset()

		n := c.adjustNumForType((1<<32)+1, getU32Btf(t), nil)
		test.AssertEqual(t, n, 1)
	})

	t.Run("8 size", func(t *testing.T) {
		defer c.reset()

		n := c.adjustNumForType(7, getU64Btf(t), nil)
		test.AssertEqual(t, n, 7)
	})

	t.Run("signed sizes", func(t *testing.T) {
		tests := []struct {
			name string
			size uint32
			num  int64
			want int64
		}{
			{name: "byte", size: 1, num: 255, want: -1},
			{name: "word", size: 2, num: 65535, want: -1},
			{name: "dword", size: 4, num: 1<<32 - 1, want: -1},
			{name: "qword", size: 8, num: -7, want: -7},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				typ := &btf.Int{Name: tt.name, Size: tt.size, Encoding: btf.Signed}
				n := c.adjustNumForType(tt.num, typ, nil)
				test.AssertEqual(t, n, tt.want)
			})
		}
	})
}

func TestCC2btf(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("(struct not_found *)(skb->head)", func(t *testing.T) {
		expr, err := cc.ParseExpr("(struct not_found *)(skb->head)")
		test.AssertNoErr(t, err)

		_, err = c.cc2btf(expr)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "failed to find type")
	})

	t.Run("(struct u64 *)(skb->head)", func(t *testing.T) {
		expr, err := cc.ParseExpr("(struct u64 *)(skb->head)")
		test.AssertNoErr(t, err)

		_, err = c.cc2btf(expr)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "expected struct/union type for cast")
	})

	t.Run("(union not_found *)(skb->head)", func(t *testing.T) {
		expr, err := cc.ParseExpr("(union not_found *)(skb->head)")
		test.AssertNoErr(t, err)

		_, err = c.cc2btf(expr)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "failed to find type")
	})

	t.Run("(union u64 *)(skb->head)", func(t *testing.T) {
		expr, err := cc.ParseExpr("(union u64 *)(skb->head)")
		test.AssertNoErr(t, err)

		_, err = c.cc2btf(expr)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "expected struct/union type for cast")
	})

	t.Run("(struct iphdr *)skb->head", func(t *testing.T) {
		expr, err := cc.ParseExpr("(struct iphdr *)skb->head")
		test.AssertNoErr(t, err)

		res, err := c.cc2btf(expr)
		test.AssertNoErr(t, err)
		test.AssertNotNil(t, res)

		ptr, ok := res.(*btf.Pointer)
		test.AssertTrue(t, ok)
		strct, ok := ptr.Target.(*btf.Struct)
		test.AssertTrue(t, ok)
		test.AssertEqual(t, strct.Name, "iphdr")
	})

	t.Run("(void)skb->head", func(t *testing.T) {
		expr := prepareCcExpr(t, "(void)skb->head")

		typ, err := c.cc2btf(expr)
		test.AssertNoErr(t, err)

		voidType, ok := typ.(*btf.Void)
		test.AssertTrue(t, ok)
		test.AssertEqual(t, voidType.TypeName(), "")
	})

	t.Run("(char)skb->head", func(t *testing.T) {
		expr, err := cc.ParseExpr("(char)skb->head")
		test.AssertNoErr(t, err)

		typ, err := c.cc2btf(expr)
		test.AssertNoErr(t, err)

		intType, ok := typ.(*btf.Int)
		test.AssertTrue(t, ok)
		test.AssertEqual(t, intType.Size, 1)
	})

	t.Run("(unsigned char)skb->head", func(t *testing.T) {
		expr, err := cc.ParseExpr("(unsigned char)skb->head")
		test.AssertNoErr(t, err)

		typ, err := c.cc2btf(expr)
		test.AssertNoErr(t, err)

		intType, ok := mybtf.UnderlyingType(typ).(*btf.Int)
		test.AssertTrue(t, ok)
		test.AssertEqual(t, intType.Size, 1)
	})

	t.Run("(short)skb->head", func(t *testing.T) {
		expr, err := cc.ParseExpr("(short)skb->head")
		test.AssertNoErr(t, err)

		typ, err := c.cc2btf(expr)
		test.AssertNoErr(t, err)

		intType, ok := mybtf.UnderlyingType(typ).(*btf.Int)
		test.AssertTrue(t, ok)
		test.AssertEqual(t, intType.Size, 2)
		test.AssertEqual(t, intType.Encoding, btf.Signed)
	})

	t.Run("(unsigned short)skb->head", func(t *testing.T) {
		expr, err := cc.ParseExpr("(unsigned short)skb->head")
		test.AssertNoErr(t, err)

		typ, err := c.cc2btf(expr)
		test.AssertNoErr(t, err)

		intType, ok := mybtf.UnderlyingType(typ).(*btf.Int)
		test.AssertTrue(t, ok)
		test.AssertEqual(t, intType.Size, 2)
		test.AssertEqual(t, intType.Encoding, btf.Unsigned)
	})

	t.Run("(int)skb->head", func(t *testing.T) {
		expr, err := cc.ParseExpr("(int)skb->head")
		test.AssertNoErr(t, err)

		typ, err := c.cc2btf(expr)
		test.AssertNoErr(t, err)

		intType, ok := typ.(*btf.Int)
		test.AssertTrue(t, ok)
		test.AssertEqual(t, intType.Name, "int")
		test.AssertEqual(t, intType.Size, 4)
		test.AssertEqual(t, intType.Encoding, btf.Signed)
	})

	t.Run("(unsigned int)skb->head", func(t *testing.T) {
		expr, err := cc.ParseExpr("(unsigned int)skb->head")
		test.AssertNoErr(t, err)

		typ, err := c.cc2btf(expr)
		test.AssertNoErr(t, err)

		intType, ok := mybtf.UnderlyingType(typ).(*btf.Int)
		test.AssertTrue(t, ok)
		test.AssertEqual(t, intType.Name, "unsigned int")
		test.AssertEqual(t, intType.Size, 4)
		test.AssertEqual(t, intType.Encoding, btf.Unsigned)
	})

	t.Run("(long)skb->head", func(t *testing.T) {
		expr, err := cc.ParseExpr("(long)skb->head")
		test.AssertNoErr(t, err)

		typ, err := c.cc2btf(expr)
		test.AssertNoErr(t, err)

		intType, ok := mybtf.UnderlyingType(typ).(*btf.Int)
		test.AssertTrue(t, ok)
		test.AssertEqual(t, intType.Name, "long long int")
		test.AssertEqual(t, intType.Size, 8)
		test.AssertEqual(t, intType.Encoding, btf.Signed)
	})

	t.Run("(unsigned long)skb->head", func(t *testing.T) {
		expr, err := cc.ParseExpr("(unsigned long)skb->head")
		test.AssertNoErr(t, err)

		typ, err := c.cc2btf(expr)
		test.AssertNoErr(t, err)

		intType, ok := mybtf.UnderlyingType(typ).(*btf.Int)
		test.AssertTrue(t, ok)
		test.AssertEqual(t, intType.Name, "long unsigned int")
		test.AssertEqual(t, intType.Size, 8)
		test.AssertEqual(t, intType.Encoding, btf.Unsigned)
	})

	t.Run("(long long)skb->head", func(t *testing.T) {
		expr, err := cc.ParseExpr("(long long)skb->head")
		test.AssertNoErr(t, err)

		typ, err := c.cc2btf(expr)
		test.AssertNoErr(t, err)

		intType, ok := mybtf.UnderlyingType(typ).(*btf.Int)
		test.AssertTrue(t, ok)
		test.AssertEqual(t, intType.Name, "long long int")
		test.AssertEqual(t, intType.Size, 8)
		test.AssertEqual(t, intType.Encoding, btf.Signed)
	})

	t.Run("(unsigned long long)skb->head", func(t *testing.T) {
		expr, err := cc.ParseExpr("(unsigned long long)skb->head")
		test.AssertNoErr(t, err)

		typ, err := c.cc2btf(expr)
		test.AssertNoErr(t, err)

		intType, ok := mybtf.UnderlyingType(typ).(*btf.Int)
		test.AssertTrue(t, ok)
		test.AssertEqual(t, intType.Name, "long long unsigned int")
		test.AssertEqual(t, intType.Size, 8)
		test.AssertEqual(t, intType.Encoding, btf.Unsigned)
	})

	t.Run("(enum XXX)skb->head", func(t *testing.T) {
		expr, err := cc.ParseExpr("(enum XXX)skb->head")
		test.AssertNoErr(t, err)

		_, err = c.cc2btf(expr)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "failed to find type")
	})
}

func TestExtractEnum(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("not enum", func(t *testing.T) {
		_, err := c.extractEnum(&btf.Int{}, "")
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "type Int[unsigned size=0] is not an enum")
	})

	t.Run("valid enum", func(t *testing.T) {
		progType := getBpfProgTypeBtf(t)
		enum, err := c.extractEnum(progType, "BPF_PROG_TYPE_XDP")
		test.AssertNoErr(t, err)
		test.AssertEqual(t, enum, 6)
	})

	t.Run("invalid enum", func(t *testing.T) {
		progType := getBpfProgTypeBtf(t)
		_, err := c.extractEnum(progType, "BPF_PROG_TYPE_INVALID")
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "enum 'BPF_PROG_TYPE_INVALID' not found in type")
	})
}
