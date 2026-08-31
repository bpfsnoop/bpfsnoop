// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"strings"
	"testing"

	"github.com/Asphaltt/mybtf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	c2go "rsc.io/c2go/cc"
)

func requireType(t *testing.T, name string) btf.Type {
	t.Helper()
	typ, err := testBtf.AnyTypeByName(name)
	if err != nil {
		t.Fatalf("find BTF type %q: %v", name, err)
	}
	return typ
}

func TestAnalyzeRetvalExpr(t *testing.T) {
	tests := []struct {
		name     string
		expr     string
		vars     []string
		cast     string
		wantErr  string
		ordinary bool
	}{
		{name: "ordinary", expr: "retval > count", vars: []string{"count", "retval"}, ordinary: true},
		{name: "string literal", expr: `"$retval"`, wantErr: "requires an explicit concrete cast"},
		{name: "signed", expr: "(int)$retval < 0", vars: []string{RetvalName}, cast: "int"},
		{name: "unsigned", expr: "(unsigned int)$retval != 0", vars: []string{RetvalName}, cast: "uint"},
		{name: "pointer", expr: "(void *)$retval != NULL", vars: []string{RetvalName, "NULL"}, cast: "void*"},
		{name: "struct pointer", expr: "((struct sk_buff *)$retval)->len > 0", vars: []string{RetvalName}, cast: "struct sk_buff*"},
		{name: "same repeated cast", expr: "(int)$retval > 0 && (int)$retval < 10", vars: []string{RetvalName}, cast: "int"},
		{name: "qualified equivalent casts", expr: "(int)$retval > 0 && (const int)$retval < 10", vars: []string{RetvalName}, cast: "int"},
		{name: "bare", expr: "$retval != 0", wantErr: "requires an explicit concrete cast"},
		{name: "bare through parens", expr: "($retval) != 0", wantErr: "requires an explicit concrete cast"},
		{name: "member before cast", expr: "(int)$retval.foo != 0", wantErr: "requires an explicit concrete cast"},
		{name: "void cast", expr: "(void)$retval", wantErr: "invalid non-scalar cast"},
		{name: "struct value cast", expr: "(struct sk_buff)$retval", wantErr: "invalid non-scalar cast"},
		{name: "conflicting casts", expr: "(int)$retval > 0 && (unsigned int)$retval < 10", wantErr: "conflicting casts"},
		{name: "unknown dollar name", expr: "(int)$return != 0", wantErr: "failed to parse expression"},
		{name: "retval suffix", expr: "(int)$retval2 != 0", wantErr: "requires an explicit concrete cast"},
		{name: "embedded retval", expr: "x$retval != 0", wantErr: "requires an explicit concrete cast"},
		{name: "missing cast close", expr: "(int $retval != 0", wantErr: "failed to parse expression"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := AnalyzeExpr(tt.expr)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("got error %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if strings.Join(got.Vars, ",") != strings.Join(tt.vars, ",") {
				t.Fatalf("vars = %q, want %q", got.Vars, tt.vars)
			}
			if got.RetvalCast != tt.cast {
				t.Fatalf("cast = %q, want %q", got.RetvalCast, tt.cast)
			}
			if tt.ordinary && got.CompilerExpr != tt.expr {
				t.Fatalf("ordinary expression changed to %q", got.CompilerExpr)
			}
			if tt.cast != "" && !strings.Contains(got.CompilerExpr, retvalCompilerName) {
				t.Fatalf("compiler expression %q doesn't contain internal retval name", got.CompilerExpr)
			}
		})
	}
}

func TestRewriteRetval(t *testing.T) {
	expr := `"$retval"`
	got := rewriteRetval(expr)
	want := `"____retval____"`
	if got != want {
		t.Fatalf("rewrite = %q, want %q", got, want)
	}
}

func TestRetvalCTypeHelpers(t *testing.T) {
	intType := &c2go.Type{Kind: c2go.Int}
	intAlias := &c2go.Type{Kind: c2go.TypedefType, Name: "integer", Base: intType}
	opaqueAlias := &c2go.Type{Kind: c2go.TypedefType, Name: "opaque"}

	if validRetvalCast(nil) {
		t.Fatal("nil cast should be invalid")
	}
	if !validRetvalCast(opaqueAlias) || !validRetvalCast(intAlias) {
		t.Fatal("scalar typedef casts should be valid")
	}

	target := &c2go.Expr{Op: c2go.Name, Text: retvalCompilerName}
	wrapped := &c2go.Expr{Op: c2go.Paren, Left: &c2go.Expr{Op: c2go.Paren, Left: target}}
	if !enclosesThroughParens(wrapped, target) {
		t.Fatal("nested parentheses should enclose target")
	}
}

func TestSameUnderlyingRetvalType(t *testing.T) {
	intType := &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}
	uintType := &btf.Int{Name: "unsigned int", Size: 4, Encoding: btf.Unsigned}
	tests := []struct {
		name        string
		left, right btf.Type
	}{
		{name: "void", left: &btf.Void{}, right: &btf.Void{}},
		{name: "int", left: intType, right: &btf.Int{Name: "another name", Size: 4, Encoding: btf.Signed}},
		{name: "enum", left: &btf.Enum{Name: "state", Size: 4, Signed: true}, right: &btf.Enum{Name: "state", Size: 4, Signed: true}},
		{name: "float", left: &btf.Float{Name: "double", Size: 8}, right: &btf.Float{Name: "other", Size: 8}},
		{name: "pointer", left: &btf.Pointer{Target: intType}, right: &btf.Pointer{Target: &btf.Const{Type: intType}}},
		{name: "struct", left: &btf.Struct{Name: "record"}, right: &btf.Struct{Name: "record"}},
		{name: "union", left: &btf.Union{Name: "value"}, right: &btf.Union{Name: "value"}},
		{name: "fallback", left: &btf.Array{Index: uintType, Type: intType, Nelems: 2}, right: &btf.Array{Index: uintType, Type: intType, Nelems: 2}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !sameUnderlyingType(tt.left, tt.right) {
				t.Fatalf("types should match: %v and %v", tt.left, tt.right)
			}
		})
	}
}

func TestRetvalTypeMatches(t *testing.T) {
	intType := requireType(t, "int")
	uintType := requireType(t, "unsigned int")
	skbType := requireType(t, "sk_buff")

	tests := []struct {
		name string
		expr string
		ret  btf.Type
		want bool
	}{
		{name: "signed", expr: "(int)$retval == 0", ret: intType, want: true},
		{name: "nested parentheses", expr: "(int)(($retval))", ret: intType, want: true},
		{name: "signed typedef qualifier", expr: "(int)$retval == 0", ret: &btf.Const{Type: &btf.Typedef{Name: "status_t", Type: intType}}, want: true},
		{name: "signed unsigned mismatch", expr: "(int)$retval == 0", ret: uintType},
		{name: "pointer", expr: "(struct sk_buff *)$retval != NULL", ret: &btf.Pointer{Target: skbType}, want: true},
		{name: "qualified pointer target", expr: "(struct sk_buff *)$retval != NULL", ret: &btf.Pointer{Target: &btf.Const{Type: skbType}}, want: true},
		{name: "unrelated struct", expr: "(struct sk_buff *)$retval != NULL", ret: &btf.Pointer{Target: &btf.Struct{Name: "x"}}},
		{name: "pointer scalar mismatch", expr: "(struct sk_buff *)$retval != NULL", ret: intType},
		{name: "void return", expr: "(void *)$retval != NULL", ret: &btf.Void{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MatchRetvalType(tt.expr, tt.ret, testBtf, testBtf)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("match = %v, want %v", got, tt.want)
			}
		})
	}

	if got, err := MatchRetvalType("count > 0", intType, testBtf, testBtf); err != nil || got {
		t.Fatalf("expression without retval match = (%v, %v), want (false, nil)", got, err)
	}
	if _, err := MatchRetvalType("(int)$unknown", intType, testBtf, testBtf); err == nil {
		t.Fatal("invalid retval expression should fail")
	}
}

func TestPrepareRetvalCompileOptions(t *testing.T) {
	intType := requireType(t, "int")

	tests := []struct {
		name, expr string
		ret        btf.Type
		want       string
	}{
		{name: "parse error", expr: "(int)$unknown", ret: intType, want: "failed to parse expression"},
		{name: "analysis error", expr: "$retval", ret: intType, want: "requires an explicit concrete cast"},
		{name: "missing return type", expr: "(int)$retval", want: "without a declared return type"},
		{name: "resolution error", expr: "(struct type_that_does_not_exist *)$retval", ret: &btf.Pointer{Target: &btf.Struct{Name: "type_that_does_not_exist"}}, want: "failed to resolve"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := CompileFilterExpr(CompileExprOptions{
				Expr:       tt.expr,
				RetvalType: tt.ret,
				Spec:       testBtf,
				Kernel:     testBtf,
				LabelExit:  "exit",
			})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got error %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestCompileRetvalExpr(t *testing.T) {
	intType := requireType(t, "int")
	skbType := requireType(t, "sk_buff")

	t.Run("filter loads synthetic final slot", func(t *testing.T) {
		insns, err := CompileFilterExpr(CompileExprOptions{
			Expr:       "retval == 7 && (int)$retval < 0",
			Params:     []btf.FuncParam{{Name: "retval", Type: intType}},
			RetvalType: intType,
			Spec:       testBtf,
			Kernel:     testBtf,
			LabelExit:  "exit",
		})
		if err != nil {
			t.Fatal(err)
		}
		var loadsReal, loadsRetval, signExtendsRetval, signedComparison bool
		for _, insn := range insns {
			if insn.OpCode == asm.LoadMemOp(asm.DWord) && insn.Src == asm.R9 {
				loadsReal = loadsReal || insn.Offset == 0
				loadsRetval = loadsRetval || insn.Offset == 8
			}
			signExtendsRetval = signExtendsRetval || insn.OpCode == asm.ArSh.Op(asm.ImmSource) && insn.Constant == 32
			signedComparison = signedComparison || insn.OpCode.JumpOp() == asm.JSGE
		}
		if !loadsReal || !loadsRetval {
			t.Fatalf("expected distinct real and synthetic argument loads, got %v", insns)
		}
		if !signExtendsRetval || !signedComparison {
			t.Fatalf("expected signed retval extension and comparison, got %v", insns)
		}
	})

	t.Run("boolean pointer and dereference", func(t *testing.T) {
		_, err := CompileFilterExpr(CompileExprOptions{
			Expr:       "(struct sk_buff *)$retval != NULL && ((struct sk_buff *)$retval)->len > 0",
			RetvalType: &btf.Pointer{Target: skbType},
			Spec:       testBtf,
			Kernel:     testBtf,
			LabelExit:  "exit",
		})
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("eval preserves scalar type", func(t *testing.T) {
		res, err := CompileEvalExpr(CompileExprOptions{
			Expr:       "(int)$retval",
			RetvalType: &btf.Const{Type: intType},
			Spec:       testBtf,
			Kernel:     testBtf,
			LabelExit:  "exit",
		})
		if err != nil {
			t.Fatal(err)
		}
		intResult, ok := mybtf.UnderlyingType(res.Btf).(*btf.Int)
		if !ok {
			t.Fatalf("result BTF = %v, want int", res.Btf)
		}
		if intResult.Encoding != btf.Signed {
			t.Fatalf("result BTF encoding = %v, want signed", intResult.Encoding)
		}
		if len(res.Insns) == 0 || res.Insns[0].Offset != 0 {
			t.Fatalf("expected retval load from only slot, got %v", res.Insns)
		}
	})

	t.Run("eval preserves pointer type", func(t *testing.T) {
		res, err := CompileEvalExpr(CompileExprOptions{
			Expr:       "(struct sk_buff *)$retval",
			RetvalType: &btf.Pointer{Target: skbType},
			Spec:       testBtf,
			Kernel:     testBtf,
			LabelExit:  "exit",
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := mybtf.UnderlyingType(res.Btf).(*btf.Pointer); !ok {
			t.Fatalf("result BTF = %v, want pointer", res.Btf)
		}
	})

	t.Run("reject mismatched return", func(t *testing.T) {
		_, err := CompileEvalExpr(CompileExprOptions{
			Expr:       "(unsigned int)$retval",
			RetvalType: intType,
			Spec:       testBtf,
			Kernel:     testBtf,
			LabelExit:  "exit",
		})
		if err == nil || !strings.Contains(err.Error(), "does not match") {
			t.Fatalf("got error %v, want type mismatch", err)
		}
	})
}
