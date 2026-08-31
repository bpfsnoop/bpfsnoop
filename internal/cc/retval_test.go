// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"strings"
	"testing"

	c2go "rsc.io/c2go/cc"
)

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
