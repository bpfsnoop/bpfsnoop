// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"errors"
	"iter"
	"testing"

	"github.com/bpfsnoop/bpfsnoop/internal/test"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// Spec allows querying a set of Types and loading the set into the
// kernel.
type Spec struct {
	*btf.Spec
	t *testing.T

	anyTypeByName func(name string) (btf.Type, error)
	typeID        func(t btf.Type) (btf.TypeID, error)
}

func (s *Spec) notFoundErr(name string) (btf.Type, error) {
	return nil, btf.ErrNotFound
}

func (s *Spec) err(name string) (btf.Type, error) {
	return nil, errors.New("btf spec is nil")
}

func (s *Spec) notFunc(name string) (btf.Type, error) {
	return getSkbBtf(s.t), nil
}

func (s *Spec) AnyTypeByName(name string) (btf.Type, error) {
	if s.anyTypeByName != nil {
		return s.anyTypeByName(name)
	}
	return s.Spec.AnyTypeByName(name)
}

func (s *Spec) getTypeIDErr(t btf.Type) (btf.TypeID, error) {
	return 0, errors.New("injected TypeID lookup failure")
}

func (s *Spec) TypeID(t btf.Type) (btf.TypeID, error) {
	if s.typeID != nil {
		return s.typeID(t)
	}
	return s.Spec.TypeID(t)
}

func (s *Spec) All() iter.Seq2[btf.Type, error] {
	return s.Spec.All()
}

func newSpec(t *testing.T, s *btf.Spec) *Spec {
	return &Spec{
		t:    t,
		Spec: s,
	}
}

func (c *compiler) setBtfIDErr(t *testing.T) {
	c.memMode = MemoryReadModeCoreRead

	spec := newSpec(t, testBtf)
	spec.typeID = spec.getTypeIDErr
	c.btfSpec = spec
}

func TestNewCompiler(t *testing.T) {
	const reg = asm.R8

	opts := CompileExprOptions{
		Expr:      "skb->len == 0",
		LabelExit: "__label_exit",
		Spec:      testBtf,
		Kernel:    testBtf,
	}

	t.Run("empty expr", func(t *testing.T) {
		_, err := newCompiler(CompileExprOptions{
			Expr:      "",
			LabelExit: "__label_exit",
			Spec:      testBtf,
		})
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "expression and label exit cannot be empty")
	})

	t.Run("empty btf spec", func(t *testing.T) {
		_, err := newCompiler(CompileExprOptions{
			Expr:      "skb->len == 0",
			LabelExit: "__label_exit",
			Spec:      nil,
		})
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "btf spec cannot be empty")
	})

	t.Run("bpf_rdonly_cast not found", func(t *testing.T) {
		_, err := testBtf.AnyTypeByName(kfuncBpfRdonlyCast)
		test.AssertNoErr(t, err)

		spec := newSpec(t, testBtf)
		spec.anyTypeByName = spec.notFoundErr

		opts.Kernel = spec
		defer func() { opts.Kernel = testBtf }()

		c, err := newCompiler(opts)
		test.AssertNoErr(t, err)
		test.AssertFalse(t, c.rdonlyCastFastcall)
	})

	t.Run("bpf_rdonly_cast find kfunc failure", func(t *testing.T) {
		_, err := testBtf.AnyTypeByName(kfuncBpfRdonlyCast)
		test.AssertNoErr(t, err)

		spec := newSpec(t, testBtf)
		spec.anyTypeByName = spec.err

		opts.Kernel = spec
		defer func() { opts.Kernel = testBtf }()

		_, err = newCompiler(opts)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "failed to find kfunc")
	})

	t.Run("bpf_rdonly_cast not a function", func(t *testing.T) {
		_, err := testBtf.AnyTypeByName(kfuncBpfRdonlyCast)
		test.AssertNoErr(t, err)

		spec := newSpec(t, testBtf)
		spec.anyTypeByName = spec.notFunc

		opts.Kernel = spec
		defer func() { opts.Kernel = testBtf }()

		_, err = newCompiler(opts)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "bpf_rdonly_cast should be a function")
	})

	t.Run("bpf_rdonly_cast type ID not found", func(t *testing.T) {
		_, err := testBtf.AnyTypeByName(kfuncBpfRdonlyCast)
		test.AssertNoErr(t, err)

		spec := newSpec(t, testBtf)
		spec.typeID = func(btf.Type) (btf.TypeID, error) {
			return 0, btf.ErrNotFound
		}

		opts.Kernel = spec
		defer func() { opts.Kernel = testBtf }()

		_, err = newCompiler(opts)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "failed to get type ID for kfunc bpf_rdonly_cast")
		test.AssertTrue(t, errors.Is(err, btf.ErrNotFound))
	})

	c, err := newCompiler(opts)
	test.AssertNoErr(t, err)
	test.AssertFalse(t, c.rdonlyCastFastcall)
}

func TestFindType(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("btf spec", func(t *testing.T) {
		typ, err := c.findType("sk_buff")
		test.AssertNoErr(t, err)
		test.AssertNotNil(t, typ)
		strct, ok := typ.(*btf.Struct)
		test.AssertTrue(t, ok)
		test.AssertEqual(t, strct.Name, "sk_buff")
	})

	t.Run("kernel spec", func(t *testing.T) {
		_, err := c.findType("not_found")
		test.AssertHaveErr(t, err)
		test.AssertIsErr(t, err, btf.ErrNotFound)
	})
}
