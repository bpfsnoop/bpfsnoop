// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"fmt"

	"github.com/Asphaltt/mybtf"
	"github.com/cilium/ebpf/btf"
	"github.com/gobwas/glob"

	"github.com/bpfsnoop/bpfsnoop/internal/btfx"
)

type kfuncMatch struct {
	flag KfuncFlag
	glob glob.Glob
}

func kfuncFlags2matches(funcs []string) ([]*kfuncMatch, error) {
	kflags, err := parseKfuncFlags(funcs)
	if err != nil {
		return nil, err
	}

	matches := make([]*kfuncMatch, 0, len(kflags))
	for _, kf := range kflags {
		g, err := glob.Compile(kf.name)
		if err != nil {
			return nil, fmt.Errorf("failed to compile glob from %s: %w", kf.name, err)
		}

		matches = append(matches, &kfuncMatch{
			flag: kf,
			glob: g,
		})
	}

	return matches, nil
}

func (m kfuncMatch) match(fn string, fp *btf.FuncProto) bool {
	if !m.glob.Match(fn) {
		return false
	}

	if m.flag.arg == "" {
		return true
	}

	for _, p := range fp.Params {
		if p.Name == m.flag.arg {
			if m.flag.typ == "" {
				return true
			}

			ptyp := btfx.Repr(mybtf.UnderlyingType(p.Type))
			return ptyp == m.flag.typ
		}
	}

	return false
}

func matchKfunc(fn string, fp *btf.FuncProto, matches []*kfuncMatch) (*kfuncMatch, bool) {
	for _, m := range matches {
		if m.match(fn, fp) {
			return m, true
		}
	}
	return nil, false
}
