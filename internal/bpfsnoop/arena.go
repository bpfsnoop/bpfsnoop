// Copyright 2026 Liang Tang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"slices"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"

	"github.com/bpfsnoop/bpfsnoop/internal/btfx"
	"github.com/bpfsnoop/bpfsnoop/internal/cc"
)

// argArenaTag is the BTF decl tag of a func param that points into an arena,
// which __arg_arena adds.
const argArenaTag = "arg:arena"

// isArenaParam reports whether the i-th param of fn is tagged __arg_arena.
func isArenaParam(fn *btf.Func, i int) bool {
	return fn != nil && i < len(fn.ParamTags) && slices.Contains(fn.ParamTags[i], argArenaTag)
}

// withArenaParams returns a copy of arena for tracing fn, with the params of fn
// that point into the arena. They're known by their __arg_arena tag: arena
// pointers lack the address space in BTF.
func withArenaParams(arena *cc.ArenaInfo, fn *btf.Func) *cc.ArenaInfo {
	if arena == nil {
		return nil
	}

	a := *arena
	a.Params = nil
	for i, p := range fn.Type.(*btf.FuncProto).Params {
		if isArenaParam(fn, i) {
			a.Params = append(a.Params, p.Name)
		}
	}
	return &a
}

// progArena returns the arena of traced prog id, or nil if it uses none, for
// reading arena memory through the params of its funcs that point into it.
// It's looked up once, when tracing the prog.
func (p *bpfProgs) progArena(id ebpf.ProgramID) (*cc.ArenaInfo, error) {
	if arena, ok := p.arenas[id]; ok {
		return arena, nil
	}
	p.arenas[id] = nil

	info, ok := p.infos[id]
	if !ok {
		return nil, nil
	}

	m, err := info.openArena()
	if err != nil || m == nil {
		return nil, err
	}

	arena := cc.NewArenaInfo(m.FD())
	p.arenaMaps = append(p.arenaMaps, m)
	p.arenas[id] = arena

	minfo, err := m.Info()
	if err == nil {
		mapID, _ := minfo.ID()
		VerboseLog("Prog %d uses arena map %d", id, mapID)
	}
	return arena, nil
}

// markArenaPointer marks the pointer type of a value repr as __arena, e.g.
// "(struct node *)n=0x7f..." becomes "(struct node __arena *)n=0x7f...".
func markArenaPointer(s string, typ btf.Type) string {
	t := btfx.Repr(typ)
	if !strings.HasSuffix(t, "*") {
		return s
	}
	return strings.Replace(s, "("+t+")", "("+strings.TrimSuffix(t, "*")+"__arena *)", 1)
}
