// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"structs"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"
)

// progInfo contains tracing metadata without either instruction stream.
type progInfo struct {
	Type ebpf.ProgramType
	Tag  string

	id             ebpf.ProgramID
	btfID          btf.ID
	funcInfos      []byte
	lineInfos      []byte
	jitedKsyms     []uint64
	jitedFuncLens  []uint32
	jitedLineInfos []uint64
	btfOnce        sync.Once
	btfSpec        *btf.Spec
	btfErr         error
}

// bpfProgInfoRaw is the bpf_prog_info UAPI prefix through the BTF/JIT
// record sizes. Instruction pointers and lengths stay zero on the data call.
type bpfProgInfoRaw struct {
	_                    structs.HostLayout
	Type                 uint32
	ID                   uint32
	Tag                  [8]byte
	JitedProgLen         uint32
	XlatedProgLen        uint32
	JitedProgInsns       uint64
	XlatedProgInsns      uint64
	LoadTime             uint64
	CreatedByUID         uint32
	NrMapIDs             uint32
	MapIDs               uint64
	Name                 [16]byte
	Ifindex              uint32
	_                    [4]byte /* unsupported bitfield */
	NetnsDev             uint64
	NetnsIno             uint64
	NrJitedKsyms         uint32
	NrJitedFuncLens      uint32
	JitedKsyms           uint64
	JitedFuncLens        uint64
	BTFID                uint32
	FuncInfoRecSize      uint32
	FuncInfo             uint64
	NrFuncInfo           uint32
	NrLineInfo           uint32
	LineInfo             uint64
	JitedLineInfo        uint64
	NrJitedLineInfo      uint32
	LineInfoRecSize      uint32
	JitedLineInfoRecSize uint32
	NrProgTags           uint32
	ProgTags             uint64
	RunTimeNs            uint64
	RunCnt               uint64
	RecursionMisses      uint64
	VerifiedInsns        uint32
	AttachBtfObjID       uint32
	AttachBtfID          uint32
	_                    [4]byte
}

func progInfoSlicePointer[T any](slice []T) uint64 {
	return uint64(uintptr(unsafe.Pointer(unsafe.SliceData(slice))))
}

func fetchBPFProgInfo(prog *ebpf.Program) (*progInfo, error) {
	get := func(info *bpfProgInfoRaw) error {
		attr := struct {
			FD, Size uint32
			Info     unsafe.Pointer
		}{
			FD:   uint32(prog.FD()),
			Size: uint32(unsafe.Sizeof(*info)),
			Info: unsafe.Pointer(info),
		}

		_, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_OBJ_GET_INFO_BY_FD,
			uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
		if errno != 0 {
			return fmt.Errorf("failed to get BPF program info: %w", errno)
		}
		return nil
	}

	var info bpfProgInfoRaw
	if err := get(&info); err != nil {
		return nil, err
	}

	p := &progInfo{
		Type:           ebpf.ProgramType(info.Type),
		Tag:            hex.EncodeToString(info.Tag[:]),
		id:             ebpf.ProgramID(info.ID),
		btfID:          btf.ID(info.BTFID),
		funcInfos:      make([]byte, uint64(btf.FuncInfoSize)*uint64(info.NrFuncInfo)),
		lineInfos:      make([]byte, uint64(btf.LineInfoSize)*uint64(info.NrLineInfo)),
		jitedKsyms:     make([]uint64, info.NrJitedKsyms),
		jitedFuncLens:  make([]uint32, info.NrJitedFuncLens),
		jitedLineInfos: make([]uint64, info.NrJitedLineInfo),
	}

	// Use a fresh structure: feeding back the instruction lengths from the
	// first call would request instruction data that we deliberately omit.
	data := bpfProgInfoRaw{
		NrFuncInfo:           info.NrFuncInfo,
		FuncInfoRecSize:      btf.FuncInfoSize,
		FuncInfo:             progInfoSlicePointer(p.funcInfos),
		NrLineInfo:           info.NrLineInfo,
		LineInfoRecSize:      btf.LineInfoSize,
		LineInfo:             progInfoSlicePointer(p.lineInfos),
		NrJitedKsyms:         info.NrJitedKsyms,
		JitedKsyms:           progInfoSlicePointer(p.jitedKsyms),
		NrJitedFuncLens:      info.NrJitedFuncLens,
		JitedFuncLens:        progInfoSlicePointer(p.jitedFuncLens),
		NrJitedLineInfo:      info.NrJitedLineInfo,
		JitedLineInfoRecSize: uint32(unsafe.Sizeof(uint64(0))),
		JitedLineInfo:        progInfoSlicePointer(p.jitedLineInfos),
	}
	err := get(&data)
	if err != nil {
		return nil, err
	}

	// Programs are immutable, but validate returned counts before slicing.
	if data.NrFuncInfo > info.NrFuncInfo || data.NrLineInfo > info.NrLineInfo ||
		data.NrJitedKsyms > info.NrJitedKsyms || data.NrJitedFuncLens > info.NrJitedFuncLens ||
		data.NrJitedLineInfo > info.NrJitedLineInfo {
		return nil, fmt.Errorf("BPF program info grew while fetching metadata")
	}

	p.funcInfos = p.funcInfos[:uint64(data.NrFuncInfo)*uint64(btf.FuncInfoSize)]
	p.lineInfos = p.lineInfos[:uint64(data.NrLineInfo)*uint64(btf.LineInfoSize)]
	p.jitedKsyms = p.jitedKsyms[:data.NrJitedKsyms]
	p.jitedFuncLens = p.jitedFuncLens[:data.NrJitedFuncLens]
	p.jitedLineInfos = p.jitedLineInfos[:data.NrJitedLineInfo]

	// The kernel clears these pointers when raw address disclosure is denied.
	if data.JitedKsyms == 0 {
		p.jitedKsyms = nil
	}
	if data.JitedFuncLens == 0 {
		p.jitedFuncLens = nil
	}
	if data.JitedLineInfo == 0 {
		p.jitedLineInfos = nil
	}
	return p, nil
}

func (p *progInfo) ID() (ebpf.ProgramID, bool) { return p.id, p.id != 0 }
func (p *progInfo) BTFID() (btf.ID, bool)      { return p.btfID, p.btfID != 0 }

func (p *progInfo) spec() (*btf.Spec, error) {
	p.btfOnce.Do(func() {
		if p.btfID == 0 {
			p.btfErr = fmt.Errorf("program has no BTF: %w", ebpf.ErrNotSupported)
			return
		}

		handle, err := btf.NewHandleFromID(p.btfID)
		if err != nil {
			p.btfErr = err
			return
		}

		defer handle.Close()
		p.btfSpec, p.btfErr = handle.Spec(nil)
	})
	return p.btfSpec, p.btfErr
}

func (p *progInfo) FuncInfos() (btf.FuncOffsets, error) {
	if len(p.funcInfos) == 0 {
		return nil, fmt.Errorf("program has no function info: %w", ebpf.ErrNotSupported)
	}

	spec, err := p.spec()
	if err != nil {
		return nil, err
	}

	return btf.LoadFuncInfos(bytes.NewReader(p.funcInfos), binary.NativeEndian,
		uint32(len(p.funcInfos)/int(btf.FuncInfoSize)), spec)
}

func (p *progInfo) LineInfos() (btf.LineOffsets, error) {
	if len(p.lineInfos) == 0 {
		return nil, fmt.Errorf("program has no line info: %w", ebpf.ErrNotSupported)
	}

	spec, err := p.spec()
	if err != nil {
		return nil, err
	}

	return btf.LoadLineInfos(bytes.NewReader(p.lineInfos), binary.NativeEndian,
		uint32(len(p.lineInfos)/int(btf.LineInfoSize)), spec)
}

func (p *progInfo) JitedKsymAddrs() ([]uintptr, bool) {
	addrs := make([]uintptr, len(p.jitedKsyms))
	for i, addr := range p.jitedKsyms {
		addrs[i] = uintptr(addr)
	}

	return addrs, len(addrs) != 0
}

func (p *progInfo) JitedFuncLens() ([]uint32, bool) {
	return p.jitedFuncLens, len(p.jitedFuncLens) != 0
}

func (p *progInfo) JitedLineInfos() ([]uint64, bool) {
	return p.jitedLineInfos, len(p.jitedLineInfos) != 0
}
