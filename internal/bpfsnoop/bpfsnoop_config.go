// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

const (
	lbrConfigFlagOutputLbrIdx = 0 + iota
	lbrConfigFlagOutputStackIdx
	lbrConfigFlagOutputPktIdx
	lbrConfigFlagOutputArgIdx
)

type BpfsnoopConfig struct {
	Flags     uint32
	FilterPid uint32
	FnArgs    [MAX_BPF_FUNC_ARGS]ParamFlags
	FnArgsNr  uint32
	FnRet     ParamFlags
	WithRet   bool
	Pad       uint8
}

func (cfg *BpfsnoopConfig) SetOutputLbr(v bool) {
	if v {
		cfg.Flags |= 1 << lbrConfigFlagOutputLbrIdx
	}
}

func (cfg *BpfsnoopConfig) SetOutputStack(v bool) {
	if v {
		cfg.Flags |= 1 << lbrConfigFlagOutputStackIdx
	}
}

func (cfg *BpfsnoopConfig) SetOutputPktTuple(v bool) {
	if v {
		cfg.Flags |= 1 << lbrConfigFlagOutputPktIdx
	}
}

func (cfg *BpfsnoopConfig) SetOutputArgData(v bool) {
	if v {
		cfg.Flags |= 1 << lbrConfigFlagOutputArgIdx
	}
}
