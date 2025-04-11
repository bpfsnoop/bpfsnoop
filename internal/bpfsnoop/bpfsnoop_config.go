// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

const (
	configFlagOutputLbrIdx = 0 + iota
	configFlagOutputStackIdx
	configFlagOutputPktIdx
	configFlagOutputArgIdx
	configFlagBothEntryExitIdx
	configFlagIsEntryIdx
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
		cfg.Flags |= 1 << configFlagOutputLbrIdx
	}
}

func (cfg *BpfsnoopConfig) SetOutputStack(v bool) {
	if v {
		cfg.Flags |= 1 << configFlagOutputStackIdx
	}
}

func (cfg *BpfsnoopConfig) SetOutputPktTuple(v bool) {
	if v {
		cfg.Flags |= 1 << configFlagOutputPktIdx
	}
}

func (cfg *BpfsnoopConfig) SetOutputArgData(v bool) {
	if v {
		cfg.Flags |= 1 << configFlagOutputArgIdx
	}
}

func (cfg *BpfsnoopConfig) SetBothEntryExit(v bool) {
	if v {
		cfg.Flags |= 1 << configFlagBothEntryExitIdx
	}
}

func (cfg *BpfsnoopConfig) SetIsEntry(v bool) {
	if v {
		cfg.Flags |= 1 << configFlagIsEntryIdx
	}
}
