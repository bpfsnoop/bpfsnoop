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
	configFlagIsFsessionIdx
)

type BpfsnoopConfig struct {
	Flags     uint32
	FilterPid uint32
	FnArgsNr  uint32
	WithRet   bool
	Pad       [3]uint8
	FnArgsBuf uint32
	ArgDataSz uint32
}

func (cfg *BpfsnoopConfig) setFlags(v bool, idx int) {
	if v {
		cfg.Flags |= 1 << idx
	}
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

func (cfg *BpfsnoopConfig) SetOutputArg(v bool) {
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

func (cfg *BpfsnoopConfig) SetIsFsession(v bool) {
	cfg.setFlags(v, configFlagIsFsessionIdx)
}
