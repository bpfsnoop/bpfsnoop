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
	configFlagIsSessionIdx
	configFlagInsnModeIdx
	configFlagGraphModeIdx
	configFlagIsTpIdx
	configFlagIsProgIdx
	configFlagKmultiModeIdx
)

const (
	traceeFlagOutputLbr   = uint32(1 << configFlagOutputLbrIdx)
	traceeFlagOutputStack = uint32(1 << configFlagOutputStackIdx)
	traceeFlagOutputPkt   = uint32(1 << configFlagOutputPktIdx)
	traceeFlagBothMode    = uint32(1 << configFlagBothEntryExitIdx)
	traceeFlagSession     = uint32(1 << configFlagIsSessionIdx)
	traceeFlagInsnMode    = uint32(1 << configFlagInsnModeIdx)
	traceeFlagGraphMode   = uint32(1 << configFlagGraphModeIdx)
	traceeFlagIsTp        = uint32(1 << configFlagIsTpIdx)
	traceeFlagIsProg      = uint32(1 << configFlagIsProgIdx)
	traceeFlagKmultiMode  = uint32(1 << configFlagKmultiModeIdx)
)

type BpfsnoopConfig struct {
	Flags            uint32
	FilterPid        uint32
	FnArgsNr         uint32
	WithRet          bool
	Pad              [3]uint8
	FnArgsBuf        uint32
	ArgDataSz        uint32
	TraceeArgEntrySz uint32
	TraceeArgExitSz  uint32
	TraceeArgDataSz  uint32
}

func haveFlag(flags, flag uint32) bool {
	return flags&flag != 0
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

func (cfg *BpfsnoopConfig) SetIsSession(v bool) {
	cfg.setFlags(v, configFlagIsSessionIdx)
}

func (cfg *BpfsnoopConfig) SetInsnMode(v bool) {
	cfg.setFlags(v, configFlagInsnModeIdx)
}

func (cfg *BpfsnoopConfig) SetGraphMode(v bool) {
	cfg.setFlags(v, configFlagGraphModeIdx)
}

func (cfg *BpfsnoopConfig) SetIsTp(v bool) {
	cfg.setFlags(v, configFlagIsTpIdx)
}

func (cfg *BpfsnoopConfig) SetIsProg(v bool) {
	cfg.setFlags(v, configFlagIsProgIdx)
}

func (cfg *BpfsnoopConfig) SetKmultiMode(v bool) {
	cfg.setFlags(v, configFlagKmultiModeIdx)
}
