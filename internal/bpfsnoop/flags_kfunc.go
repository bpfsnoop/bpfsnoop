// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"fmt"
	"strings"
)

type KfuncFlag struct {
	name string
	arg  string
	typ  string
	insn bool
	progFlagImmInfo
}

func parseKfuncFlag(k string) (KfuncFlag, error) {
	skbMode := false
	var kf KfuncFlag

	for strings.HasPrefix(k, "(") {
		if strings.HasPrefix(k, "(i)") {
			kf.insn = true
			k = k[3:]
		}
		if strings.HasPrefix(k, "(g)") {
			kf.graph = true
			k = k[3:]
		}
		if strings.HasPrefix(k, "(s)") {
			kf.stack = true
			k = k[3:]
		}
		if strings.HasPrefix(k, "(l)") {
			kf.lbr = true
			k = k[3:]
		}
		if strings.HasPrefix(k, "(b)") {
			kf.both = true
			k = k[3:]
		}
		if strings.HasPrefix(k, "(p)") {
			kf.pkt = true
			k = k[3:]
		}
		if strings.HasPrefix(k, "(m)") {
			kf.multi = true
			k = k[3:]
		}
		if strings.HasPrefix(strings.ToLower(k), "(skb)") {
			skbMode = true
			k = k[5:]
		}
	}
	if skbMode {
		kf.arg = "skb"
		kf.typ = "struct sk_buff *"
	}
	kf.fltrExpr = k
	kf.insn = kf.insn || outputFuncInsns
	kf.graph = kf.graph || outputFuncGraph
	kf.stack = kf.stack || outputFuncStack
	kf.lbr = kf.lbr || outputLbr
	kf.both = kf.both || (hasModeEntry() && hasModeExit())
	kf.pkt = kf.pkt || outputPkt
	if kf.insn && kf.graph {
		return kf, fmt.Errorf("kfunc %s cannot be traced with both insn and graph", k)
	}
	if kf.multi && kf.insn {
		return kf, fmt.Errorf("kfunc %s cannot be traced with both multi and insn", k)
	}

	fields := strings.Split(k, ":")
	switch len(fields) {
	case 1:
		kf.name = strings.TrimSpace(fields[0])

	case 2:
		kf.name = strings.TrimSpace(fields[0])
		kf.arg = strings.TrimSpace(fields[1])

		// Check if arg has type info. The type info is enclosed in parentheses.
		if kf.arg != "" && kf.arg[0] == '(' {
			typ, err := getTypeDescFrom(kf.arg)
			if err != nil {
				return kf, err
			}
			kf.typ = strings.TrimSpace(typ)
			kf.arg = strings.TrimSpace(kf.arg[len(typ)+2:])
		}

	case 3:
		kf.name = strings.TrimSpace(fields[0])
		kf.arg = strings.TrimSpace(fields[1])
		kf.typ = strings.TrimSpace(fields[2])

	default:
		return kf, fmt.Errorf("invalid kfunc flag: %s", k)
	}

	if kf.multi && kf.typ == "" {
		return kf, fmt.Errorf("multi mode requires typed argument, e.g. '(m)*:(struct sk_buff *)skb', got '%s'", k)
	}

	if kf.multi {
		kf.argName = kf.arg
		kf.argType = kf.typ
	}

	return kf, nil
}

func parseKfuncFlags(kfs []string) ([]KfuncFlag, error) {
	var kflags []KfuncFlag
	for _, k := range kfs {
		kf, err := parseKfuncFlag(k)
		if err != nil {
			return nil, err
		}
		kflags = append(kflags, kf)
	}

	return kflags, nil
}
