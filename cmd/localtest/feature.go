// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"unsafe"
)

const (
	featLbr           = "lbr"
	featFsession      = "fsession"
	featKprobeMulti   = "kprobe.multi"
	featKprobeSession = "kprobe.session"
	featNestedTracing = "nested-tracing"
	featUnionArg      = "tracing-union-arg"
)

func haveAllFeatures(feats []string) bool {
	if len(feats) == 0 {
		return true
	}

	ff := map[string]*int8{
		featLbr:           &features.lbr,
		featFsession:      &features.fsession,
		featKprobeMulti:   &features.kprobeMulti,
		featKprobeSession: &features.kprobeSession,
		featNestedTracing: &features.nestedTracing,
		featUnionArg:      &features.tracingUnionArg,
	}

	cnt := 0
	for _, feat := range feats {
		if v, ok := ff[feat]; !ok || *v != 1 {
			return false
		}

		cnt++
	}

	return cnt == len(feats)
}

var features struct {
	ringbuf             int8 // kernel 5.8
	lbr                 int8 // kernel 6.2 on x86_64
	getStackidHelper    int8
	getFuncArgCntHelper int8 // kernel 5.17
	fsession            int8 // kernel 7.0
	kprobeMulti         int8 // kernel 5.18
	kprobeSession       int8 // kernel 6.10
	nestedTracing       int8 // kernel 6.8
	endbr               int8
	tracingUnionArg     int8 // kernel 6.18
}

func init() {
	b := unsafe.Slice(&features.ringbuf, unsafe.Sizeof(features))
	for i := range b {
		b[i] = -1
	}
}

func setFeatValue(feat *int8, v string) {
	switch strings.TrimSpace(v) {
	case "true":
		*feat = 1
	case "false":
		*feat = 0
	}
}

func detectFeatures() error {
	output, err := exec.Command("./bpfsnoop", "--detect-features").CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to ./bpfsnoop --detect-features: %w\terr:\n%s", err, string(output))
	}

	feats := map[string]*int8{
		"Ringbuf map":       &features.ringbuf,
		"Branch Record":     &features.lbr,
		"Get stackid":       &features.getStackidHelper,
		"Get arg_cnt":       &features.getFuncArgCntHelper,
		"fsession":          &features.fsession,
		"kprobe.multi":      &features.kprobeMulti,
		"kprobe.session":    &features.kprobeSession,
		"Nested tracing":    &features.nestedTracing,
		"ENDBR insn":        &features.endbr,
		"tracing union arg": &features.tracingUnionArg,
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}

		feat, ok := feats[k]
		if ok {
			setFeatValue(feat, v)
		}
	}
	return scanner.Err()
}
