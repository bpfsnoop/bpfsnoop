// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"log"

	"github.com/fatih/color"
)

func VerboseLog(format string, args ...any) {
	if verbose {
		log.Printf(format, args...)
	}
}

func verboseLogIf(cond bool, format string, args ...any) {
	if cond && verbose {
		log.Printf(format, args...)
	}
}

func DebugLog(format string, args ...any) {
	if debugLog {
		log.Printf(format, args...)
	}
}

func debugLogIf(cond bool, format string, args ...any) {
	if cond && debugLog {
		log.Printf(format, args...)
	}
}

func WarnLog(format string, args ...any) {
	log.Print(color.New(color.FgRed, color.Bold).Sprintf("WARNING: "+format, args...))
}

func WarnLogIf(cond bool, format string, args ...any) {
	if cond {
		WarnLog(format, args...)
	}
}

func LogIf(cond bool, format string, args ...any) {
	if cond {
		log.Printf(format, args...)
	}
}
