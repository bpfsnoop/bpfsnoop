// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"time"

	flag "github.com/spf13/pflag"
	"golang.org/x/sys/unix"
)

var (
	colorful bool
	mcpMode  bool
	testName string
)

type flags struct {
	noColor bool

	testCase

	testFile string
	testDir  string
}

func parseFlags() *flags {
	var f flags

	flag.BoolVar(&f.noColor, "no-color", false, "disable colored output")
	flag.BoolVar(&mcpMode, "mcp", false, "run test cases as MCP tool calls")
	flag.StringVar(&f.tag, "tag", "", "tags for the test case")
	flag.StringVar(&f.test, "test", "", "test case to run")
	flag.StringVar(&f.tool, "tool", "", "MCP tool to call")
	flag.StringVar(&f.arguments, "arguments", "{}", "JSON arguments for the MCP tool")
	flag.BoolVar(&f.expectError, "expect-error", false, "expect the MCP tool to return an error")
	flag.StringVar(&f.match, "match", "", "match test case stderr/stdout output")
	flag.DurationVar(&f.timeout, "timeout", 5*time.Second, "timeout for the test case")
	flag.StringVar(&f.requiredProcess, "required-process", "", "required process to run the test case")
	flag.StringVar(&f.triggerProcess, "trigger-process", "", "process to trigger the test case")

	flag.StringVar(&testName, "name", "", "name of the test case to run in the file or directory")
	flag.StringVar(&f.testFile, "test-file", "", "test the cases in the specified file")
	flag.StringVar(&f.testDir, "test-dir", "", "test the cases in the specified directory")

	flag.Parse()

	f.noColor = f.noColor || !isatty(os.Stdout.Fd())
	colorful = !f.noColor

	return &f
}

// isatty checks if the given file descriptor is a terminal (TTY).
func isatty(fd uintptr) bool {
	// Attempt to get terminal attributes for the file descriptor using IoctlGetTermios.
	// If the call succeeds (err is nil), the file descriptor is a TTY.
	_, err := unix.IoctlGetTermios(int(fd), unix.TCGETS)
	return err == nil
}
