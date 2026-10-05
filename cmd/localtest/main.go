// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/bpfsnoop/bpfsnoop/internal/assert"
)

type failedTest struct {
	file string
	testCase
}

var (
	failedTests  []failedTest
	skippedTests []failedTest
)

func main() {
	if err := detectFeatures(); err != nil {
		prErr(os.Stderr, red, "Failed to detect features: %v", err)
		os.Exit(1)
	}

	var passed bool
	defer func() {
		if !passed {
			os.Exit(1)
		}
	}()

	f := parseFlags()
	if !mcpMode {
		var err error
		cliBackend, err = startCLIWorker(os.Stdout)
		if err != nil {
			prErr(os.Stderr, red, "Failed to start CLI worker: %v\n", err)
			return
		}
		defer cliBackend.Close(os.Stdout)
	}

	if f.testFile != "" {
		w := os.Stdout
		started := time.Now()
		defer func() {
			elapsed := time.Since(started)
			fmt.Fprintln(w)
			prInfo(w, yellow, "Test file %s completed in %s\n\n", f.testFile, elapsed)
			if passed {
				prInfo(w, green, "=== ALL TESTS PASSED ===\n")
			} else {
				prErr(w, red, "=== SOME TESTS FAILED ===\n")
				printFailedTests(w)
			}
			if len(skippedTests) != 0 {
				fmt.Fprintln(w)
				prInfo(w, yellow, "=== SOME TESTS SKIPPED ===\n")
				printSkippedTests(w)
			}
		}()

		passed = testFile(w, f.testFile)
		return
	}

	if f.testDir != "" {
		w := os.Stdout
		started := time.Now()
		defer func() {
			elapsed := time.Since(started)
			fmt.Fprintln(w)
			prInfo(w, yellow, "Test dir %s completed in %s\n\n", f.testDir, elapsed)
			if passed {
				prInfo(w, green, "=== ALL TESTS PASSED ===\n")
			} else {
				prErr(w, red, "=== SOME TESTS FAILED ===\n")
				printFailedTests(w)
			}
			if len(skippedTests) != 0 {
				fmt.Fprintln(w)
				prInfo(w, yellow, "=== SOME TESTS SKIPPED ===\n")
				printSkippedTests(w)
			}
		}()

		dentries, err := os.ReadDir(f.testDir)
		assert.NoErr(err, "Failed to read test directory %s: %v", f.testDir)

		files := make([]string, 0, len(dentries))
		for _, dent := range dentries {
			if strings.HasSuffix(dent.Name(), ".txt") {
				files = append(files, dent.Name())
			}
		}
		slices.Sort(files)

		passed = true
		for i, file := range files {
			prLongSeparatorIf(w, i > 0 && testName == "")

			file = filepath.Join(f.testDir, file)
			passed = testFile(w, file) && passed
		}

		return
	}

	passed = test(os.Stdout, f.testCase)
	if !passed {
		failedTests = append(failedTests, failedTest{testCase: f.testCase})
		printFailedTests(os.Stdout)
	}
	if len(skippedTests) != 0 {
		fmt.Fprintln(os.Stdout)
		prInfo(os.Stdout, yellow, "=== SOME TESTS SKIPPED ===\n")
		printSkippedTests(os.Stdout)
	}
}

func descFailedTest(t failedTest) string {
	name := t.name
	if name == "" {
		name = "<unnamed>"
	}
	target := t.test
	if mcpMode {
		target = t.tool
	}

	var sb strings.Builder
	if t.file != "" {
		fmt.Fprintf(&sb, "- %s: ", t.file)
	} else {
		fmt.Fprintf(&sb, "- ")
	}
	fmt.Fprintf(&sb, "%s (%s)", name, target)

	if t.feature != nil {
		fmt.Fprintf(&sb, " (feat: %v)", t.feature)
	}

	if t.hint != "" {
		fmt.Fprintf(&sb, " (hint: %s)", t.hint)
	}

	return sb.String()
}

func printFailedTests(w io.Writer) {
	if len(failedTests) == 0 {
		return
	}

	fmt.Fprintln(w)
	prErr(w, red, "Failed tests:\n")
	for _, failed := range failedTests {
		prErr(w, red, "%s\n", descFailedTest(failed))
	}
}

func printSkippedTests(w io.Writer) {
	if len(skippedTests) == 0 {
		return
	}

	prInfo(w, yellow, "Skipped tests:\n")
	for _, skip := range skippedTests {
		prInfo(w, yellow, "%s\n", descFailedTest(skip))
	}
}
