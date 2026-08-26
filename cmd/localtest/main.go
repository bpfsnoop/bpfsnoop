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

var failedTests []failedTest

func main() {
	var passed bool
	defer func() {
		if !passed {
			os.Exit(1)
		}
	}()

	f := parseFlags()

	if f.testFile != "" {
		w := os.Stdout
		started := time.Now()
		defer func() {
			elapsed := time.Since(started)
			fmt.Fprintln(w)
			prInfo(w, yellow, "Test file %s completed in %s\n", f.testFile, elapsed)
			if passed {
				prInfo(w, green, "=== ALL TESTS PASSED ===\n")
			} else {
				prErr(w, red, "=== SOME TESTS FAILED ===\n")
				printFailedTests(w)
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
			prInfo(w, yellow, "Test dir %s completed in %s\n", f.testDir, elapsed)
			if passed {
				prInfo(w, green, "=== ALL TESTS PASSED ===\n")
			} else {
				prErr(w, red, "=== SOME TESTS FAILED ===\n")
				printFailedTests(w)
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
			i++

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
}

func printFailedTests(w io.Writer) {
	if len(failedTests) == 0 {
		return
	}

	fmt.Fprintln(w)
	prErr(w, red, "Failed tests:\n")
	for _, failed := range failedTests {
		name := failed.name
		if name == "" {
			name = "<unnamed>"
		}
		if failed.file != "" {
			prErr(w, red, "- %s: %s (%s)\n", failed.file, name, failed.test)
		} else {
			prErr(w, red, "- %s (%s)\n", name, failed.test)
		}
	}
}
