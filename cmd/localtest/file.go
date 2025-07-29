// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"
)

func parseTestCase(scanner *bufio.Scanner) (testCase, bool, error) {
	var t testCase
	t.reset()

	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue // Skip empty lines and comments
		}
		if strings.HasPrefix(line, "---") {
			return t, true, nil // End of test case
		}

		a, b, ok := strings.Cut(line, ":")
		if !ok {
			return t, false, fmt.Errorf("invalid test case format: %s", line)
		}

		a, b = strings.TrimSpace(a), strings.TrimSpace(b)
		switch a {
		case "name":
			t.name = b
			continue

		case "tag":
			t.tag = b
			continue

		case "test":
			t.test = "./bpfsnoop " + b
			continue

		case "match", "match_" + runtime.GOARCH:
			t.match = b
			continue

		case "timeout":
			var err error
			t.timeout, err = time.ParseDuration(b)
			if err != nil {
				return t, false, fmt.Errorf("invalid timeout: %s", b)
			}
			continue

		case "prerequisite":
			t.requiredProcess = b
			continue

		case "trigger":
			t.triggerProcess = b
			continue

		default:
			if strings.HasPrefix(a, "match_") {
				continue
			}
			return t, false, fmt.Errorf("unknown field: %s", a)
		}
	}

	return t, false, scanner.Err()
}

func testFile(w io.Writer, file string) bool {
	fd, err := os.Open(file)
	if err != nil {
		prErr(w, red, "Failed to open file %s: %v\n", file, err)
		return false
	}
	defer fd.Close()
	prInfo(w, yellow, "Testing file: %s\n\n", file)

	scanner := bufio.NewScanner(fd)
	passed := true
	next := true
	var i int
	for next {
		var t testCase
		t, next, err = parseTestCase(scanner)
		if err != nil {
			prErr(w, red, "Failed to parse test case in file %s: %v\n", file, err)
			return false
		}

		if !t.valid() {
			prErr(w, red, "Invalid test case in file %s: %+v\n", file, t)
			return false
		}

		prSeparatorIf(w, i != 0 && testName == "")
		i++

		if testName == "" || testName == t.name {
			passed = test(w, t) && passed
		}
	}

	return passed
}
