// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"strconv"
	"strings"
)

func parseUnsigned(text string) (uint64, error) {
	if strings.HasPrefix(text, "0x") {
		return strconv.ParseUint(text[2:], 16, 64)
	}
	if strings.HasPrefix(text, "0o") {
		return strconv.ParseUint(text[2:], 8, 64)
	}
	if strings.HasPrefix(text, "0b") {
		return strconv.ParseUint(text[2:], 2, 64)
	}
	if strings.HasPrefix(text, "0") && len(text) > 1 {
		return strconv.ParseUint(text[1:], 8, 64)
	}
	if strings.HasPrefix(text, "'") {
		if len(text) != 3 || text[len(text)-1] != '\'' {
			return 0, strconv.ErrSyntax
		}

		r := []rune((text[1 : len(text)-1]))
		return uint64(r[0]), nil
	}
	return strconv.ParseUint(text, 10, 64)
}

func parseNumber(text string) (int64, error) {
	isMinus := strings.HasPrefix(text, "-")
	if isMinus {
		text = text[1:]
	}
	if strings.HasPrefix(text, "+") {
		text = text[1:]
	}

	n, err := parseUnsigned(text)
	if err != nil {
		return 0, err
	}
	if isMinus {
		return -int64(n), nil
	}
	return int64(n), nil
}
