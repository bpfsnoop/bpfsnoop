// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import "errors"

var (
	ErrNotFound = errors.New("not found")
	ErrFinished = errors.New("finished")
	errSkipped  = errors.New("skipped")
)
