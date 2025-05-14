// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import "errors"

var (
	ErrNotImplemented    = errors.New("not implemented")
	ErrRegisterNotEnough = errors.New("not enough registers")
	ErrVarNotFound       = errors.New("not found variable")
	ErrBtfNotFound       = errors.New("not found btf type")
)
