// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

// Package atomix provides synchronization helpers.
package atomix

import "sync"

// Once runs a value-producing function at most once and caches both its value
// and error.
type Once[T any] struct {
	once sync.Once
	run  func() (T, error)
	data T
	err  error
}

// NewOnce returns a value-producing Once for run.
func NewOnce[T any](run func() (T, error)) *Once[T] {
	return &Once[T]{run: run}
}

// Do runs the function on the first call and returns its cached result on all
// calls.
func (o *Once[T]) Do() (T, error) {
	o.once.Do(func() {
		o.data, o.err = o.run()
		o.run = nil
	})
	return o.data, o.err
}
