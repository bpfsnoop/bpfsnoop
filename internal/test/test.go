// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"reflect"
	"strings"
	"testing"
)

func AssertEqual[T comparable](t *testing.T, got, want T) {
	t.Helper()
	if got != want {
		t.Errorf("got %v, want %v", got, want)
	}
}

func AssertEqualSlice[T comparable](t *testing.T, got, want []T) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("got %v, want %v", got, want)
	}

	for i := range got {
		if i >= len(want) {
			break
		}
		if !reflect.DeepEqual(got[i], want[i]) {
			t.Errorf("idx %d: got %v, want %v", i, got[i], want[i])
			break
		}
	}
}

func AssertEmptySlice[T any](t *testing.T, got []T) {
	t.Helper()
	if len(got) != 0 {
		t.Errorf("got %v, want empty", got)
	}
}

func AssertStrPrefix(t *testing.T, got, prefix string) {
	t.Helper()
	if !strings.HasPrefix(got, prefix) {
		t.Errorf("got %v, want prefix %v", got, prefix)
	}
}

func AssertTrue(t *testing.T, got bool) {
	t.Helper()
	if !got {
		t.Errorf("got false, want true")
	}
}

func AssertFalse(t *testing.T, got bool) {
	t.Helper()
	if got {
		t.Errorf("got true, want false")
	}
}

func AssertNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
		t.FailNow()
	}
}

func AssertHaveErr(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Errorf("expected error, but got nil")
		t.FailNow()
	}
}

func AssertPanic(t *testing.T, f func()) {
	t.Helper()
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected panic, but got nil")
		}
	}()

	f()
}
