# Copyright 2025 Leon Hwang.
# SPDX-License-Identifier: Apache-2.0


CMD_BPFTOOL ?= bpftool
CMD_CC ?= clang
CMD_CD ?= cd
CMD_CHECKSUM ?= sha256sum
CMD_CP ?= cp
CMD_CXX ?= clang++
CMD_GH ?= gh
CMD_MV ?= mv
CMD_TAR ?= tar

DIR_BIN := ./bin

GOBUILD := go build -v -trimpath
GOBUILD_CGO_CFLAGS := CGO_CFLAGS='-O2 -I$(CURDIR)/lib/capstone/include -I$(CURDIR)/lib/libpcap'
GOBUILD_CGO_LDFLAGS := CGO_LDFLAGS='-O2 -g -L$(CURDIR)/lib/capstone/build -lcapstone -L$(CURDIR)/lib/libpcap -lpcap -static'

GOGEN := go generate

BPF_OBJ := bpfsnoop_bpfel.o bpfsnoop_bpfeb.o feat_bpfel.o feat_bpfeb.o traceable_bpfel.o traceable_bpfeb.o
BPF_SRC := $(wildcard bpf/*.c) $(wildcard bpf/*.h) $(wildcard bpf/headers/*.h)

BPFSNOOP_OBJ := bpfsnoop
BPFSNOOP_SRC := $(shell find internal -type f -name '*.go') main.go
BPFSNOOP_CSM := $(BPFSNOOP_OBJ).sha256sum
RELEASE_NOTES ?= release_notes.txt

LIBCAPSTONE_OBJ := lib/capstone/build/libcapstone.a

LIBPCAP_OBJ := lib/libpcap/libpcap.a

VMLINUX_OBJ := $(CURDIR)/bpf/headers/vmlinux.h
