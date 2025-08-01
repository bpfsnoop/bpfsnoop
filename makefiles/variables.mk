# Copyright 2025 Leon Hwang.
# SPDX-License-Identifier: Apache-2.0


CMD_BPFTOOL ?= bpftool
CMD_CC ?= clang
CMD_CD ?= cd
CMD_CHECKSUM ?= sha256sum
CMD_CP ?= cp
CMD_CXX ?= clang++
CMD_IP ?= ip
CMD_GH ?= gh
CMD_MV ?= mv
CMD_TAR ?= tar
CMD_GIT ?= git
CMD_GIT_MODULES ?= $(CMD_GIT) submodule

DIR_BIN := ./bin
DIR_BPF := ./internal/bpf
DIR_MUSL := $(CURDIR)/lib/musl

UNAME_ARCH := $(shell uname -m)

GOBUILD := go build -v -trimpath
GOBUILD_CGO_CC := CC=$(CMD_CC) CXX=$(CMD_CXX)
GOBUILD_CGO_CFLAGS_MUSL := -I$(DIR_MUSL)/include -I$(DIR_MUSL)/obj/include -I$(DIR_MUSL)/arch/generic  -I$(DIR_MUSL)/arch/$(UNAME_ARCH) -Wno-error=bitwise-op-parentheses -Wno-error=shift-op-parentheses
GOBUILD_CGO_CFLAGS := CGO_CFLAGS='-O2 -I$(CURDIR)/lib/capstone/include -I$(CURDIR)/lib/libpcap $(GOBUILD_CGO_CFLAGS_MUSL)'
GOBUILD_CGO_LDFLAGS := CGO_LDFLAGS='-O2 -g -L$(CURDIR)/lib/capstone/build -lcapstone -L$(CURDIR)/lib/libpcap -lpcap -L$(CURDIR)/lib/musl/lib -lc -lresolv -static'

ifeq ($(UNAME_ARCH),x86_64)
	TARGET_ARCH := x86
else ifeq ($(UNAME_ARCH),aarch64)
	TARGET_ARCH := arm64
else
	$(error Unsupported architecture: $(UNAME_ARCH).)
endif

GO_RUN_BPF2GO := go run github.com/cilium/ebpf/cmd/bpf2go -cc clang
BPF2GO := cd $(DIR_BPF) && $(GO_RUN_BPF2GO) -go-package bpf
BPF2GO_EXTRA_FLAGS := -g -D__TARGET_ARCH_$(TARGET_ARCH) -I$(CURDIR)/bpf -I$(CURDIR)/bpf/headers -I$(CURDIR)/lib/libbpf/src -Wno-address-of-packed-member -Wall

BPFSNOOP_BPF_OBJ := $(DIR_BPF)/bpfsnoop_bpfel.o $(DIR_BPF)/bpfsnoop_bpfeb.o
BPFSNOOP_BPF_SRC := bpf/bpfsnoop.c $(wildcard bpf/*.h) $(wildcard bpf/headers/*.h)

INSN_BPF_OBJ := $(DIR_BPF)/insn_bpfel.o $(DIR_BPF)/insn_bpfeb.o
INSN_BPF_SRC := bpf/bpfsnoop_insn.c bpf/bpfsnoop_event.h bpf/bpfsnoop_sess.h

GRAPH_BPF_OBJ := $(DIR_BPF)/graph_bpfel.o $(DIR_BPF)/graph_bpfeb.o
GRAPH_BPF_SRC := bpf/bpfsnoop_fgraph.c bpf/bpfsnoop_event.h bpf/bpfsnoop_sess.h bpf/bpfsnoop_fn_args_output.h

FEAT_BPF_OBJ := $(DIR_BPF)/feat_bpfel.o $(DIR_BPF)/feat_bpfeb.o
FEAT_BPF_SRC := bpf/feature.c

TRACEABLE_BPF_OBJ := $(DIR_BPF)/traceable_bpfel.o $(DIR_BPF)/traceable_bpfeb.o
TRACEABLE_BPF_SRC := bpf/traceable.c

TRACEPOINT_BPF_OBJ := $(DIR_BPF)/tracepoint_bpfel.o $(DIR_BPF)/tracepoint_bpfeb.o
TRACEPOINT_BPF_SRC := bpf/tracepoint.c

TRACEPOINT_MODULE_BPF_OBJ := $(DIR_BPF)/tracepoint_module_bpfel.o $(DIR_BPF)/tracepoint_module_bpfeb.o
TRACEPOINT_MODULE_BPF_SRC := bpf/tracepoint_module.c

READ_BPF_OBJ := $(DIR_BPF)/read_bpfel.o $(DIR_BPF)/read_bpfeb.o
READ_BPF_SRC := bpf/read.c

TAILCALL_BPF_OBJ := $(DIR_BPF)/tailcall_bpfel.o $(DIR_BPF)/tailcall_bpfeb.o
TAILCALL_BPF_SRC := bpf/tailcall.c

BPF_OBJS := $(BPFSNOOP_BPF_OBJ) \
			$(INSN_BPF_OBJ) \
			$(GRAPH_BPF_OBJ) \
			$(READ_BPF_OBJ) \
			$(FEAT_BPF_OBJ) \
			$(TAILCALL_BPF_OBJ) \
			$(TRACEABLE_BPF_OBJ) \
			$(TRACEPOINT_BPF_OBJ) \
			$(TRACEPOINT_MODULE_BPF_OBJ)

BPFSNOOP_OBJ := bpfsnoop
BPFSNOOP_SRC := $(shell find internal -type f -name '*.go') main.go
BPFSNOOP_CSM := $(BPFSNOOP_OBJ).sha256sum
RELEASE_NOTES ?= release_notes.txt

LIBCAPSTONE_OBJ := lib/capstone/build/libcapstone.a

LIBPCAP_OBJ := lib/libpcap/libpcap.a

LIBC_OBJ := lib/musl/lib/libc.a

LIBBPF_OBJ := lib/libbpf/src

VMLINUX_OBJ := $(CURDIR)/bpf/headers/vmlinux.h

GIT_MODULES_DIR := .git/modules

LOCALTEST_OBJ := localtest
LOCALTEST_SRC := $(shell find ./cmd/localtest/ -type f -name '*.go')

XDPCRC_DIR := ./cmd/xdpcrc
XDPCRC_BPF_OBJ := $(XDPCRC_DIR)/xdp_bpfel.o $(DIR_BPF)/xdp_bpfeb.o
XDPCRC_OBJ := xdpcrc
XDPCRC_SRC := $(wildcard $(XDPCRC_DIR)/cmd/xdpcrc/*.go) $(wildcard $(XDPCRC_DIR)/cmd/xdpcrc/*.c)
