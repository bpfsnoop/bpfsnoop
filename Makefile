# Copyright 2024 Leon Hwang.
# SPDX-License-Identifier: Apache-2.0

include makefiles/variables.mk

.DEFAULT_GOAL := $(BPFSNOOP_OBJ)

# Build libcapstone for static linking
$(LIBCAPSTONE_OBJ):
	cd lib/capstone && \
		cmake -B build -DCMAKE_BUILD_TYPE=Release -DCAPSTONE_ARCHITECTURE_DEFAULT=1 -DCAPSTONE_BUILD_CSTOOL=0 && \
		cmake --build build

# Build libpcap for static linking
$(LIBPCAP_OBJ):
	cd lib/libpcap && \
		./autogen.sh && \
		CC=$(CMD_CC) CXX=$(CMD_CXX) ./configure --disable-rdma --disable-shared --disable-usb --disable-netmap --disable-bluetooth --disable-dbus --without-libnl && \
		make

$(VMLINUX_OBJ):
	$(CMD_BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_OBJ)

$(FEAT_BPF_OBJ): $(FEAT_BPF_SRC) $(VMLINUX_OBJ)
	$(BPF2GO) feat bpf/feature.c -- $(BPF2GO_EXTRA_FLAGS)

$(TRACEABLE_BPF_OBJ): $(TRACEABLE_BPF_SRC) $(VMLINUX_OBJ)
	$(BPF2GO) traceable bpf/traceable.c -- $(BPF2GO_EXTRA_FLAGS)

$(TRACEPOINT_BPF_OBJ): $(TRACEPOINT_BPF_SRC) $(VMLINUX_OBJ)
	$(BPF2GO) tracepoint bpf/tracepoint.c -- $(BPF2GO_EXTRA_FLAGS)

$(TRACEPOINT_MODULE_BPF_OBJ): $(TRACEPOINT_MODULE_BPF_SRC) $(VMLINUX_OBJ)
	$(BPF2GO) tracepoint_module bpf/tracepoint_module.c -- $(BPF2GO_EXTRA_FLAGS)

$(BPFSNOOP_BPF_OBJ): $(BPFSNOOP_BPF_SRC) $(VMLINUX_OBJ)
	$(BPF2GO) bpfsnoop bpf/bpfsnoop.c -- $(BPF2GO_EXTRA_FLAGS)

$(BPFSNOOP_OBJ): $(BPF_OBJS) $(BPFSNOOP_SRC) $(LIBCAPSTONE_OBJ) $(LIBPCAP_OBJ)
	$(GOBUILD_CGO_CFLAGS) $(GOBUILD_CGO_LDFLAGS) $(GOBUILD)

.PHONY: local_release
local_release: $(BPFSNOOP_OBJ)
	@$(CMD_CP) $(BPFSNOOP_OBJ) $(DIR_BIN)/$(BPFSNOOP_OBJ)
	$(CMD_CHECKSUM) $(BPFSNOOP_OBJ) > $(DIR_BIN)/$(BPFSNOOP_CSM)

.PHONY: clean
clean:
	rm -f $(BPF_OBJS)
	rm -f $(BPFSNOOP_OBJ)
	rm -rf $(DIR_BIN)/*
	@touch $(DIR_BIN)/.gitkeep

.PHONY: publish
publish: local_release
	@if [ -z "$(VERSION)" ]; then echo "VERSION is not set"; exit 1; fi
	$(CMD_TAR) -czf $(DIR_BIN)/$(BPFSNOOP_OBJ)-$(VERSION)-linux-amd64.tar.gz $(DIR_BIN)/$(BPFSNOOP_OBJ) $(DIR_BIN)/$(BPFSNOOP_CSM)
	@$(CMD_MV) $(RELEASE_NOTES) $(DIR_BIN)/$(RELEASE_NOTES)
	$(CMD_GH) release create $(VERSION) $(DIR_BIN)/$(BPFSNOOP_OBJ)-$(VERSION)-linux-amd64.tar.gz --title "BPFSNOOP $(VERSION)" --notes-file $(DIR_BIN)/$(RELEASE_NOTES)
