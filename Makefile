# Copyright 2024 Leon Hwang.
# SPDX-License-Identifier: Apache-2.0

include makefiles/variables.mk

.DEFAULT_GOAL := $(BPFSNOOP_OBJ)

$(GIT_MODULES_DIR):
	@$(CMD_GIT_MODULES) update --init --force --recursive

$(LIBCAPSTONE_SRC) $(LIBPCAP_SRC): $(GIT_MODULES_DIR)

# Build libcapstone for static linking
$(LIBCAPSTONE_OBJ): $(LIBCAPSTONE_SRC)
	cd $(LIBCAPSTONE_DIR) && \
		CC=$(CMD_CC) CXX=$(CMD_CXX) cmake -B build \
			-DCMAKE_BUILD_TYPE=Release \
			-DCAPSTONE_ARCHITECTURE_DEFAULT=1 \
			-DCAPSTONE_BUILD_CSTOOL=0 \
			-DCMAKE_C_FLAGS="-Qunused-arguments" \
			-DCMAKE_EXE_LINKER_FLAGS="-L$(GCC_LIB_DIR)" && \
		cmake --build build -j $(CPU_CORES)

# Build libpcap for static linking
$(LIBPCAP_OBJ): $(LIBPCAP_SRC)
	cd $(LIBPCAP_DIR) && \
		./autogen.sh && \
		CC=$(CMD_CC) CXX=$(CMD_CXX) ./configure \
			--disable-rdma \
			--disable-shared \
			--disable-usb \
			--disable-netmap \
			--disable-bluetooth \
			--disable-dbus \
			--without-libnl && \
		make CFLAGS="-Qunused-arguments" -j $(CPU_CORES)

$(LIBBPF_OBJ): $(GIT_MODULES_DIR)

$(VMLINUX_OBJ): $(VMLINUX_SRC)
	$(CMD_BPFTOOL) btf dump file $< format c > $@ || \
		{ code=$$?; rm $@; exit $$code; }

# It is required to define a pattern rule to prevent bpf2go from being called twice
# when building with `make -j'.
.SECONDEXPANSION:
$(DIR_BPF)/%_bpfel.go: $(VMLINUX_OBJ) $$(BPF_OBJ_DEPS__$$*)
	cd $(DIR_BPF) && \
		$(GO_RUN_BPF2GO) -go-package bpf -makebase $(CURDIR) \
			$(MAP_OBJ_TO_STEM__$*) $(CURDIR)/bpf/$(MAP_OBJ_TO_SRC__$*).c \
			-- $(BPF2GO_EXTRA_FLAGS)

# bpf2go emits the big-endian binding together with the little-endian binding.
$(DIR_BPF)/%_bpfeb.go: $(DIR_BPF)/%_bpfel.go
	@:

$(BPFSNOOP_OBJ): $(wildcard ./internal/bpf/*bpf*.o) $(BPF_GO_SRC) $(BPFSNOOP_SRC) $(LIBCAPSTONE_OBJ) $(LIBPCAP_OBJ)
	$(GOBUILD_CGO_CFLAGS) $(GOBUILD_CGO_LDFLAGS) $(GOBUILD)

.PHONY: local_release
local_release: $(BPFSNOOP_OBJ)
	@$(CMD_CP) $(BPFSNOOP_OBJ) $(DIR_BIN)/$(BPFSNOOP_OBJ)
	$(CMD_CHECKSUM) $(BPFSNOOP_OBJ) > $(DIR_BIN)/$(BPFSNOOP_CSM)

.PHONY: clean
clean:
	rm -f $(BPF_OBJ) $(XDPCRC_BPF_OBJ) $(VMLINUX_OBJ)
	rm -f $(BPF_GO_SRC) $(BPF_GO_DEP)
	rm -f $(BPFSNOOP_OBJ) $(XDPCRC_OBJ) $(LOCALTEST_OBJ)
	rm -rf $(DIR_BIN)/*
	@touch $(DIR_BIN)/.gitkeep

.PHONY: distclean
distclean: clean
	cd $(LIBCAPSTONE_DIR) && cmake --build build --target clean || true
	cd $(LIBPCAP_DIR) && make clean || true

.PHONY: publish
publish: local_release
	@if [ -z "$(VERSION)" ]; then echo "VERSION is not set"; exit 1; fi
	$(CMD_CD) $(DIR_BIN) && $(CMD_TAR) -czf $(BPFSNOOP_OBJ)-$(VERSION)-linux-amd64.tar.gz $(BPFSNOOP_OBJ) $(BPFSNOOP_CSM) && $(CMD_CD) -
	@$(CMD_MV) $(RELEASE_NOTES) $(DIR_BIN)/$(RELEASE_NOTES)
	$(CMD_GH) release create $(VERSION) $(DIR_BIN)/$(BPFSNOOP_OBJ)-$(VERSION)-linux-amd64.tar.gz --title "bpfsnoop $(VERSION)" --notes-file $(DIR_BIN)/$(RELEASE_NOTES)

.PHONY: testcc
testcc:
	@go clean -testcache
	go test -race -timeout 60s -coverpkg=./internal/cc -coverprofile=coverage.txt -covermode atomic ./internal/cc
	go tool cover -func=coverage.txt
	@rm -f coverage.txt
	@go clean -testcache

$(LOCALTEST_OBJ): $(LOCALTEST_SRC)
	$(GOBUILD) -o $(LOCALTEST_OBJ) ./cmd/localtest

$(XDPCRC_OBJ): $(XDPCRC_SRC) $(VMLINUX_OBJ)
	cd ./cmd/xdpcrc && \
		$(GO_RUN_BPF2GO) -go-package main xdp ./xdp.c -- $(BPF2GO_EXTRA_FLAGS)
	$(GOBUILD) -o $(XDPCRC_OBJ) $(XDPCRC_DIR)

.PHONY: testlocal
testlocal: $(LOCALTEST_OBJ) $(XDPCRC_OBJ)
	@$(CMD_IP) link set dev lo up
	./$(LOCALTEST_OBJ) --test-dir ./t
