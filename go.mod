module github.com/bpfsnoop/bpfsnoop

go 1.24.0

toolchain go1.24.1

require (
	github.com/Asphaltt/addr2line v0.1.2
	github.com/Asphaltt/mybtf v0.0.0-20250708022622-be6f548674b2
	github.com/bpfsnoop/gapstone v0.0.0-20250326151126-f4ba393504da
	github.com/caio/go-tdigest/v4 v4.0.1
	github.com/cilium/ebpf v0.20.0
	github.com/fatih/color v1.18.0
	github.com/gobwas/glob v0.2.3
	github.com/goccy/go-json v0.10.5
	github.com/gopacket/gopacket v1.3.1
	github.com/jschwinger233/elibpcap v1.0.1
	github.com/klauspost/compress v1.17.11
	github.com/lorenzosaino/go-sysctl v0.3.1
	github.com/spf13/pflag v1.0.5
	github.com/ulikunitz/xz v0.5.12
	golang.org/x/exp v0.0.0-20241009180824-f66d83c29e7c
	golang.org/x/sync v0.17.0
	rsc.io/c2go v0.0.0-20170620140410-520c22818a08
)

require (
	github.com/BurntSushi/toml v1.1.0 // indirect
	github.com/cloudflare/cbpfc v0.0.0-20230809125630-31aa294050ff // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	golang.org/x/exp/typeparams v0.0.0-20220613132600-b0d781184e0d // indirect
	golang.org/x/lint v0.0.0-20210508222113-6edffad5e616 // indirect
	golang.org/x/mod v0.29.0 // indirect
	golang.org/x/net v0.46.0 // indirect
	golang.org/x/tools v0.38.0 // indirect
	golang.org/x/tools/go/expect v0.1.1-deprecated // indirect
	honnef.co/go/tools v0.3.2 // indirect
)

require (
	github.com/ianlancetaylor/demangle v0.0.0-20240912202439-0a2b6291aafd // indirect
	golang.org/x/sys v0.37.0
)

replace github.com/cilium/ebpf => github.com/bpfsnoop/ebpf v0.20.0-rb.0.20260130060452-2694cba928f0
