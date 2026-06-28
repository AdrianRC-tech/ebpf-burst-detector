module github.com/AdrianRC-tech/ebpf-burst-detector

go 1.26.2

require (
	github.com/cilium/ebpf v0.21.0
	github.com/jsimonetti/rtnetlink/v2 v2.0.1
	github.com/mdlayher/netlink v1.7.2
	github.com/vishvananda/netns v0.0.5
	golang.org/x/sys v0.37.0
)

require (
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/mdlayher/socket v0.5.1 // indirect
	golang.org/x/net v0.46.0 // indirect
	golang.org/x/sync v0.17.0 // indirect
)

tool github.com/cilium/ebpf/cmd/bpf2go
