// Distinct bpf2go prefixes keep the three generated object sets from clashing
// in one package.
//go:generate go tool bpf2go -target bpfel -cc clang -strip llvm-strip-18 -cflags "-O2 -g -Wall -I../../ebpf/headers" counter ../../ebpf/ingress_counter.bpf.c
//go:generate go tool bpf2go -target bpfel -cc clang -strip llvm-strip-18 -cflags "-O2 -g -Wall -I../../ebpf/headers" flow ../../ebpf/flow_stats.bpf.c
//go:generate go tool bpf2go -target bpfel -cc clang -strip llvm-strip-18 -cflags "-O2 -g -Wall -I../../ebpf/headers" cusum ../../ebpf/cusum_detector.bpf.c

package main
