//go:generate go tool bpf2go -target bpfel -cc clang -strip llvm-strip-18 -cflags "-O2 -g -Wall -I../../ebpf/headers" bpf ../../ebpf/ingress_counter.bpf.c

package main
