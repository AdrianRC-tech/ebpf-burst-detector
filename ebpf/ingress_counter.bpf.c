#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define TC_ACT_OK 0

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1);
} node_ingress_bytes SEC(".maps");

SEC("tc")
int ingress_counter(struct __sk_buff *skb)
{
	__u32 key = 0;
	__u64 *bytes = bpf_map_lookup_elem(&node_ingress_bytes, &key);
	if (bytes)
		*bytes += skb->len;
	return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
