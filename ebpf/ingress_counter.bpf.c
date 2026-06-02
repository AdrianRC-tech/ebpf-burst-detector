#include "shared_maps.h"

#define TC_ACT_OK 0

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
