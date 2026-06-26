#include "shared_maps.h"

#define TC_ACT_OK 0

SEC("tc")
int ingress_counter(struct __sk_buff *skb)
{
	__u32 key = 0;
	__u64 *bytes = bpf_map_lookup_elem(&node_ingr_bytes, &key);
	if (bytes)
		// https://people.computing.clemson.edu/~westall/853/notes/skbuff.pdf - skb->len is the total length of the packet, including headers + payload and covering any possible fragmentation.
		*bytes += skb->len;
	return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
