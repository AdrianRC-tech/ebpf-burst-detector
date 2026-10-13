#include "shared_maps.h"
#include <bpf/bpf_endian.h>

#define ETH_P_IP   0x0800 /* not in vmlinux.h — defined in <linux/if_ether.h> */

/* Flag to determine per_packet tracing. Off by default; operator sets to 1 via --trace-packets for debug runs only. */
volatile const __u8 trace_packets = 0;

/* Fixed 32-byte per-packet trace record.
 * Addresses/ports stored in network byte order (as received from the kernel).
 * family=4 means IPv4 was parsed; family=0 means non-IPv4 (tuple zeroed). */
struct pkt_trace {
	__u64 timestamp_ns;
	__u32 len;       /* skb->len */
	__u32 saddr;     /* IPv4 src, network byte order */
	__u32 daddr;     /* IPv4 dst, network byte order */
	__u16 sport;     /* src port, network byte order (TCP/UDP only, else 0) */
	__u16 dport;     /* dst port, network byte order */
	__u8  protocol;  /* IP proto: TCP=6, UDP=17, ... */
	__u8  family;    /* 4=IPv4 parsed, 0=non-IPv4/unparsed */
	__u8  _pad[6];   /* explicit pad → fixed 32-byte record */
};

/* Not pinned — only ingress-counter reads this ring buffer. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24); /* 16 MiB — generous for dev-rate tracing */
} pkt_trace_rb SEC(".maps");

SEC("tc")
int ingress_counter(struct __sk_buff *skb)
{
	__u32 key = 0;
	__u64 *bytes = bpf_map_lookup_elem(&node_ingr_bytes, &key);

	if (trace_packets) {
		struct pkt_trace *t = bpf_ringbuf_reserve(&pkt_trace_rb, sizeof(*t), 0);
		if (t) {
			__builtin_memset(t, 0, sizeof(*t));
			t->timestamp_ns = bpf_ktime_get_ns();
			t->len = skb->len;

			if (skb->protocol != bpf_htons(ETH_P_IP)) {
				goto submit;
			}
			void *data = (void *)(long)skb->data;
			void *data_end = (void *)(long)skb->data_end;


			struct ethhdr *eth = data;
			struct iphdr *iph = data + sizeof(*eth);
			// Bounds check: ensure the skb contains enough data for the Ethernet + IP headers.
			if ((void *)(iph + 1) > data_end)
				goto submit;
			
			t->family = 4; // IPv4
			t->protocol = iph->protocol;
			t->saddr = iph->saddr;
			t->daddr = iph->daddr;

			// Check: Validate that IPHeader is not malformed (minimum 20 bytes) and compute its size in bytes
			__u8 ihl = iph->ihl * 4;
			if (ihl < 20)     
				goto submit;

			// Check: fragmented packets beyond the first fragment have no transport header
			// frag_off bits 0-12 = fragment offset; nonzero means "not the first fragment"
			if (iph->frag_off & bpf_htons(0x1FFF))
				goto submit;   // ports unavailable, leave them 0

			// Check: Only TCP and UDP carry src/dst ports at transport header offset 0/2
			// ICMP has no port so stays at 0.
			if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {
				void *transport = (void *)iph + ihl;
				if (transport + 4 > data_end)   // need 2 bytes sport + 2 bytes dport
					goto submit;
				t->sport = *(__u16 *)transport;
				t->dport = *(__u16 *)(transport + 2);
			}
			submit:
			
				bpf_ringbuf_submit(t, 0);
		}
	}

	if (bytes)
		// https://people.computing.clemson.edu/~westall/853/notes/skbuff.pdf - skb->len is the total length of the packet, including headers + payload and covering any possible fragmentation. It does not include skb metadata length.
		*bytes += skb->len;
	return TCX_NEXT;
}

char LICENSE[] SEC("license") = "GPL";
