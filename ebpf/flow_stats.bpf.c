#include "shared_maps.h"
#include <bpf/bpf_endian.h>

#define EEXIST 17 /* not in vmlinux.h — standard errno, see asm-generic/errno-base.h */

SEC("tc")
int flow_counter(struct __sk_buff *skb)
{
	struct iphdr iph;

	/* Offset-independent: works whether or not an L2 header precedes the IP
	 * header (netkit L3 mode has none), unlike a hardcoded 14-byte offset. */
	if (bpf_skb_load_bytes_relative(skb, 0, &iph, sizeof(iph), BPF_HDR_START_NET) ||
	    iph.version != 4 || iph.ihl < 5) {
		/* Not IPv4 (e.g. IPv6): ingress_counter still counts the bytes node-wide. */
		return TCX_NEXT;
	}

	struct flow_key key = {};
	key.src_ip = iph.saddr;
	key.dst_ip = iph.daddr;
	key.proto = iph.protocol;

	/* Only TCP/UDP carry ports, and only the first fragment has a transport
	 * header at ihl*4 — a non-first fragment leaves ports at 0. */
	if ((iph.protocol == IPPROTO_TCP || iph.protocol == IPPROTO_UDP) &&
	    !(iph.frag_off & bpf_htons(0x1FFF))) {
		struct {
			__be16 sport;
			__be16 dport;
		} ports;

		if (!bpf_skb_load_bytes_relative(skb, iph.ihl * 4, &ports, sizeof(ports), BPF_HDR_START_NET)) {
			key.src_port = ports.sport;
			key.dst_port = ports.dport;
		}
	}

	struct flow_stat *stat = bpf_map_lookup_elem(&flow_stats, &key);
	if (!stat) {
		/* first_seen_ns is per-CPU: this insert only initializes the
		 * calling CPU's value slot, zeroing every other CPU's slot for this
		 * key (userspace sums across CPUs taking the min non-zero
		 * first_seen — see flowring.go). */
		struct flow_stat init = {
			.bytes         = skb->len,
			.skbs          = 1,
			.first_seen_ns = bpf_ktime_get_ns(),
		};
		long ret = bpf_map_update_elem(&flow_stats, &key, &init, BPF_NOEXIST);

		if (ret == 0)
			return TCX_NEXT;
		if (ret != -EEXIST)
			return TCX_NEXT;
		/* Another CPU created this key between our lookup and insert
		 * (the key itself is shared across CPUs, only the value is
		 * per-CPU) — look up our own zero-initialized slot and add. */
		stat = bpf_map_lookup_elem(&flow_stats, &key);
		if (!stat)
			return TCX_NEXT;
	}

	stat->bytes += skb->len;
	stat->skbs += 1;
	return TCX_NEXT;
}

char LICENSE[] SEC("license") = "GPL";
