/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <stdbool.h>
#include <bpf/bpf_endian.h>


struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 64);
} xsks_map SEC(".maps");


SEC("xdp")
int xdp_sock_prog(struct xdp_md *ctx)
{
    int index = ctx->rx_queue_index;

    void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	__u64 offset = sizeof(*eth);

	if ((void *)eth + offset > data_end)
		return 0;

    struct iphdr *iph = data + offset;
    offset += sizeof(*iph);

    if ((void *)iph + sizeof(*iph) > data_end)
        return XDP_PASS;

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)iph + sizeof(*iph);

        if ((void *)tcph + sizeof(*tcph) > data_end)
            return XDP_PASS;

		__u16 src_port = bpf_ntohs(tcph->source);
		__u16 dest_port = bpf_ntohs(tcph->dest);
		if (src_port == 9000 || src_port == 9001) {
			bpf_printk("src IP: %u, dst IP: %u, src port: %u, dst port: %u\n",
				bpf_ntohl(iph->saddr),
				bpf_ntohl(iph->daddr),
				src_port,
				dest_port);
			if (bpf_map_lookup_elem(&xsks_map, &index))
                return bpf_redirect_map(&xsks_map, index, 0);
            
		}
	}

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
