/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* to u64 in host order */
// static inline __u64 ether_addr_to_u64(const __u8 *addr)
// {
// 	__u64 u = 0;
// 	int i;

// 	for (i = ETH_ALEN - 1; i >= 0; i--)
// 		u = u << 8 | addr[i];
// 	return u;
// }

SEC("xdp")
int  xdp_prog_simple(struct xdp_md *ctx)
{
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
			// send to a specific buffer in the user space
				
			
		}
	}


    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
