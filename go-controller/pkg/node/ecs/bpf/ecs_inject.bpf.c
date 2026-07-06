// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: GPL-2.0-only
//
// TC egress BPF — inject EDNS0 Client Subnet (ECS, RFC 7871) into DNS queries.
// Attachment: TC egress of ovn-udn1 INSIDE the pod's network namespace.
//
// After bpf_skb_change_tail, the kernel has already computed the full UDP
// checksum (skb_checksum_help was called internally for CHECKSUM_PARTIAL skbs).
// We must therefore update the UDP checksum incrementally for every byte we
// add or change, using:
//   bpf_csum_diff  — to compute the checksum contribution of newly appended bytes
//   bpf_l4_csum_replace — to apply incremental updates to the in-packet checksum
//   bpf_l3_csum_replace — for the IP header checksum

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define DNS_PORT    53
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif
#define DNS_QR_MASK 0x8000u

/* OPT RR header only (name+type+class+ttl+rdlen = 1+2+2+4+2 = 11 bytes) */
#define OPT_HDR_SZ  11
/* ECS option: code(2)+len(2)+family(2)+srcpfx(1)+scopepfx(1)+addr(4) = 12 */
#define ECS_OPT_SZ  12
/* Full OPT RR with embedded ECS: 11 + 12 = 23 */
#define OPT_FULL_SZ 23

/* BPF flags for bpf_l4_csum_replace */
#define BPF_F_PSEUDO_HDR    0x10ULL

static __always_inline int skip_qname(struct __sk_buff *skb, int off)
{
    for (int i = 0; i < 128; i++) {
        __u8 label = 0;
        if (bpf_skb_load_bytes(skb, off, &label, 1) < 0) return -1;
        if (label == 0)              return off + 1;
        if ((label & 0xC0) == 0xC0) return off + 2;
        if (label > 63)              return -1;
        off += 1 + (int)label;
        if (off > (int)skb->len) return -1;
    }
    return -1;
}

SEC("tc")
int inject_ecs(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)          return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP))  return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)           return TC_ACT_OK;
    if (ip->protocol != IPPROTO_UDP)            return TC_ACT_OK;

    __be32 pod_ip   = ip->saddr;
    int    ip_hlen  = (int)ip->ihl * 4;
    if (ip_hlen < 20) return TC_ACT_OK;

    struct udphdr *udp = (void *)ip + ip_hlen;
    if ((void *)(udp + 1) > data_end)          return TC_ACT_OK;
    if (udp->dest != bpf_htons(DNS_PORT))      return TC_ACT_OK;

    /* Save header fields BEFORE resize */
    __u16 saved_ip_tot  = bpf_ntohs(ip->tot_len);
    __u16 saved_udp_len = bpf_ntohs(udp->len);

    int eth_sz  = (int)sizeof(struct ethhdr);   /* 14 */
    int udp_off = eth_sz + ip_hlen;             /* byte offset of UDP header */
    int dns_off = udp_off + (int)sizeof(struct udphdr);  /* byte offset of DNS */

    /* Packet-byte offsets for later bpf_skb_store_bytes / csum calls */
    __u32 ip_tot_off  = 16;                    /* eth(14) + tot_len at byte 2 */
    __u32 ip_csum_off = 24;                    /* eth(14) + check at byte 10  */
    __u32 udp_len_off = ((__u32)udp_off) + 4; /* UDP length field             */
    __u32 udp_csum_off= ((__u32)udp_off) + 6; /* UDP checksum field           */

    if (dns_off + 12 > (int)skb->len) return TC_ACT_OK;

    /* Must be a DNS query (QR=0) with exactly one question */
    __u16 t;
    if (bpf_skb_load_bytes(skb, dns_off + 2,  &t, 2) < 0) return TC_ACT_OK;
    if (bpf_ntohs(t) & DNS_QR_MASK) return TC_ACT_OK;
    if (bpf_skb_load_bytes(skb, dns_off + 4,  &t, 2) < 0) return TC_ACT_OK;
    if (bpf_ntohs(t) != 1)          return TC_ACT_OK;
    if (bpf_skb_load_bytes(skb, dns_off + 6,  &t, 2) < 0) return TC_ACT_OK;
    if (bpf_ntohs(t))                return TC_ACT_OK;
    if (bpf_skb_load_bytes(skb, dns_off + 8,  &t, 2) < 0) return TC_ACT_OK;
    if (bpf_ntohs(t))                return TC_ACT_OK;
    if (bpf_skb_load_bytes(skb, dns_off + 10, &t, 2) < 0) return TC_ACT_OK;
    __u16 arcount = bpf_ntohs(t);
    if (arcount > 1) return TC_ACT_OK;

    int qend = skip_qname(skb, dns_off + 12);
    if (qend < 0) return TC_ACT_OK;
    int question_end = qend + 4;   /* skip QTYPE + QCLASS */
    if (question_end > (int)skb->len) return TC_ACT_OK;

    // ── Case A: ARCOUNT == 0 ─────────────────────────────────────────────────
    // Append a complete OPT RR (with embedded ECS option) and set ARCOUNT=1.
    if (arcount == 0) {
        __u8 opt_rr[OPT_FULL_SZ];
        /* OPT RR header */
        opt_rr[0]  = 0x00;              /* name = root */
        opt_rr[1]  = 0x00; opt_rr[2]  = 0x29; /* type = OPT (41) */
        opt_rr[3]  = 0x04; opt_rr[4]  = 0xD0; /* class = 1232 (payload size) */
        opt_rr[5]  = 0x00; opt_rr[6]  = 0x00;
        opt_rr[7]  = 0x00; opt_rr[8]  = 0x00; /* TTL / flags = 0 */
        opt_rr[9]  = 0x00; opt_rr[10] = 0x0C; /* RDLENGTH = 12 (one ECS opt) */
        /* ECS option inside RDATA */
        opt_rr[11] = 0x00; opt_rr[12] = 0x08; /* OPTION-CODE  = 8 (ECS) */
        opt_rr[13] = 0x00; opt_rr[14] = 0x08; /* OPTION-LENGTH = 8 */
        opt_rr[15] = 0x00; opt_rr[16] = 0x01; /* FAMILY = 1 (IPv4) */
        opt_rr[17] = 0x20; opt_rr[18] = 0x00; /* /32 source, /0 scope */
        opt_rr[19] = (pod_ip >>  0) & 0xFF;
        opt_rr[20] = (pod_ip >>  8) & 0xFF;
        opt_rr[21] = (pod_ip >> 16) & 0xFF;
        opt_rr[22] = (pod_ip >> 24) & 0xFF;

        __u32 old_len = skb->len;
        if (bpf_skb_change_tail(skb, old_len + OPT_FULL_SZ, 0) < 0)
            return TC_ACT_OK;
        if (bpf_skb_store_bytes(skb, old_len, opt_rr, OPT_FULL_SZ, 0) < 0)
            return TC_ACT_OK;

        /* ARCOUNT: 0 → 1 */
        __u16 one = bpf_htons(1);
        __u16 zero_u16 = 0;
        bpf_skb_store_bytes(skb, dns_off + 10, &one, 2, 0);
        /* Update UDP checksum for ARCOUNT change */
        bpf_l4_csum_replace(skb, udp_csum_off, zero_u16, one, BPF_F_PSEUDO_HDR | 2);

        /* Update UDP checksum for the 23 newly appended bytes.
         * Use size=2 (NOT size=4) to keep the formula consistent:
         *   size=2 → *sum = fold16(*sum + delta)   (additive)
         *   size=4 → *sum = ~fold16(*sum + delta)  (inverts, breaks subsequent size=2)
         * Fold the 32-bit bpf_csum_diff result to 16 bits before passing. */
        __wsum new_data_csum32 = bpf_csum_diff(NULL, 0, (void *)opt_rr, OPT_FULL_SZ, 0);
        __u16 new_data_csum16 = (__u16)new_data_csum32 + (__u16)(new_data_csum32 >> 16);
        bpf_l4_csum_replace(skb, udp_csum_off, 0, new_data_csum16, 2);

        /* Update UDP length: add delta twice (UDP header field + pseudo-header). */
        __u16 new_udp_len_be = bpf_htons(saved_udp_len + OPT_FULL_SZ);
        bpf_skb_store_bytes(skb, udp_len_off, &new_udp_len_be, 2, 0);
        bpf_l4_csum_replace(skb, udp_csum_off,
            bpf_htons(saved_udp_len), new_udp_len_be, 2);
        /* Extra call for pseudo-header UDP length contribution */
        __u16 udp_delta_be = bpf_htons(OPT_FULL_SZ);
        bpf_l4_csum_replace(skb, udp_csum_off, 0, udp_delta_be, 2);

        /* Update IP total length + IP header checksum */
        __u16 new_ip_tot_be = bpf_htons(saved_ip_tot + OPT_FULL_SZ);
        bpf_skb_store_bytes(skb, ip_tot_off, &new_ip_tot_be, 2, 0);
        bpf_l3_csum_replace(skb, ip_csum_off, bpf_htons(saved_ip_tot), new_ip_tot_be, 2);

        return TC_ACT_OK;
    }

    // ── Case B: ARCOUNT == 1 ─────────────────────────────────────────────────
    // Locate the existing OPT RR and append an ECS option to its RDATA.
    int opt_off = question_end;
    if (opt_off + OPT_HDR_SZ > (int)skb->len) return TC_ACT_OK;

    __u8 rr_name = 0xFF; __u16 rr_type = 0;
    if (bpf_skb_load_bytes(skb, opt_off,     &rr_name, 1) < 0) return TC_ACT_OK;
    if (bpf_skb_load_bytes(skb, opt_off + 1, &rr_type, 2) < 0) return TC_ACT_OK;
    if (rr_name != 0 || bpf_ntohs(rr_type) != 41)              return TC_ACT_OK;

    __u16 rdlen_be = 0;
    if (bpf_skb_load_bytes(skb, opt_off + 9, &rdlen_be, 2) < 0) return TC_ACT_OK;
    __u16 rdlen = bpf_ntohs(rdlen_be);

    /* Build the 12-byte ECS option to append */
    __u8 ecs[ECS_OPT_SZ];
    ecs[0]  = 0x00; ecs[1]  = 0x08; /* OPTION-CODE = 8 (ECS) */
    ecs[2]  = 0x00; ecs[3]  = 0x08; /* OPTION-LENGTH = 8     */
    ecs[4]  = 0x00; ecs[5]  = 0x01; /* FAMILY = 1 (IPv4)     */
    ecs[6]  = 0x20; ecs[7]  = 0x00; /* /32 source, /0 scope  */
    ecs[8]  = (pod_ip >>  0) & 0xFF;
    ecs[9]  = (pod_ip >>  8) & 0xFF;
    ecs[10] = (pod_ip >> 16) & 0xFF;
    ecs[11] = (pod_ip >> 24) & 0xFF;

    __u32 old_len = skb->len;
    if (bpf_skb_change_tail(skb, old_len + ECS_OPT_SZ, 0) < 0)
        return TC_ACT_OK;
    if (bpf_skb_store_bytes(skb, old_len, ecs, ECS_OPT_SZ, 0) < 0)
        return TC_ACT_OK;

    /* Update OPT RDLENGTH: rdlen → rdlen + ECS_OPT_SZ */
    __u16 new_rdlen_be = bpf_htons(rdlen + ECS_OPT_SZ);
    bpf_skb_store_bytes(skb, opt_off + 9, &new_rdlen_be, 2, 0);
    /* Update UDP checksum for RDLENGTH change */
    bpf_l4_csum_replace(skb, udp_csum_off, rdlen_be, new_rdlen_be, BPF_F_PSEUDO_HDR | 2);

    /* Update UDP checksum for the 12 newly appended ECS bytes.
     * Use size=2 with folded 16-bit csum (NOT size=4 which would invert). */
    __wsum ecs_csum32 = bpf_csum_diff(NULL, 0, (void *)ecs, ECS_OPT_SZ, 0);
    __u16 ecs_csum16 = (__u16)ecs_csum32 + (__u16)(ecs_csum32 >> 16);
    bpf_l4_csum_replace(skb, udp_csum_off, 0, ecs_csum16, 2);

    /* Update UDP length: add delta twice (UDP header field + pseudo-header). */
    __u16 new_udp_len_be = bpf_htons(saved_udp_len + ECS_OPT_SZ);
    bpf_skb_store_bytes(skb, udp_len_off, &new_udp_len_be, 2, 0);
    bpf_l4_csum_replace(skb, udp_csum_off,
        bpf_htons(saved_udp_len), new_udp_len_be, 2);
    /* Extra call for pseudo-header UDP length contribution */
    __u16 udp_delta_be = bpf_htons(ECS_OPT_SZ);
    bpf_l4_csum_replace(skb, udp_csum_off, 0, udp_delta_be, 2);

    /* Update IP total length + IP header checksum */
    __u16 new_ip_tot_be = bpf_htons(saved_ip_tot + ECS_OPT_SZ);
    bpf_skb_store_bytes(skb, ip_tot_off, &new_ip_tot_be, 2, 0);
    bpf_l3_csum_replace(skb, ip_csum_off, bpf_htons(saved_ip_tot), new_ip_tot_be, 2);

    return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
