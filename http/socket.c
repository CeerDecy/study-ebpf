//go:build ignore

//#include <stddef.h>
#include <linux/bpf.h>
//#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/socket.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define IP_MF 0x2000
#define IP_OFFSET 0x1FFF
#define IP_TCP 6
#define ETH_HLEN 14

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_BUF_SIZE 64

struct so_event {
    __be32 src_addr;
    __be32 dst_addr;

    union {
        __be32 prots;
        __be16 prot16[2];
    };
    __u32 ip_proto;
    __u32 pkt_type;
    __u32 ifindex;
    __u32 payload_length;
    __u8 payload[MAX_BUF_SIZE];
};

struct __tcphdr
{
	__be16 source;
	__be16 dest;
	__be32 seq;
	__be32 ack_seq;
	__u16 res1 : 4, doff : 4, fin : 1, syn : 1, rst : 1, psh : 1, ack : 1, urg : 1, ece : 1, cwr : 1;
	__be16 window;
	__sum16 check;
	__be16 urg_ptr;
};

static __always_inline int bpf_strncmp(const char *str1, __u32 len, const char *str2) {
    for (__u32 i = 0; i < len; i++) {
        if (str1[i] != str2[i])
            return str1[i] - str2[i];
        if (str1[i] == '\0')
            break;
    }
    return 0;
}

static inline int ip_is_fragment(struct __sk_buff *skb, __u32 nhoff)
{
	__u16 frag_off;

	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, frag_off), &frag_off, 2);
	frag_off = __bpf_ntohs(frag_off);
	return frag_off & (IP_MF | IP_OFFSET);
}

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("socket")
int socket_handler(struct __sk_buff *skb) {
    struct so_event *e;
    __u8 verlen;
    __u16 proto;
    __u32 nhoff = ETH_HLEN;
    __u32 ip_proto = 0;
    __u32 tcp_hdr_len = 0;
    __u16 tlen;
    __u32 payload_offset = 0;
    __u32 payload_length = 0;
    __u8 hdr_len;

    // 从以太网帧中读取proto
    bpf_skb_load_bytes(skb, 12, &proto, 2);
    // 将字节序从大端转换成小端
    proto = __bpf_ntohs(proto);
    // 判断是否为IP协议
    if (proto != ETH_P_IP) return 0;
    // 判断IP数据报是否为分片
    if (ip_is_fragment(skb, nhoff)) return 0;

    // 读取skb中指定偏移到ETH_HLEN之后的数据，写入到hdr_len中（4位，半个字节，后续需要进行位操作）
    bpf_skb_load_bytes(skb, ETH_HLEN, &hdr_len, sizeof(hdr_len));
    // IP数据报中 高四位为version，低四位位ihl，所以用0x0f对其进行&操作，只保留低四位
    hdr_len &= 0x0f;
    // 根据IPV4协议，需要将长度乘4
    hdr_len *= 4;

    // 判断ip头长度是否异常
    if (hdr_len < sizeof(struct iphdr)) return 0;

    // 读取Ip数据报中的IP协议（8位，1字节）
    bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, protocol), &ip_proto, 1);

    // IP协议如果不为TCP则跳过
    if (ip_proto != IPPROTO_TCP) return 0;

    // tcp头部长度 为以太网帧+IP头部帧的偏移（因为TCP头部是存在IP数据报的body里的）
    tcp_hdr_len = nhoff + hdr_len;

    // 获取IP的版本
    bpf_skb_load_bytes(skb, nhoff + 0, &verlen, 1);
    // 获取IP数据报的总长度
    bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, tot_len), &tlen, sizeof(tlen));

    __u8 doff;
    // 为了获取TCP首部的长度（即data数据偏移量），可以先从确认序号的偏移量开始在加上4个字节进行读取
    bpf_skb_load_bytes(skb, tcp_hdr_len + offsetof(struct __tcphdr, ack_seq) + 4, &doff, sizeof(doff));
    // 保留高四位
    doff &= 0xf0;
    // 右移4位
    doff >>= 4;
    // 原因是4个字节为一个单位
    doff *= 4;

    // 计算出payload的偏移量
    payload_offset = ETH_HLEN + hdr_len + doff;
    // 计算出payload的长度
    payload_length = __bpf_ntohs(tlen) - hdr_len - doff;

    char line_buffer[7];
    // 如果数据包的负载长度小于 7 字节（payload_length < 7），则说明负载不足以包含任何有效的 HTTP 方法或协议头（最长为7 : `DELETE\n`），直接返回。
    if (payload_length < 7 || payload_offset < 0) return 0;

    // 从负载中读取HTTP请求行中的Method
    bpf_skb_load_bytes(skb, payload_offset, line_buffer, 7);
    if (bpf_strncmp(line_buffer, 3, "GET") != 0 &&
        bpf_strncmp(line_buffer, 4, "POST") != 0 &&
        bpf_strncmp(line_buffer, 3, "PUT") != 0 &&
        bpf_strncmp(line_buffer, 6, "DELETE") != 0 &&
        bpf_strncmp(line_buffer, 4, "HTTP") != 0) return 0;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    e->ip_proto = ip_proto;
    bpf_skb_load_bytes(skb, nhoff + hdr_len, &(e->prots), 4);
    e->pkt_type = skb->pkt_type;
    e->ifindex = skb->ifindex;

    e->payload_length = payload_length;
    bpf_skb_load_bytes(skb, payload_offset, e->payload, MAX_BUF_SIZE);

    bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, saddr), &(e->src_addr), 4);
    bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, daddr), &(e->dst_addr), 4);

    bpf_ringbuf_submit(e,0);
    return skb->len;
}