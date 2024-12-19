#ifndef __SOCKET_H
#define __SOCKET_H

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

#endif