package main

import (
	"encoding/binary"
	"fmt"
)

type SoEvent struct {
	SrcAddr       uint32   // 源地址 (__be32)
	DstAddr       uint32   // 目的地址 (__be32)
	Prot32        uint32   // 32位协议字段 (union 中的 __be32)
	IPProto       uint32   // IP 协议 (__u32)
	PktType       uint32   // 数据包类型 (__u32)
	IfIndex       uint32   // 接口索引 (__u32)
	PayloadLength uint32   // 数据长度 (__u32)
	Payload       [64]byte // 数据内容 (__u8[MAX_BUF_SIZE])
}

// Prot16 返回 union 中的 16 位协议数组字段 (对应 __be16 prot16[2])
func (e *SoEvent) Prot16() [2]uint16 {
	return [2]uint16{uint16(e.Prot32 >> 16), uint16(e.Prot32 & 0xFFFF)}
}

func (e *SoEvent) String() string {
	srcIP := make([]byte, 4)
	dstIP := make([]byte, 4)
	binary.LittleEndian.PutUint32(srcIP, e.SrcAddr)
	binary.LittleEndian.PutUint32(dstIP, e.DstAddr)

	return fmt.Sprintf(
		"SrcAddr: %s, DstAddr: %s, Prot16: %v, IPProto: %d, PktType: %d, IfIndex: %d, PayloadLength: %d, Payload: %s",
		ipToString(srcIP),
		ipToString(dstIP),
		e.Prot16(),
		e.IPProto,
		e.PktType,
		e.IfIndex,
		e.PayloadLength,
		string(e.Payload[:]),
	)
}

func ipToString(ip []byte) string {
	return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
}
