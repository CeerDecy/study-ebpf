package main

import (
	"fmt"
	"github.com/vishvananda/netlink"
)

func main() {
	list, _ := netlink.LinkList()
	for _, v := range list {
		if v.Type() != "veth" {
			continue
		}
		fmt.Printf("name: %v, index: %v\n", v.Attrs().Name, v.Attrs().Index)
	}
}
