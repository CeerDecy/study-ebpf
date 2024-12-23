package main

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"time"
)

// https://eunomia.dev/zh/tutorials/29-sockops/#ebpf_1

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf_redirect bpf_redirect.bpf.c -- -I../headers
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf_contrack bpf_contrack.bpf.c -- -I../headers

func main() {

	mountPath := "/sys/fs/bpf/"

	if err := unix.Mount("bpf", mountPath, "bpf", 0, ""); err != nil {
		logrus.Fatalln(err)
	}

	var contrackObject bpf_contrackObjects
	if err := loadBpf_contrackObjects(&contrackObject, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath:        mountPath,
			LoadPinOptions: ebpf.LoadPinOptions{},
		},
	}); err != nil {
		logrus.Infoln(err)
		return
	}
	defer contrackObject.Close()

	logrus.Infoln("MapOptions has pinned ====> ", contrackObject.SockOpsMap.IsPinned())

	if err := contrackObject.SockOpsMap.Pin(mountPath + "sock_ops_map"); err != nil {
		logrus.Fatalf("failed to pin map, error: %v", err)
	}

	logrus.Infoln("Custom has pinned ====> ", contrackObject.SockOpsMap.IsPinned())

	cgroup, err := link.AttachCgroup(link.CgroupOptions{
		Path:    "/sys/fs/cgroup/",
		Attach:  ebpf.AttachCGroupSockOps,
		Program: contrackObject.BpfSockopsHandler,
	})
	if err != nil {
		logrus.Infoln(err)
		return
	}
	defer cgroup.Close()

	time.Sleep(time.Hour * 10)
}
