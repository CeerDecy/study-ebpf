package main

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"log"
	"os"
	"os/signal"
	"syscall"
)

// https://eunomia.dev/zh/tutorials/29-sockops/#ebpf_1

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf_redirect bpf_redirect.bpf.c -- -I../headers
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf_contrack bpf_contrack.bpf.c -- -I../headers

var mount = "/sys/fs/bpf"

func main() {

	if err := unix.Mount("bpf", mount, "bpf", 0, ""); err != nil {
		logrus.Fatalln(err)
	}
	defer unix.Unmount(mount, 0)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("failed to adjust rlimit: %v", err)
	}

	var contrackObj bpf_contrackObjects
	var redirect bpf_redirectObjects

	LoadContrackBpf(&contrackObj)
	LoadRedirectBpf(&redirect, &contrackObj)
	defer contrackObj.Close()
	defer redirect.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGINT, syscall.SIGKILL)
	<-sig
}

func LoadRedirectBpf(obj *bpf_redirectObjects, b *bpf_contrackObjects) {
	if err := loadBpf_redirectObjects(obj, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: mount,
		},
	}); err != nil {
		logrus.Fatalln("load redirect bpf failed", err)
	}

	if err := link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  b.SockOpsMap.FD(),
		Program: obj.BpfRedir,
		Attach:  ebpf.AttachSkMsgVerdict,
	}); err != nil {
		logrus.Fatalln("attach ebpf program failed", err)
	}

}

func LoadContrackBpf(obj *bpf_contrackObjects) {

	if err := loadBpf_contrackObjects(obj, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: mount,
		},
	}); err != nil {
		logrus.Fatalln("load contrack bpf prog error: ", err)
	}

	logrus.Infoln("MapOptions has pinned ====> ", obj.SockOpsMap.IsPinned())

	if err := obj.SockOpsMap.Pin(mount + "/sock_ops_map"); err != nil {
		logrus.Fatalf("failed to pin map, error: %v", err)
	}

	logrus.Infoln("Custom has pinned ====> ", obj.SockOpsMap.IsPinned())

	_, err := link.AttachCgroup(link.CgroupOptions{
		Path:    "/sys/fs/cgroup/",
		Attach:  ebpf.AttachCGroupSockOps,
		Program: obj.BpfSockopsHandler,
	})
	if err != nil {
		log.Fatalf("failed to attach group contrack eBPF program spec: %v", err)
	}
}
