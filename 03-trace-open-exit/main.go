package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/sirupsen/logrus"
	"os"
	"os/signal"
	"syscall"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf trace-open-exit.bpf.c -- -I../headers

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		logrus.Fatalf("failed to remove mem lock, %v", err)
	}

	obj := bpfObjects{}
	if err := loadBpfObjects(&obj, nil); err != nil {
		logrus.Fatalf("failed to load bpf object, %v", err)
	}

	enterOpenAt, err := link.Tracepoint("syscalls", "sys_enter_openat", obj.TracepointSyscallsSysEnterOpenat, nil)
	if err != nil {
		logrus.Fatalf("failed to link enter tracepoint, %v", err)
	}
	defer enterOpenAt.Close()

	exitOpenAt, err := link.Tracepoint("syscalls", "sys_exit_openat", obj.TracepointSyscallsSysExitOpenat, nil)
	if err != nil {
		logrus.Fatalf("failed to link exit tracepoint, %v", err)
	}
	defer exitOpenAt.Close()

	reader, err := ringbuf.NewReader(obj.Rb)
	if err != nil {
		logrus.Fatalf("failed to new reader for ringbuf, %v", err)
	}
	defer reader.Close()

	fmt.Println("ready to read")
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGKILL, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGSTOP, syscall.SIGINT)
	for {
		select {
		case <-sigChan:
			fmt.Println("stop....")
			return
		default:
			record, err := reader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				fmt.Fprintf(os.Stderr, "error reading from ringbuf: %v\n", err)
				continue
			}

			var event Event
			if err = binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				logrus.Errorf("binary read failed, %v", err)
				continue
			}
			logrus.Infoln(event.String())
		}
	}
}

type OpenFile struct {
	Pid      uint32
	Filename [256]byte
}

type Event struct {
	Pid      uint32
	Ret      uint64
	Filename [256]byte
	Comm     [256]byte
}

func (e *Event) String() string {
	return fmt.Sprintf(
		"Event{Pid: %d, Ret: %d, Filename: %s, Comm: %s}",
		e.Pid,
		e.Ret,
		byteArrayToString(e.Filename),
		byteArrayToString(e.Comm),
	)
}

func byteArrayToString(b [256]byte) string {
	n := 0
	for i, v := range b {
		if v == '\x00' { // Stop at the first null byte
			n = i
			break
		}
	}
	return string(b[:n])
}
