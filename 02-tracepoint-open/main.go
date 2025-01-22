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
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf open.bpf.c -- -I../headers

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("failed to remove mem lock", err)
	}

	obj := bpfObjects{}
	if err := loadBpfObjects(&obj, nil); err != nil {
		log.Fatal("failed to laod bpf object", err)
	}
	defer obj.Close()

	tracepoint, err := link.Tracepoint("syscalls", "sys_enter_openat", obj.TracepointSyscallSysEnterOpenat, nil)
	if err != nil {
		log.Fatal("failed to tracepoint object", err)
	}
	defer tracepoint.Close()

	reader, err := ringbuf.NewReader(obj.Rb)
	if err != nil {
		log.Println("ring buffer reader error: ", err)
		return
	}
	defer reader.Close()

	logrus.Infoln("wait ringbuf")

	wg := &sync.WaitGroup{}
	wg.Add(1)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-sig:
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
					fmt.Fprintf(os.Stderr, "failed to parse ringbuf event: %v\n", err)
					continue
				}

				logrus.Infoln(event.String())
			}
		}
	}()
	wg.Wait()
}

type Event struct {
	Pid      uint32
	Filename [256]byte
}

func (e *Event) String() string {
	var buf = make([]byte, 0, 256)
	for _, b := range e.Filename {
		if b == '\x00' {
			break
		}
		buf = append(buf, b)
	}
	return fmt.Sprintf("pid: [%v], filename: [%v]", e.Pid, string(buf))
}
