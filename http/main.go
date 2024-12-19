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
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"unsafe"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf socket.c -- -I../headers

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Println("remove mem lock error:", err)
		return
	}

	obj := bpfObjects{}
	if err := loadBpfObjects(&obj, nil); err != nil {
		log.Println("load object error: ", err)
	}
	defer obj.Close()

	list, err := netlink.LinkList()
	if err != nil {
		log.Fatalln(err)
	}

	for _, v := range list {
		index := v.Attrs().Index
		if v.Type() != "veth" {
			continue
		}
		sock, err := OpenRawSock(index)
		if err != nil {
			log.Fatalln(err)
			return
		}

		file := os.NewFile(uintptr(sock), fmt.Sprintf("raw_sock_%v", sock))
		if file == nil {
			log.Fatalf("Failed to create os.File from raw socket")
		}

		if err = link.AttachSocketFilter(file, obj.SocketHandler); err != nil {
			log.Fatalln(err)
			return
		}
	}

	reader, err := ringbuf.NewReader(obj.bpfMaps.Rb)
	if err != nil {
		log.Println("ring buffer reader error: ", err)
		return
	}
	defer reader.Close()

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

				var event SoEvent
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

func OpenRawSock(index int) (int, error) {
	sock, err := unix.Socket(unix.AF_PACKET,
		unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, int(Htons(unix.ETH_P_ALL)))
	if err != nil {
		return 0, err
	}

	sll := syscall.SockaddrLinklayer{}
	sll.Protocol = Htons(unix.ETH_P_ALL)
	sll.Ifindex = index
	if err := syscall.Bind(sock, &sll); err != nil {
		return 0, err
	}

	return sock, nil
}

// Htons converts to network byte order short uint16.
func Htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}
