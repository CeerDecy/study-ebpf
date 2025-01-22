package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf hello-ebpf.bpf.c -- -I../headers

func main() {

}
