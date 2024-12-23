// Code generated by bpf2go; DO NOT EDIT.
//go:build mips || mips64 || ppc64 || s390x

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type bpf_contrackSockKey struct {
	Sip    uint32
	Dip    uint32
	Sport  uint32
	Dport  uint32
	Family uint32
}

// loadBpf_contrack returns the embedded CollectionSpec for bpf_contrack.
func loadBpf_contrack() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_Bpf_contrackBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load bpf_contrack: %w", err)
	}

	return spec, err
}

// loadBpf_contrackObjects loads bpf_contrack and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*bpf_contrackObjects
//	*bpf_contrackPrograms
//	*bpf_contrackMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadBpf_contrackObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadBpf_contrack()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// bpf_contrackSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpf_contrackSpecs struct {
	bpf_contrackProgramSpecs
	bpf_contrackMapSpecs
}

// bpf_contrackSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpf_contrackProgramSpecs struct {
	BpfSockopsHandler *ebpf.ProgramSpec `ebpf:"bpf_sockops_handler"`
}

// bpf_contrackMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpf_contrackMapSpecs struct {
	SockOpsMap *ebpf.MapSpec `ebpf:"sock_ops_map"`
}

// bpf_contrackObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadBpf_contrackObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpf_contrackObjects struct {
	bpf_contrackPrograms
	bpf_contrackMaps
}

func (o *bpf_contrackObjects) Close() error {
	return _Bpf_contrackClose(
		&o.bpf_contrackPrograms,
		&o.bpf_contrackMaps,
	)
}

// bpf_contrackMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadBpf_contrackObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpf_contrackMaps struct {
	SockOpsMap *ebpf.Map `ebpf:"sock_ops_map"`
}

func (m *bpf_contrackMaps) Close() error {
	return _Bpf_contrackClose(
		m.SockOpsMap,
	)
}

// bpf_contrackPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadBpf_contrackObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpf_contrackPrograms struct {
	BpfSockopsHandler *ebpf.Program `ebpf:"bpf_sockops_handler"`
}

func (p *bpf_contrackPrograms) Close() error {
	return _Bpf_contrackClose(
		p.BpfSockopsHandler,
	)
}

func _Bpf_contrackClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed bpf_contrack_bpfeb.o
var _Bpf_contrackBytes []byte