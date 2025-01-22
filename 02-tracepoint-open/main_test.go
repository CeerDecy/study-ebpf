package main

import (
	"bytes"
	"github.com/sirupsen/logrus"
	"testing"
)

func TestEvent_String(t *testing.T) {
	s := string(bytes.TrimRight([]byte{'a', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00'}, "\x00"))
	logrus.Infof(s)
}
