package modcipher

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"slices"
)

type contentType uint8

const (
	handshake contentType = 22
)

type protocolVersion uint16

type handshakeType uint8

const (
	clientHello handshakeType = 1
)

var idToCipherSuite = map[uint16]*tls.CipherSuite{}

func init() {
	for _, cs := range tls.CipherSuites() {
		idToCipherSuite[cs.ID] = cs
	}
}

type CipherSuite uint16

func (c CipherSuite) String() string {
	cs, ok := idToCipherSuite[uint16(c)]
	if !ok {
		return fmt.Sprintf("%04x", uint16(c))
	}
	return cs.Name
}

type uint24 [3]uint8

type random [32]uint8

type Conn struct {
	net.Conn
	Preferences map[CipherSuite]int
}

var _ net.Conn = (*Conn)(nil)

func (c *Conn) Write(b []byte) (int, error) {
	cipherSuites, at, ok := acceptCipherSuites(b)
	if !ok {
		return c.Conn.Write(b)
	}

	slog.Info("ClientHello", "cipher_suites", cipherSuites, "at", at)

	cipherSuites = slices.SortedStableFunc(slices.Values(cipherSuites), func(x CipherSuite, y CipherSuite) int {
		return c.Preferences[y] - c.Preferences[x]
	})

	slog.Info("ClientHello(modified)", "cipher_suites", cipherSuites)

	target := b[at : at+len(cipherSuites)*2]
	slog.Info("write", "bytes", fmt.Sprintf("%02x", b))
	w := bytes.NewBuffer(target)
	w.Reset()
	for _, cs := range cipherSuites {
		if err := binary.Write(w, binary.BigEndian, cs); err != nil {
			return 0, err
		}
	}
	slog.Info("write", "bytes", fmt.Sprintf("%02x", b))

	return c.Conn.Write(b)
}

func acceptCipherSuites(b []byte) ([]CipherSuite, int, bool) {
	r := bytes.NewReader(b)

	if ct, ok := accept[contentType](r); !ok || ct != handshake {
		return nil, 0, false
	}

	if pv, ok := accept[protocolVersion](r); !ok || (pv != 0x0301 && pv != 0x0303) {
		return nil, 0, false
	}

	if _, ok := accept[uint16](r); !ok {
		return nil, 0, false
	}

	if mt, ok := accept[handshakeType](r); !ok || mt != clientHello {
		return nil, 0, false
	}

	if _, ok := accept[uint24](r); !ok {
		return nil, 0, false
	}

	if lv, ok := accept[protocolVersion](r); !ok || lv != 0x303 {
		return nil, 0, false
	}

	if _, ok := accept[random](r); !ok {
		return nil, 0, false
	}

	legacySessionIDLen, ok := accept[uint8](r)
	if !ok {
		return nil, 0, false
	}

	if _, ok := acceptVariableLength[uint8](r, int(legacySessionIDLen)); !ok {
		return nil, 0, false
	}

	// The length of cipher suites in bytes.
	l, ok := accept[uint16](r)
	if !ok {
		return nil, 0, false
	}

	at := len(b) - r.Len()

	css, ok := acceptVariableLength[CipherSuite](r, int(l)/2)
	return css, at, ok
}

func accept[T comparable](r io.Reader) (T, bool) {
	var actual T
	err := binary.Read(r, binary.BigEndian, &actual)
	return actual, err == nil
}

func acceptVariableLength[T comparable](r io.Reader, length int) ([]T, bool) {
	actual := make([]T, length)
	err := binary.Read(r, binary.BigEndian, &actual)
	return actual, err == nil
}
