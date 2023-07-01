// Package NTLM implements the NTLM hash algorithm.
package ntlm

import (
	"hash"

	"golang.org/x/crypto/md4" //lint:ignore SA1019 NTLM is backed by MD4
)

// The block size of NTLM in bytes.
const BlockSize = 64

// The size of an NTLM hash in bytes.
const Size = 16

// New returns a new hash.Hash computing the NTLM hash.
func New() hash.Hash {
	return &ntlm{
		h: md4.New(),
	}
}

// Sum returns the NTLM hash of the data.
func Sum(data []byte) [Size]byte {
	var h [Size]byte
	hh := New()
	hh.Write(data)
	hh.Sum(h[:0])
	return h
}

type ntlm struct {
	h hash.Hash // MD4 hasher
}

func (n *ntlm) Write(p []byte) (int, error) {
	buf := make([]byte, 0, len(p)*2)
	for _, b := range p {
		buf = append(buf, b)
		buf = append(buf, 0) // UTF-16 shenanigans
	}
	return n.h.Write(buf)
}

func (n *ntlm) Sum(b []byte) []byte {
	return n.h.Sum(b)
}

func (n *ntlm) Reset() {
	n.h.Reset()
}

func (n *ntlm) Size() int {
	return n.h.Size()
}

func (n *ntlm) BlockSize() int {
	return n.h.BlockSize()
}
