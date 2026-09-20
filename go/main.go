/*
 * SPDX-FileCopyrightText: 2026 Kazimierz Pogoda / Xemantic
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * noumen-crypto-bench - benchmarks for noumen's cryptographic primitives
 * Copyright (C) 2026 Kazimierz Pogoda / Xemantic
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

// The Go reference ceiling: assembly fast paths, a mature runtime, and a
// crypto library that already contains everything this benchmark needs.
//
// That last point is itself a measurement. XChaCha20 here is two library calls
// — chacha20.HChaCha20 for the subkey, chacha20poly1305.New for the rest —
// whereas on Kotlin/Native the same construction requires hand-writing the
// HChaCha20 permutation, because neither OpenSSL 3 nor cryptography-kotlin
// exposes it. See XChaCha.kt.
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

const chunk = 64 * 1024
const tag = 16
const ctChunk = chunk + tag

func env(k string, d int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return d
}

func emit(impl, suite, algo, pass string, param any, unit string, value float64) {
	fmt.Printf("%s,%s,%s,%s,%v,%s,%.0f\n", impl, suite, algo, pass, param, unit, value)
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func nonce(n []byte, counter uint64, last bool) {
	n[0], n[1], n[2] = 0, 0, 0
	binary.BigEndian.PutUint64(n[3:11], counter)
	n[11] = 0
	if last {
		n[11] = 1
	}
}

func chunkCount(size int) int { return (size + chunk - 1) / chunk }
func sealedSize(size int) int { return size + chunkCount(size)*tag }

func median(iters int, pass func() float64) float64 {
	pass() // warm-up
	r := make([]float64, iters)
	for i := range r {
		r[i] = pass()
	}
	sort.Float64s(r)
	return r[iters/2]
}

type algo struct {
	name string
	aead cipher.AEAD
	key  []byte
}

// algos returns the AEADs under test, all keyed from key.
func algos(key []byte, header []byte) []algo {
	cc, err := chacha20poly1305.New(key)
	must(err)
	blk, err := aes.NewCipher(key)
	must(err)
	gcm, err := cipher.NewGCM(blk)
	must(err)
	// The XChaCha20 STREAM framing: one subkey per object, then ordinary
	// ChaCha20-Poly1305 under the counter nonce.
	sub, err := chacha20.HChaCha20(key, header[:16])
	must(err)
	xc, err := chacha20poly1305.New(sub)
	must(err)
	return []algo{
		{"chacha20poly1305", cc, key},
		{"aes256gcm", gcm, key},
		{"xchacha20poly1305", xc, sub},
	}
}

// ---------------------------------------------------------------- aead suite

// encrypt returns MiB/s of plaintext processed.
func encrypt(a cipher.AEAD, in, out []byte) float64 {
	var n [12]byte
	chunks := chunkCount(len(in))
	t0 := time.Now()
	ip, op := 0, 0
	for i := 0; i < chunks; i++ {
		end := min(ip+chunk, len(in))
		nonce(n[:], uint64(i), i == chunks-1)
		ct := a.Seal(out[op:op], n[:], in[ip:end], nil)
		op += len(ct)
		ip = end
	}
	return float64(ip) / 1048576.0 / time.Since(t0).Seconds()
}

// decrypt returns MiB/s of ciphertext processed.
func decrypt(a cipher.AEAD, in, out []byte) float64 {
	var n [12]byte
	chunks := (len(in) + ctChunk - 1) / ctChunk
	t0 := time.Now()
	ip, op := 0, 0
	for i := 0; i < chunks; i++ {
		end := min(ip+ctChunk, len(in))
		nonce(n[:], uint64(i), i == chunks-1)
		pt, err := a.Open(out[op:op], n[:], in[ip:end], nil)
		must(err)
		op += len(pt)
		ip = end
	}
	return float64(ip) / 1048576.0 / time.Since(t0).Seconds()
}

func aeadSuite(sizeMib, iters int) {
	plain := make([]byte, sizeMib<<20)
	rand.New(rand.NewSource(42)).Read(plain)
	key := make([]byte, 32)
	rand.New(rand.NewSource(7)).Read(key)
	header := make([]byte, 24)
	rand.New(rand.NewSource(11)).Read(header)

	ct := make([]byte, sealedSize(len(plain)))
	back := make([]byte, len(plain))

	for _, a := range algos(key, header) {
		enc := median(iters, func() float64 { return encrypt(a.aead, plain, ct) })
		dec := median(iters, func() float64 { return decrypt(a.aead, ct, back) })
		if !bytes.Equal(plain, back) {
			panic("roundtrip mismatch: " + a.name)
		}
		emit("go", "aead", a.name, "encrypt", "-", "mib_s", enc)
		emit("go", "aead", a.name, "decrypt", "-", "mib_s", dec)
	}

	h := median(iters, func() float64 {
		t0 := time.Now()
		sha256.Sum256(plain)
		return float64(len(plain)) / 1048576.0 / time.Since(t0).Seconds()
	})
	emit("go", "aead", "sha256", "hash", "-", "mib_s", h)
}

// -------------------------------------------------------------- stream suite

var sinkNames = []string{"null", "file", "pipe"}

type sink struct {
	name  string
	w     io.Writer
	close func()
}

func openSink(name, dir string) *sink {
	switch name {
	case "null":
		f, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
		must(err)
		return &sink{name, f, func() { f.Close() }}
	case "file":
		p := filepath.Join(dir, "sink.bin")
		f, err := os.Create(p)
		must(err)
		return &sink{name, f, func() { f.Close(); os.Remove(p) }}
	case "pipe":
		// A child draining the pipe, modelling a write to object storage.
		cmd := exec.Command("sh", "-c", "cat > /dev/null")
		w, err := cmd.StdinPipe()
		must(err)
		must(cmd.Start())
		return &sink{name, w, func() { w.Close(); cmd.Wait() }}
	}
	panic("unknown sink: " + name)
}

func createSource(path string, size int64) {
	f, err := os.Create(path)
	must(err)
	defer f.Close()
	r := rand.New(rand.NewSource(42))
	buf := make([]byte, chunk)
	for written := int64(0); written < size; {
		r.Read(buf)
		n := int64(chunk)
		if size-written < n {
			n = size - written
		}
		_, err := f.Write(buf[:n])
		must(err)
		written += n
	}
}

// oidPass hashes the plaintext only — the work git-lfs owes with or without
// encryption.
func oidPass(src string, size int64, oid []byte) float64 {
	f, err := os.Open(src)
	must(err)
	defer f.Close()
	h := sha256.New()
	buf := make([]byte, chunk)
	t0 := time.Now()
	for {
		n, err := f.Read(buf)
		if n > 0 {
			h.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		must(err)
	}
	copy(oid, h.Sum(nil))
	return float64(size) / 1048576.0 / time.Since(t0).Seconds()
}

// sealPass reads, hashes and seals in one bounded-memory pass.
func sealPass(src string, s *sink, a cipher.AEAD, size int64, oid []byte) float64 {
	f, err := os.Open(src)
	must(err)
	defer f.Close()
	var n [12]byte
	h := sha256.New()
	in := make([]byte, chunk)
	out := make([]byte, 0, ctChunk)
	chunks := chunkCount(int(size))
	t0 := time.Now()
	for i := 0; ; i++ {
		r, err := io.ReadFull(f, in)
		if r == 0 {
			break
		}
		if err != nil && err != io.ErrUnexpectedEOF {
			must(err)
		}
		h.Write(in[:r])
		nonce(n[:], uint64(i), i == chunks-1)
		out = a.Seal(out[:0], n[:], in[:r], nil)
		_, err = s.w.Write(out)
		must(err)
	}
	copy(oid, h.Sum(nil))
	return float64(size) / 1048576.0 / time.Since(t0).Seconds()
}

// openPass reads the STREAM, opens it, and hashes the recovered plaintext.
func openPass(sealed string, s *sink, a cipher.AEAD, plainSize, sealedBytes int64, oid []byte) float64 {
	f, err := os.Open(sealed)
	must(err)
	defer f.Close()
	var n [12]byte
	h := sha256.New()
	in := make([]byte, ctChunk)
	out := make([]byte, 0, chunk)
	chunks := chunkCount(int(plainSize))
	t0 := time.Now()
	for i := 0; ; i++ {
		r, err := io.ReadFull(f, in)
		if r == 0 {
			break
		}
		if err != nil && err != io.ErrUnexpectedEOF {
			must(err)
		}
		nonce(n[:], uint64(i), i == chunks-1)
		out, err = a.Open(out[:0], n[:], in[:r], nil)
		must(err)
		h.Write(out)
		_, err = s.w.Write(out)
		must(err)
	}
	copy(oid, h.Sum(nil))
	return float64(sealedBytes) / 1048576.0 / time.Since(t0).Seconds()
}

func streamSuite(sizeMib, iters int) {
	size := int64(sizeMib) << 20
	dir, err := os.MkdirTemp("", "noumen-crypto-bench-go")
	must(err)
	defer os.RemoveAll(dir)

	src := filepath.Join(dir, "plain.bin")
	sealed := filepath.Join(dir, "sealed.bin")
	createSource(src, size)

	key := make([]byte, 32)
	rand.New(rand.NewSource(7)).Read(key)
	header := make([]byte, 24)
	rand.New(rand.NewSource(11)).Read(header)

	plainOid := make([]byte, 32)
	oid := make([]byte, 32)
	sealedBytes := int64(sealedSize(int(size)))

	emit("go", "stream", "sha256", "oid", "-", "mib_s",
		median(iters, func() float64 { return oidPass(src, size, plainOid) }))

	for _, a := range algos(key, header) {
		for _, name := range sinkNames {
			s := openSink(name, dir)
			r := median(iters, func() float64 { return sealPass(src, s, a.aead, size, oid) })
			s.close()
			if !bytes.Equal(oid, plainOid) {
				panic("object id mismatch while sealing " + a.name)
			}
			emit("go", "stream", a.name, "seal+oid", name, "mib_s", r)
		}

		// A real sealed file, so the open pass reads real input.
		f, err := os.Create(sealed)
		must(err)
		sealPass(src, &sink{"fd", f, func() {}}, a.aead, size, oid)
		f.Close()

		for _, name := range sinkNames {
			s := openSink(name, dir)
			r := median(iters, func() float64 {
				return openPass(sealed, s, a.aead, size, sealedBytes, oid)
			})
			s.close()
			if !bytes.Equal(oid, plainOid) {
				panic("object id mismatch while opening " + a.name)
			}
			emit("go", "stream", a.name, "open+oid", name, "mib_s", r)
		}
	}
}

// ------------------------------------------------------------ parallel suite

// sealParallel fans the chunks of plain across workers goroutines. Chunk i
// always lands at i*ctChunk, so the result is byte-identical to a serial seal.
func sealParallel(a cipher.AEAD, plain, out []byte, workers int) float64 {
	chunks := chunkCount(len(plain))
	per := (chunks + workers - 1) / workers
	t0 := time.Now()
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(from, until int) {
			defer wg.Done()
			var n [12]byte
			for i := from; i < until; i++ {
				ip := i * chunk
				end := min(ip+chunk, len(plain))
				nonce(n[:], uint64(i), i == chunks-1)
				a.Seal(out[i*ctChunk:i*ctChunk], n[:], plain[ip:end], nil)
			}
		}(min(w*per, chunks), min((w+1)*per, chunks))
	}
	wg.Wait()
	return float64(len(plain)) / 1048576.0 / time.Since(t0).Seconds()
}

func parallelSuite(sizeMib, iters int) {
	plain := make([]byte, sizeMib<<20)
	rand.New(rand.NewSource(42)).Read(plain)
	key := make([]byte, 32)
	rand.New(rand.NewSource(7)).Read(key)
	header := make([]byte, 24)
	rand.New(rand.NewSource(11)).Read(header)

	out := make([]byte, sealedSize(len(plain)))
	reference := make([]byte, sealedSize(len(plain)))
	maxWorkers := env("MAX_WORKERS", 8)

	for _, a := range algos(key, header) {
		encrypt(a.aead, plain, reference)
		for w := 1; w <= maxWorkers; w *= 2 {
			for i := range out {
				out[i] = 0
			}
			r := median(iters, func() float64 { return sealParallel(a.aead, plain, out, w) })
			if !bytes.Equal(out, reference) {
				panic(fmt.Sprintf("parallel output differs from serial: %s at %d workers", a.name, w))
			}
			emit("go", "parallel", a.name, "encrypt", w, "mib_s", r)
		}
	}
}

// ------------------------------------------------------------------- startup

// cryptoInit does what any helper invocation must before sealing a byte.
func cryptoInit() {
	a, err := chacha20poly1305.New(make([]byte, 32))
	must(err)
	a.Seal(nil, make([]byte, 12), nil, nil)
	sha256.New()
}

func main() {
	suite := "all"
	if len(os.Args) > 1 {
		suite = os.Args[1]
	}
	switch suite {
	case "noop":
		return
	case "crypto-init":
		cryptoInit()
		return
	case "envelope":
		return // carried by the Kotlin/Native binary only
	}

	sizeMib, iters := env("SIZE_MIB", 256), env("ITERS", 5)
	switch suite {
	case "aead":
		aeadSuite(sizeMib, iters)
	case "stream":
		streamSuite(sizeMib, iters)
	case "parallel":
		parallelSuite(sizeMib, iters)
	case "all":
		aeadSuite(sizeMib, iters)
		streamSuite(sizeMib, iters)
		parallelSuite(sizeMib, iters)
	default:
		panic("unknown suite: " + suite)
	}
}
