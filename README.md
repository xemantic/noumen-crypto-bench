# noumen-crypto-bench

What it costs a [noumen](https://github.com/xemantic/noumen) client to encrypt git and git-LFS objects,
measured end to end on Kotlin/Native,
with the JVM, Go and Rust as reference ceilings.

[<img alt="license" src="https://img.shields.io/github/license/xemantic/noumen-crypto-bench?color=blue">](https://github.com/xemantic/noumen-crypto-bench/blob/main/LICENSE)

[<img alt="GitHub Actions Workflow Status" src="https://img.shields.io/github/actions/workflow/status/xemantic/noumen-crypto-bench/build-main.yml">](https://github.com/xemantic/noumen-crypto-bench/actions/workflows/build-main.yml)
[<img alt="GitHub branch check runs" src="https://img.shields.io/github/check-runs/xemantic/noumen-crypto-bench/main">](https://github.com/xemantic/noumen-crypto-bench/actions/workflows/build-main.yml)
[<img alt="GitHub last commit" src="https://img.shields.io/github/last-commit/xemantic/noumen-crypto-bench">](https://github.com/xemantic/noumen-crypto-bench/commits/main/)

[<img alt="GitHub contributors" src="https://img.shields.io/github/contributors/xemantic/noumen-crypto-bench">](https://github.com/xemantic/noumen-crypto-bench/graphs/contributors)
[<img alt="GitHub commit activity" src="https://img.shields.io/github/commit-activity/t/xemantic/noumen-crypto-bench">](https://github.com/xemantic/noumen-crypto-bench/commits/main/)
[<img alt="GitHub code size in bytes" src="https://img.shields.io/github/languages/code-size/xemantic/noumen-crypto-bench">]()
[<img alt="GitHub Created At" src="https://img.shields.io/github/created-at/xemantic/noumen-crypto-bench">](https://github.com/xemantic/noumen-crypto-bench/commits)
[<img alt="kotlin version" src="https://img.shields.io/badge/dynamic/toml?url=https%3A%2F%2Fraw.githubusercontent.com%2Fxemantic%2Fnoumen-crypto-bench%2Fmain%2Fgradle%2Flibs.versions.toml&query=versions.kotlin&label=kotlin">](https://kotlinlang.org/docs/releases.html)
[<img alt="discord users online" src="https://img.shields.io/discord/811561179280965673">](https://discord.gg/vQktqqN2Vn)
[![Bluesky](https://img.shields.io/badge/Bluesky-0285FF?logo=bluesky&logoColor=fff)](https://bsky.app/profile/xemantic.com)

## Why?

noumen stores only ciphertext,
so the cost of every git operation is the cost of the cryptography underneath it.
It encrypts git objects end-to-end with [age](https://age-encryption.org/) and SSH recipients,
and the plan is to store gigabyte-size LFS objects under the same envelope.

Two things about noumen narrow what is worth measuring.

The first is that **the client runtime is already decided**.
[SCOPE.md](https://github.com/xemantic/noumen/blob/main/SCOPE.md) requires a single Kotlin/Native executable,
because git invokes a remote helper repeatedly
and a JVM client would pay its startup on every invocation.
So this is not a language shootout.
Kotlin/Native is the platform;
the JVM, Go and Rust columns are here to say how much of the achievable throughput it is reaching,
and the `startup` suite is here to put a number on the latency that ruled the JVM out in the first place.

The second is that **the streaming format is not decided**.
SCOPE.md §10 leaves it open between age's 64 KiB chunk STREAM construction
and a custom XChaCha20-Poly1305 framing keyed by the data encryption key,
with benchmarks to settle it.
Both are measured here.

So the questions are:

- Can a Kotlin/Native client saturate the LFS path, and where does it lose?
- What does the envelope cost when objects are many and small, rather than few and large?
- Which framing should §10 pick?
- Does the client need parallel chunking at all?

This repository is deliberately separate from noumen itself,
so that benchmark scaffolding,
fixtures,
and throwaway comparison implementations never reach the product's dependency graph.

## What is measured

Every suite shares the same construction:
64 KiB plaintext chunks,
a 16-byte tag per chunk,
and a 12-byte nonce of an 11-byte big-endian chunk counter followed by a last-chunk flag,
as in age STREAM.

| suite      | what it answers                                                                                                                                                                                                                 |
|------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `aead`     | The primitive ceiling: bulk AEAD over a buffer already in memory, hash in a separate pass. Excludes I/O deliberately, so that the gap to `stream` is attributable to the read/write path rather than to the cipher.               |
| `stream`   | What a transfer agent actually does: read a file in bounded memory, hash the plaintext for the LFS object id and seal it in the **same** pass, write the result to a sink. Three sinks — `/dev/null`, a real file, and a pipe drained by a child process. |
| `startup`  | Process cold-start, timed from outside the process, over many invocations. `noop` is the runtime and loader; `crypto-init` additionally brings up the provider and fetches the cipher. The delta is what the crypto costs per invocation. |
| `parallel` | Whether fanning chunks across cores helps, and where the curve flattens. Counter nonces make chunks independent, so the parallel output is byte-identical to the serial output, which the tests assert.                            |
| `envelope` | Wrapping the file key for each recipient (X25519 + HKDF, as in age's stanza). One-off per object, so it is cheap only when objects are large — the mirror image of the LFS case.                                                   |

The `stream` suite reads through a warm page cache.
Dropping caches is not portable without root,
so those numbers are a CPU-and-syscall ceiling rather than a disk benchmark.

## Implementations

| column   | directory         | what runs                                                                                                                                                                                                              |
|----------|-------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `kn-evp` | `src/nativeMain/` | OpenSSL EVP driven directly through the cinterop bindings in `cryptography-provider-openssl3-api`: one `EVP_CIPHER_CTX` per object, key set once, IV re-initialised per chunk, buffers pinned once. The intended noumen bulk path. |
| `kn-lib` | `src/nativeMain/` | [cryptography-kotlin](https://github.com/whyoleg/cryptography-kotlin)'s high-level API on the same statically linked OpenSSL. Same bytes underneath as `kn-evp`, different Kotlin plumbing.                            |
| `kn-pure`| `src/nativeMain/` | SHA-256 and ChaCha20 written in plain Kotlin, with no OpenSSL underneath. Present to answer whether noumen should own its simple primitives; carries `aead` only. |
| `jvm`    | `src/jvmMain/`    | `javax.crypto` from the default provider, JDK 21 intrinsics. Carries `aead` and `startup` only — SCOPE.md rules it out as a client runtime.                                                                            |
| `go`     | `go/`             | `golang.org/x/crypto/chacha20poly1305` and stdlib `crypto/aes` + `cipher.NewGCM`, with assembly fast paths.                                                                                                            |
| `rust`   | `rust/`           | RustCrypto, with the aarch64 hardware backends explicitly enabled — see [rust/.cargo/config.toml](rust/.cargo/config.toml), which is worth reading before comparing against it.                                        |

Not every implementation carries every suite,
and that is intentional:
`envelope` is Kotlin/Native only because that is where the decision lives,
and `stream` skips `kn-lib` because the `aead` suite already rules it out.
Missing cells render as `-`.

## Running

```shell
./bench.sh                     # every suite
./bench.sh stream parallel     # just these
SIZE_MIB=1024 ITERS=10 ./bench.sh
```

Requirements: JDK 21+, Go 1.23+, a Rust toolchain.
Gradle fetches the Kotlin/Native compiler and the prebuilt OpenSSL.
See [DEVELOPMENT.md](DEVELOPMENT.md) for the CSV protocol the binaries speak,
the other environment variables,
and how to add a suite or an implementation.

The benchmarks are a runnable program rather than a published library,
so nothing here is released to Maven Central.

## Sample results

Apple M1 (8 logical cores, 4 of them performance), macOS 26.6,
JDK 26, Go 1.26, Rust 1.93, Kotlin 2.4.20 + cryptography-kotlin 0.6.0,
`SIZE_MIB=128 ITERS=5`, with `startup` measured separately at `STARTUP_RUNS=300`.

Two warnings before reading these.
This is a laptop-class ARM chip, not a deployment target,
so read the ratios rather than the absolute values.
And repeated runs on this host vary by about ±10% on the `aead` suite —
it throttles — so treat differences smaller than that as noise.
The findings below are the ones that survive that margin.

```
aead — mib_s
algo               pass             jvm       go     rust   kn-lib  kn-pure   kn-evp
aes256gcm          encrypt         3327     5147     1882     1808        -     5698
aes256gcm          decrypt         3327     5771     1786     2027        -     6679
chacha20poly1305   encrypt          781      804      582     1153        -     1441
chacha20poly1305   decrypt          825      843      585     1221        -     1568
xchacha20poly1305  encrypt            -      841      528        -        -     1692
xchacha20poly1305  decrypt            -      844      580        -        -     1532
chacha20           xor                -        -        -        -      175     2285
sha256             hash               -     2222     2056     2252      173        -

stream — mib_s
algo               pass        param       go     rust   kn-evp
sha256             oid             -     1768     1486     1696
aes256gcm          seal+oid     null     1378      918     1523
aes256gcm          seal+oid     pipe      995      727     1107
aes256gcm          seal+oid     file      535      640      812
aes256gcm          open+oid     null     1417      898     1498
aes256gcm          open+oid     pipe     1290      820     1386
aes256gcm          open+oid     file      773      614      630
chacha20poly1305   seal+oid     null      586      442      877
chacha20poly1305   seal+oid     pipe      457      395      726
chacha20poly1305   seal+oid     file      339      355      569
chacha20poly1305   open+oid     null      568      435      867
chacha20poly1305   open+oid     pipe      538      428      857
chacha20poly1305   open+oid     file      339      363      404

parallel — mib_s
algo               pass        param       go     rust   kn-evp
aes256gcm          encrypt         1     5104     1813     6594
aes256gcm          encrypt         2     9897     3310    12674
aes256gcm          encrypt         4    19037     6591    23685
aes256gcm          encrypt         8    19239     8947    17798
chacha20poly1305   encrypt         1      678      558     1722
chacha20poly1305   encrypt         2     1295     1136     3330
chacha20poly1305   encrypt         4     3030     2051     6333
chacha20poly1305   encrypt         8     4208     2898     7473

envelope — ops_s
algo               pass        param   kn-lib
x25519-hkdf        wrap            1    16107
x25519-hkdf        wrap            4     4042
x25519-hkdf        wrap           16      921

startup — ms (STARTUP_RUNS=300)
algo               pass             jvm       go     rust   kn-evp
-                  noop           46.84     4.00     4.33     6.48
-                  crypto-init    93.28     4.20     3.09     7.64
```

## What we learned

### The object id hash costs more than the encryption

This is the result that changes the picture, and it survives the noise comfortably.
SHA-256 runs at around 1700–2250 MiB/s on this host.
AES-256-GCM runs at around 5700–6600.
So on AES hardware **the hash is roughly three times more expensive than the cipher** —
and git-lfs computes that hash over the plaintext whether or not the object is encrypted.

The `stream` suite shows where the cost goes.
Its `null`-sink throughput is in the region you get by running the cipher pass
and the hash pass back to back, rather than either one alone:

```
kn-evp, aes256gcm:   1/5698 + 1/1696  ->  1307 predicted, 1523 measured
kn-evp, chacha20:    1/1441 + 1/1696  ->   779 predicted,   877 measured
```

The measured figures run 12–17% ahead of that simple model here,
and landed 1–2% *behind* it on an earlier run,
so the honest reading is that the two passes roughly add
and nothing large is being lost to framing or buffering.
The bytes are simply traversed twice.

The practical consequence does not depend on the model's precision:
a noumen LFS client should not think of itself as paying for encryption.
It pays for a plaintext hash it owes anyway, and gets encryption at the margin.

### Bulk AEAD is not the bottleneck; the write path is

Every implementation is far above realistic upload bandwidth,
so encryption can run inline while streaming to object storage.
Below the cipher, the sinks cost a consistent amount independent of the algorithm:

| sink                       | implied stage throughput |
|----------------------------|--------------------------|
| pipe to a draining child   | ~4.0 GiB/s               |
| write to a real file       | ~1.7 GiB/s               |

Writing to a file through the page cache is more than twice as expensive as writing to a pipe,
which is the opposite of the intuition that a local write should be the cheap case.
For noumen it is the reassuring direction:
the LFS path streams to a socket, not to disk.

### Kotlin/Native is not giving anything up on throughput

`kn-evp` is the fastest column in the table —
not merely the fastest Kotlin, but faster than Go, the JVM and Rust on both ciphers.

The sharper check is against OpenSSL's own benchmark harness on the same machine.
`openssl speed -evp`, at its largest block size of 16 KiB, reports:

| algorithm         | `openssl speed` | `kn-evp` (64 KiB chunks, IV re-init per chunk) |
|-------------------|-----------------|------------------------------------------------|
| AES-256-GCM       | 6394 MiB/s      | 5435–6502 MiB/s over repeated runs             |
| ChaCha20-Poly1305 | 1746 MiB/s      | 1441–1721 MiB/s over repeated runs             |

Kotlin/Native brackets OpenSSL's own figure rather than trailing it,
which is as much as this host's ±10% spread can establish —
but it is enough to say that driving EVP through cinterop,
and re-initialising an IV for every chunk,
cost nothing that shows up above the noise floor.
That is the thing SCOPE.md needed to be true.

`kn-lib` still loses to it — roughly 1.3x on ChaCha20 and 3x on AES-GCM —
so the split SCOPE.md plans for is the right one:
cryptography-kotlin for the envelope, EVP directly for the STREAM path.
(The 4x figure from the earlier Xeon measurements narrows here;
the shape of the finding survives, the magnitude is host-dependent.)

### The startup argument for native holds, and the crypto tax is negligible

Measured over 300 invocations each:

| | to `main` | with a cipher ready |
|---|---|---|
| JVM            | ~47 ms  | ~93 ms  |
| Kotlin/Native  | ~6.5 ms | ~7.6 ms |
| Go             | ~4.0 ms | ~4.2 ms |
| Rust           | ~4.3 ms | ~3.1 ms |

For a helper git invokes repeatedly, the JVM's order of magnitude is the whole argument,
and it is settled.

Two smaller observations.
Kotlin/Native starts about 1.6x slower than Go or Rust —
real, but nowhere near mattering.
And bringing up the OpenSSL provider costs it **under a millisecond**,
against effectively zero for Go and Rust,
whose crypto-init figures sit inside their own measurement noise.
An earlier, more lightly sampled run put that tax at 1.25 ms and another at 4 ms;
at 300 invocations it settles below 1 ms.
It is not a reason to avoid OpenSSL.

### Parallel chunking works, and stops paying at four cores

The counter-nonce construction makes chunks independent,
and the tests assert that parallel output is byte-identical to serial output,
so this is exact rather than approximate.

Scaling is near-linear to 4 workers (3.7x for ChaCha20) and then flattens —
this host has 4 performance cores and 4 efficiency cores,
and the curve finds that boundary rather than a software limit.
`kotlin.native.concurrent.Worker` was adequate;
it needs an `ObsoleteWorkersApi` opt-in but has no throughput cost.

Given the previous findings, parallelism matters for local verification and re-chunking,
not for upload — one core already exceeds any plausible network.

### The envelope, not the bulk path, is what limits many-small-objects

X25519 + HKDF wrapping runs at about 16k operations per second for a single recipient,
and scales as you would expect: 4,042/s at four recipients, 921/s at sixteen.

A push of ten thousand small git objects to a sixteen-member repository
therefore spends around eleven seconds in the envelope
and almost no time at all in the cipher.
That is the inverse of the LFS case,
and it is the number to watch if noumen wraps a file key per object rather than per push.

### XChaCha20 framing is free at runtime and costs a primitive to maintain

XChaCha20 and ChaCha20-Poly1305 have to perform identically here,
because in this framing XChaCha20 *is* ChaCha20-Poly1305 —
under a subkey derived once per object, and that derivation is not measurable
against a 128 MiB payload.
The numbers behave accordingly without being tidy about it:
1692 against 1441 MiB/s sealing, 1532 against 1568 opening.
The two passes disagree about which is faster,
which is what measurement noise looks like rather than a real difference.

The cost is somewhere else entirely.
Neither OpenSSL 3 nor cryptography-kotlin 0.6.0 provides XChaCha20-Poly1305 —
OpenSSL exposes only `ChaCha20` and `ChaCha20-Poly1305` —
so the Kotlin/Native client has to hand-write the HChaCha20 permutation and own it as a cryptographic primitive.
Go (`chacha20.HChaCha20`) and Rust (`chacha20::hchacha`) both ship it;
Kotlin/Native does not.
[XChaCha.kt](src/nativeMain/kotlin/XChaCha.kt) is that code,
pinned to the specification's test vector.

For SCOPE.md §10 this is the whole argument:
the two framings perform identically,
so the decision is about which one leaves less cryptography in noumen's own hands.
That is age STREAM.

### Hand-writing the primitives in Kotlin costs an order of magnitude

SHA-256 and ChaCha20 are both small enough to implement correctly in an afternoon,
and both are frozen specifications that will never change.
That makes them the obvious candidates for owning outright
rather than linking a C library — so the `kn-pure` column implements both in plain Kotlin.
They agree with OpenSSL byte for byte,
across every SHA-256 padding boundary and every ChaCha20 block boundary.
They are simply slow:

| algorithm            | `kn-pure` | OpenSSL     | ratio |
|----------------------|-----------|-------------|-------|
| SHA-256              | 173 MiB/s | 2252 MiB/s  | 13x   |
| ChaCha20 (keystream) | 175 MiB/s | 2285 MiB/s  | 13x   |

The SHA-256 result has an easy explanation.
This machine reports `FEAT_SHA256`,
OpenSSL uses the ARMv8 `sha256h`/`sha256su0` instructions,
and Kotlin/Native offers neither intrinsics for them nor inline assembly.
Reaching those instructions means cinterop into C —
at which point OpenSSL is already there and already doing it.

**The ChaCha20 result is the one that settles the question.**
No processor has a ChaCha instruction;
every implementation, OpenSSL's included, is add-rotate-xor over vector registers.
No hardware advantage is being conceded,
so the 13x is purely the distance between what Kotlin/Native's code generator emits
and what OpenSSL's hand-written NEON assembly does.
And it flatters the hand-written version twice over:
`kn-pure` measures the keystream *without* Poly1305,
so a genuine hand-written AEAD would be slower still.

At ~175 MiB/s a hand-written primitive would be several times slower than the NVMe feeding it,
and would become the bottleneck for every operation noumen performs.

There is no startup argument for it either.
Avoiding OpenSSL to save its sub-millisecond initialisation only pays
if nothing else needs the library —
but SSH-key recipients force X25519 or RSA-OAEP into the envelope,
and the Ed25519-to-X25519 conversion an `ssh-ed25519` recipient requires
is exactly the kind of code nobody should hand-write.
The library has to be initialised regardless.

### A warning about RustCrypto build configuration

The Rust column is the slowest here, and it very nearly told a much worse story.
RustCrypto gates its aarch64 hardware backends behind crate-specific `--cfg` flags
rather than on target features,
so a default `--release` build silently takes the software path in three separate places:

```
chacha20poly1305   327 ->  573 MiB/s   (chacha20_force_neon)
aes256gcm          141 -> 1912 MiB/s   (aes_armv8 + polyval_armv8)
sha256             338 -> 2092 MiB/s   (sha2 "asm" feature)
```

The earlier revision of this README concluded that "RustCrypto's `aes-gcm` is noticeably slower
than Go's and the JDK's GHASH".
Most of that gap was build configuration, not the crates.
The flags are documented in [rust/.cargo/config.toml](rust/.cargo/config.toml);
a Rust client should still also benchmark `ring` or `aws-lc-rs`,
but not for the reason previously given here.

### Caveats

- The `stream` suite reads through a warm page cache,
  so its numbers are a CPU-and-syscall ceiling, not a disk benchmark.
- One host, one architecture, one run.
  The ratios are the point; the absolute values are not portable,
  and the AES/ChaCha20 relationship in particular depends entirely on the hardware's AES support.
- The `aead` suite excludes the object id hash, which the `stream` suite shows is the dominant cost.
  Read `aead` as a cipher ceiling, not as a client's throughput.
- `kn-pure`'s ChaCha20 row is an unauthenticated keystream, deliberately compared against
  OpenSSL's raw `ChaCha20` rather than against ChaCha20-Poly1305.
  It is an upper bound on a hand-written AEAD, not one.
- Repeated runs on this host vary by about ±10% on the `aead` suite.
  Every conclusion above is one that survives that margin;
  differences smaller than it are not claimed as findings.

## Development

See [DEVELOPMENT.md](DEVELOPMENT.md) for the CSV protocol,
the environment variables,
and how to add a suite or an implementation.
## Documentation conventions

All the Markdown files in this project are authored with
[semantic line breaks](https://sembr.org/).
Each sentence starts on its own line,
and long sentences may be split further at clause boundaries.
This keeps `git diff` and code review focused on the sentence that actually changed,
instead of on a whole reflowed paragraph.

There is no maximum line length,
and paragraphs are never hard-wrapped to a fixed column.
Line length is a rendering concern,
so it is left to the editor.

### Markdown soft wrapping in the IDE

**IntelliJ IDEA**:
`Settings` → `Editor` → `General` → `Soft Wraps`,
enable `Soft-wrap these files` and make sure the mask contains `*.md`
(the default mask already does).
To toggle it for the file at hand only,
use `View` → `Active Editor` → `Soft-Wrap`.

**VS Code**:
add the following to your `settings.json`:

```json
{
  "[markdown]": {
    "editor.wordWrap": "on"
  }
}
```

Alternatively toggle it for the current file with `Alt`+`Z` (`Option`+`Z` on macOS).
