# Development

Maintenance notes for working on this project itself.

## Update gradlew wrapper

```shell
./gradlew wrapper --gradle-version latest --distribution-type bin
```

## Native targets

`./gradlew build` configures only the Kotlin/Native target of the host it runs on,
which is all [bench.sh](bench.sh) needs.
To configure the whole matrix — `linuxX64`, `linuxArm64`, `macosArm64`, `macosX64` — pass `-PallNativeTargets`,
as CI does;
targets the host cannot build are then skipped rather than failing the build.

## Update dependencies

Gradle dependencies are pinned in [libs.versions.toml](gradle/libs.versions.toml).
When bumping `cryptographyKotlin`, check which Kotlin version its klibs were compiled with
and keep `kotlin` at or above it.

Go and Rust dependencies live in `go/go.mod` and `rust/Cargo.toml` respectively.

## The measurement protocol

Every binary prints one CSV line per measurement on stdout:

```
impl,suite,algo,pass,param,unit,value
```

- `impl` — `jvm`, `go`, `rust`, `kn-lib`, `kn-evp`. Each binary labels its own output;
  the Kotlin/Native executable carries both `kn-lib` and `kn-evp` and emits both names.
- `suite` — `aead`, `stream`, `parallel`, `envelope`. The `startup` suite is timed externally.
- `param` — whatever the suite varies (worker count, sink, recipient count), or `-`.
- `unit` — `mib_s`, `ms` or `ops_s`.

[bench.sh](bench.sh) collects those lines and pivots them into one table per suite.
It has no knowledge of which algorithms or implementations exist,
so a new row or column needs no change to the table code —
an implementation that does not carry a suite simply prints nothing for it,
and the cell renders as `-`.

## Selecting suites

```shell
./bench.sh                     # every suite
./bench.sh stream parallel     # just these
SIZE_MIB=1024 ITERS=10 ./bench.sh
```

Each binary takes the suite name as its first argument,
so a single implementation can be run directly while working on it:

```shell
SIZE_MIB=64 ./go/crypto-bench stream
```

Environment variables: `SIZE_MIB`, `ITERS`, `CHUNK_KIB` (Kotlin/Native only, probes
per-call versus per-byte overhead), `MAX_WORKERS`, `STARTUP_RUNS`.

## Adding an implementation

Print the CSV lines described above, keeping the construction identical:
64 KiB plaintext chunks, an 11-byte big-endian counter nonce plus a last-chunk flag,
one tag per chunk.
Add the new `impl` name to the `impls` list in `bench.sh`'s `pivot` function —
that list only fixes column *order*; membership is discovered from the data.

Implement whichever suites make sense.
Nothing requires an implementation to carry all of them,
and the existing ones deliberately do not:
the JVM carries `aead` and `startup` only, because `SCOPE.md` rules it out as a client runtime,
and `envelope` is Kotlin/Native only, because that is where the decision lives.

## Adding a suite

Add it to `ALL_SUITES` in `bench.sh`, implement it behind the suite name in each
binary that should carry it, and emit rows. The table code needs no change.

## Watch out for build configuration

RustCrypto gates its hardware backends behind crate-specific `--cfg` flags rather than
on target features, so a default `aarch64` release build silently takes the software path.
See [rust/.cargo/config.toml](rust/.cargo/config.toml) for the flags and what each is worth;
on Apple Silicon they are collectively the difference between 141 and 1912 MiB/s for AES-GCM.
A benchmark run without them measures the build configuration rather than the crates,
so check the equivalent before trusting any new implementation's numbers.
