# CLAUDE.md

This file captures only what cannot be inferred from the codebase itself.

## Rules for editing this file

Both developers and AI agents are expected to add entries as they encounter surprises.

- **Add an entry** when you encounter something unexpected: a build quirk, a non-obvious constraint, a dependency gotcha, or any behavior that would surprise the next agent or developer.
- **Add an entry** when a developer flags an anti-pattern produced by AI — describe the anti-pattern and the preferred alternative.
- **Do not** add codebase overviews, directory listings, or anything discoverable by reading the source.
- Keep entries concise: one line per lesson, grouped under a heading if a theme emerges.

## Conventions

### Markdown authoring

Markdown files use [semantic line breaks](https://sembr.org/):
break a line after a sentence,
and optionally at clause boundaries within a long sentence,
so that diffs stay meaningful and reviewable.

There is no column width limit —
never reflow or hard-wrap a paragraph to fit some character count.
Modern editors soft-wrap Markdown visually,
see the [README](README.md#markdown-soft-wrapping-in-the-ide) for how to enable it.

## Known gotchas

- cryptography-kotlin's `encryptWithIv`/`decryptWithIv` require `@OptIn(DelicateCryptographyApi::class)`; the STREAM construction needs explicit per-chunk nonces, so the opt-in is intentional.
- `EVP_CTRL_AEAD_GET_TAG`/`SET_TAG` are C macros and are not exported by the cinterop bindings — they are redeclared as constants in `RawEvp.kt` (0x10 / 0x11).
- The raw EVP variant imports `dev.whyoleg.cryptography.providers.openssl3.internal.cinterop`; this is an internal package of `cryptography-provider-openssl3-api` and may move between releases.
- `RawEvp.kt` lives in the shared `nativeMain` source set, so it needs `kotlin.mpp.enableCInteropCommonization=true`; without it the per-target compilations still pass and only `compileNativeMainKotlinMetadata` fails, which only the multi-target build triggers — neither `bench.sh` nor a plain `./gradlew build` does, so CI (`-PallNativeTargets`) is the first place it would surface.
- `./gradlew build` configures only the host's own Kotlin/Native target;
  `-PallNativeTargets` configures the whole matrix and is what CI passes,
  with `kotlin.native.ignoreDisabledTargets=true` skipping the ones the host cannot build.
- The JVM benchmark must not be run through a Gradle `JavaExec` task:
  the Gradle daemon has its own long-lived environment,
  so the `SIZE_MIB`/`ITERS` that `bench.sh` exports would never reach the forked JVM.
  Gradle only compiles it and writes the runtime classpath (`jvmBenchClasspath`);
  `bench.sh` runs it in a bare `java` process.
- Neither OpenSSL 3 nor cryptography-kotlin 0.6.0 provides XChaCha20-Poly1305
  (OpenSSL exposes only `ChaCha20` and `ChaCha20-Poly1305`),
  so `XChaCha.kt` hand-writes HChaCha20;
  Go (`chacha20.HChaCha20`) and Rust (`chacha20::hchacha`) both ship it.
- An `EVP_CIPHER_CTX` is not safe to share between threads,
  so the parallel suite gives every worker its own `RawAead`.
- `kotlin.native.concurrent.Worker` needs `@OptIn(ObsoleteWorkersApi::class)`.
  It is still the supported API in 2.4.20,
  and the annotation is not a recent regression — it is identical in 2.3.20 through 2.4.20.
- cryptography-kotlin 0.6.0's klibs are compiled with Kotlin 2.3.20 (`abi_version=2.3.0`)
  while this project compiles at 2.4.20,
  and `RawEvp.kt` additionally depends on that library's *internal* cinterop package,
  so both are worth re-checking on any upgrade.
- X25519 is a curve, not an algorithm object, in cryptography-kotlin:
  reach it through `provider.get(XDH).keyPairGenerator(XDH.Curve.X25519)`.
- RustCrypto gates its aarch64 hardware backends behind crate-specific `--cfg` flags
  (`aes_armv8`, `polyval_armv8`, `chacha20_force_neon`) and a `sha2` crate feature,
  rather than on target features.
  Without them a release build silently runs the software paths, costing AES-GCM about 13x;
  see `rust/.cargo/config.toml`.
- Hand-written Kotlin primitives run ~13x slower than OpenSSL's, measured in the `kn-pure` column:
  SHA-256 because Kotlin/Native cannot emit the ARMv8 `sha256h` instructions,
  and ChaCha20 — which no hardware accelerates — purely on code generation.
  Do not replace an OpenSSL primitive with a Kotlin one without re-measuring this.
- Hex literals at or above `0x80000000` are `Long` in Kotlin and need an explicit `.toInt()`;
  `PureSha256.kt`'s constant tables are full of them.
- `assert(cond) { message }` resolves to `kotlin.assert`, which needs `@OptIn(ExperimentalNativeApi::class)`
  on Kotlin/Native — `com.xemantic.kotlin.test.assert` is single-argument only.
  Assert on a collected value instead, so power-assert can still show what differed.
- `mkdir`'s `mode_t` and the `S_I*` constants differ in width across targets,
  so calling them from the shared `nativeMain` source set fails `compileNativeMainKotlinMetadata`
  (again, only under `-PallNativeTargets`) — `BenchStream.kt` uses `mkdtemp` and a literal mode instead.
- After upgrading the Gradle wrapper, native test tasks may fail with `NoSuchFileException: build/test-results/<target>Test/binary/in-progress-results-generic.bin`, because the results of the previous Gradle version are stale — delete `build/test-results` (or run `clean`) and retry.

## Anti-patterns to avoid

- Do not add content to this file that is already discoverable by reading the source or build scripts — that inflates context without adding signal, reducing AI agent task success rates (see [arxiv 2602.11988](https://arxiv.org/abs/2602.11988)).
