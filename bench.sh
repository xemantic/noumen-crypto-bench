#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: 2026 Kazimierz Pogoda / Xemantic
# SPDX-License-Identifier: AGPL-3.0-only
#
# noumen-crypto-bench - benchmarks for noumen's cryptographic primitives
# Copyright (C) 2026 Kazimierz Pogoda / Xemantic
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public
# License along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# Builds every implementation, runs the selected suites, and prints one table
# per suite.
#
#   ./bench.sh                     # every suite
#   ./bench.sh stream parallel     # just these
#   SIZE_MIB=1024 ITERS=10 ./bench.sh
#
# Each binary prints one CSV line per measurement:
#
#     impl,suite,algo,pass,param,unit,value
#
# and this script does nothing but collect and pivot them, so adding a suite or
# an implementation needs no change to the table code below.
#
# Requires: JDK 21+ (also used by Gradle), Go 1.23+, a Rust toolchain.
# The Kotlin/Native compiler and the prebuilt OpenSSL are fetched by Gradle.
set -euo pipefail
cd "$(dirname "$0")"

export SIZE_MIB="${SIZE_MIB:-256}" ITERS="${ITERS:-5}"
# The `startup` suite times whole processes from the outside, so it needs many
# invocations to resolve a millisecond.
STARTUP_RUNS="${STARTUP_RUNS:-100}"

ALL_SUITES="aead stream parallel envelope startup"
SUITES="${*:-$ALL_SUITES}"
for s in $SUITES; do
  case " $ALL_SUITES " in
    *" $s "*) ;;
    *) echo "unknown suite: $s (want one of: $ALL_SUITES)" >&2; exit 1 ;;
  esac
done

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)   KN_TARGET=linuxX64;   KN_TASK=LinuxX64 ;;
  Linux-aarch64)  KN_TARGET=linuxArm64; KN_TASK=LinuxArm64 ;;
  Darwin-arm64)   KN_TARGET=macosArm64; KN_TASK=MacosArm64 ;;
  Darwin-x86_64)  KN_TARGET=macosX64;   KN_TASK=MacosX64 ;;
  *) echo "unsupported host for Kotlin/Native: $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac

echo "# building..." >&2
( cd go   && go mod tidy >/dev/null 2>&1 && go build -o crypto-bench . )
( cd rust && cargo build --release --quiet )
./gradlew -q jvmBenchClasspath "linkReleaseExecutable$KN_TASK"

JVM_CP="$(cat build/bench/jvm-classpath.txt)"
KN_BIN="./build/bin/$KN_TARGET/releaseExecutable/crypto-bench.kexe"
OUT="$(mktemp)"
trap 'rm -f "$OUT"' EXIT

# Every implementation, as a command prefix. The Kotlin/Native binary carries
# both `kn-lib` and `kn-evp` and labels its own output accordingly.
jvm_cmd=(java -cp "$JVM_CP" com.xemantic.noumen.crypto.bench.MainKt)
go_cmd=(./go/crypto-bench)
rust_cmd=(./rust/target/release/noumen-crypto-bench)
kn_cmd=("$KN_BIN")

run_suite() {
  local suite="$1" name cmd
  for name in jvm go rust kn; do
    eval "cmd=(\"\${${name}_cmd[@]}\")"
    "${cmd[@]}" "$suite" | tee -a "$OUT"
  done
}

# Times STARTUP_RUNS invocations of a whole process and reports the mean in
# milliseconds. The shell's own `time` is used rather than a per-process clock
# precisely because what matters here happens before main() is entered.
time_startup() {
  local impl="$1" mode="$2"; shift 2
  local elapsed
  TIMEFORMAT='%R'
  elapsed=$( { time ( for _ in $(seq 1 "$STARTUP_RUNS"); do "$@" "$mode" >/dev/null 2>&1; done ) ; } 2>&1 )
  awk -v t="$elapsed" -v n="$STARTUP_RUNS" -v i="$impl" -v m="$mode" \
    'BEGIN { printf "%s,startup,-,%s,-,ms,%.2f\n", i, m, t * 1000 / n }' | tee -a "$OUT"
}

run_startup() {
  local name impl cmd
  for name in jvm go rust kn; do
    eval "cmd=(\"\${${name}_cmd[@]}\")"
    impl="$name"; [ "$name" = kn ] && impl="kn-evp"
    time_startup "$impl" noop "${cmd[@]}"
    time_startup "$impl" crypto-init "${cmd[@]}"
  done
}

for suite in $SUITES; do
  echo "# running $suite (SIZE_MIB=$SIZE_MIB ITERS=$ITERS)..." >&2
  if [ "$suite" = startup ]; then run_startup; else run_suite "$suite"; fi
done

# One table per suite. Rows are (algo, pass, param), columns are the
# implementations that reported anything; the `param` column appears only when
# a suite actually varies something.
pivot() {
  sort -t, -k3,3 -k4,4 -k5,5n "$OUT" |
    awk -F, -v suite="$1" -v impls="jvm,go,rust,kn-lib,kn-pure,kn-evp" '
      BEGIN { ni = split(impls, I, ",") }
      $2 == suite {
        k = $3 "\034" $4 "\034" $5
        if (!(k in seen)) { seen[k] = ++n; ord[n] = k }
        v[k, $1] = $7
        unit = $6
        if ($5 != "-") param = 1
        present[$1] = 1
      }
      END {
        if (n == 0) exit
        for (i = 1; i <= ni; i++) if (I[i] in present) cols[++nc] = I[i]
        printf "\n%s — %s\n", suite, unit
        printf "%-18s %-11s", "algo", "pass"
        if (param) printf " %5s", "param"
        for (i = 1; i <= nc; i++) printf " %8s", cols[i]
        printf "\n"
        for (r = 1; r <= n; r++) {
          split(ord[r], p, "\034")
          printf "%-18s %-11s", p[1], p[2]
          if (param) printf " %5s", p[3]
          for (i = 1; i <= nc; i++) {
            key = ord[r] SUBSEP cols[i]
            printf " %8s", (key in v) ? v[key] : "-"
          }
          printf "\n"
        }
      }
    '
}

echo
echo "median of $ITERS passes over $SIZE_MIB MiB; startup is the mean of $STARTUP_RUNS invocations"
for suite in $SUITES; do pivot "$suite"; done
