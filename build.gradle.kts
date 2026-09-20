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

@file:OptIn(ExperimentalKotlinGradlePluginApi::class)

import org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi
import org.jetbrains.kotlin.gradle.dsl.KotlinVersion
import org.jetbrains.kotlin.konan.target.HostManager
import org.jetbrains.kotlin.konan.target.KonanTarget
import java.io.File

plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.kotlin.plugin.power.assert)
    alias(libs.plugins.version.catalog.update)
    alias(libs.plugins.xemantic.conventions)
}

group = "com.xemantic.noumen"

xemantic {
    description = "Benchmarks for noumen's cryptographic primitives"
    inceptionYear = "2026"
    applyAllConventions()
}

val kotlinTarget = KotlinVersion.fromVersion(libs.versions.kotlinTarget.get())

kotlin {

    compilerOptions {
        apiVersion = kotlinTarget
        languageVersion = kotlinTarget
        extraWarnings = true
        progressiveMode = true
    }

    // The JVM comparison, built by Gradle alongside the native benchmark. It shares
    // nothing but the language with it: javax.crypto has no Kotlin/Native counterpart
    // and the OpenSSL cinterop has no JVM one, so there is no common source set.
    jvm()

    // The native benchmark reaches OpenSSL through cinterop. The Go and Rust
    // comparisons are separate programs built by bench.sh, not by Gradle.
    //
    // By default only the host's own target is configured, which is all a local
    // benchmark run needs. Pass -PallNativeTargets (as CI does) to configure the
    // whole matrix; kotlin.native.ignoreDisabledTargets=true in gradle.properties
    // then skips the ones the current host cannot build.
    val allNativeTargets = providers.gradleProperty("allNativeTargets").isPresent

    val targets = if (allNativeTargets) {
        listOf(linuxX64(), linuxArm64(), macosArm64(), macosX64())
    } else listOf(
        when (val host = HostManager.host) {
            KonanTarget.LINUX_X64 -> linuxX64()
            KonanTarget.LINUX_ARM64 -> linuxArm64()
            KonanTarget.MACOS_ARM64 -> macosArm64()
            KonanTarget.MACOS_X64 -> macosX64()
            else -> error("unsupported host for the benchmark: $host")
        }
    )

    targets.forEach { target ->
        target.binaries.executable {
            baseName = "crypto-bench"
            entryPoint = "com.xemantic.noumen.crypto.bench.main"
        }
    }

    sourceSets {

        nativeMain {
            dependencies {
                implementation(libs.cryptography.core)
                implementation(libs.cryptography.provider.openssl3.prebuilt)
                // raw EVP cinterop bindings, used by the `kn-evp` variant
                implementation(libs.cryptography.provider.openssl3.api)
            }
        }

        nativeTest {
            dependencies {
                implementation(libs.kotlin.test)
                implementation(libs.xemantic.kotlin.test)
            }
        }

    }

}

repositories {
    mavenCentral()
}

// bench.sh runs the JVM benchmark in a bare `java` process, outside Gradle, so that
// nothing but the JVM is being timed and the shell's SIZE_MIB/ITERS reach it. This
// task compiles it and writes down the classpath for that `java` invocation.
tasks.register("jvmBenchClasspath") {
    val classpath = kotlin.jvm().compilations.getByName("main").let {
        it.output.allOutputs + it.runtimeDependencyFiles
    }
    val target = layout.buildDirectory.file("bench/jvm-classpath.txt")
    inputs.files(classpath)
    outputs.file(target)
    doLast {
        target.get().asFile.writeText(
            classpath.joinToString(File.pathSeparator)
        )
    }
}

powerAssert {
    functions = listOf(
        "com.xemantic.kotlin.test.assert",
        "com.xemantic.kotlin.test.have"
    )
}

versionCatalogUpdate {
    // preserve the manual, logically-grouped ordering of libs.versions.toml
    sortByKey = false
    keep {
        // kotlinTarget is a plain version constant with no version.ref
        versions = setOf("kotlinTarget")
        keepUnusedVersions = false
    }
}
