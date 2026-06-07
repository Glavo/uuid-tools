// Copyright (c) 2026 Glavo
// SPDX-License-Identifier: MPL-2.0

package org.glavo.uuid.benchmark;

import org.glavo.uuid.UUIDs;
import org.jetbrains.annotations.NotNullByDefault;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.InstantSource;
import java.util.SplittableRandom;
import java.util.UUID;
import java.util.random.RandomGenerator;
import java.util.concurrent.TimeUnit;

/// Throughput benchmarks for UUID creation, parsing, formatting, conversion,
/// and comparison paths.
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(1)
@State(Scope.Thread)
@NotNullByDefault
public class UUIDsBenchmark {

    /// Sample UUID used by parse and format benchmarks.
    private static final UUID SAMPLE = UUID.fromString("01234567-89ab-4def-a123-456789abcdef");

    /// Version 7 sample UUID used by timestamp accessor benchmarks.
    private static final UUID V7_SAMPLE = UUIDs.v7(1_718_000_000_000L, 0x123, 0x0123_4567_89AB_CDEFL);

    /// Standard textual representation of [#SAMPLE].
    private static final String SAMPLE_STANDARD = "01234567-89ab-4def-a123-456789abcdef";

    /// Compact textual representation of [#SAMPLE].
    private static final String SAMPLE_COMPACT = "0123456789ab4defa123456789abcdef";

    /// URN textual representation of [#SAMPLE].
    private static final String SAMPLE_URN = "urn:uuid:01234567-89ab-4def-a123-456789abcdef";

    /// Base62 textual representation of [#SAMPLE].
    private static final String SAMPLE_BASE62 = "0296tiiBY28FKCYq1PVSGd";

    /// Binary representation of [#SAMPLE].
    private static final byte[] SAMPLE_BYTES = UUIDs.toBytes(SAMPLE);

    /// Fixed instant source used to isolate random generation cost in v7.
    private static final InstantSource FIXED_INSTANT_SOURCE =
            InstantSource.fixed(Instant.ofEpochSecond(1, 123_456_700));

    /// Secure random source used by explicit-random benchmarks.
    private final SecureRandom secureRandom = new SecureRandom();

    /// Fast non-cryptographic random source used by explicit-random benchmarks.
    private final RandomGenerator splittableRandom = new SplittableRandom(0);

    /// Measures JDK random UUID generation.
    @Benchmark
    public UUID jdkRandomUUID() {
        return UUID.randomUUID();
    }

    /// Measures default version 4 UUID generation.
    @Benchmark
    public UUID generateV4Default() {
        return UUIDs.generateV4();
    }

    /// Measures version 4 generation with an explicit [SecureRandom].
    @Benchmark
    public UUID generateV4SecureRandom() {
        return UUIDs.generateV4(secureRandom);
    }

    /// Measures version 4 generation with an explicit fast random generator.
    @Benchmark
    public UUID generateV4SplittableRandom() {
        return UUIDs.generateV4(splittableRandom);
    }

    /// Measures default version 7 UUID generation.
    @Benchmark
    public UUID generateV7Default() {
        return UUIDs.generateV7();
    }

    /// Measures version 7 generation with a fixed instant source.
    @Benchmark
    public UUID generateV7FixedInstant() {
        return UUIDs.generateV7(FIXED_INSTANT_SOURCE, splittableRandom);
    }

    /// Measures standard UUID parsing.
    @Benchmark
    public UUID parseStandard() {
        return UUIDs.parse(SAMPLE_STANDARD);
    }

    /// Measures compact UUID parsing.
    @Benchmark
    public UUID parseCompact() {
        return UUIDs.parse(SAMPLE_COMPACT);
    }

    /// Measures URN UUID parsing.
    @Benchmark
    public UUID parseUrn() {
        return UUIDs.parse(SAMPLE_URN);
    }

    /// Measures explicit Base62 parsing.
    @Benchmark
    public UUID parseBase62() {
        return UUIDs.parseBase62(SAMPLE_BASE62);
    }

    /// Measures standard UUID formatting.
    @Benchmark
    public String formatStandard() {
        return SAMPLE.toString();
    }

    /// Measures compact UUID formatting.
    @Benchmark
    public String formatCompact() {
        return UUIDs.toCompactString(SAMPLE);
    }

    /// Measures URN UUID formatting.
    @Benchmark
    public String formatUrn() {
        return UUIDs.toURNString(SAMPLE);
    }

    /// Measures Base62 UUID formatting.
    @Benchmark
    public String formatBase62() {
        return UUIDs.toBase62String(SAMPLE);
    }

    /// Measures OID UUID formatting.
    @Benchmark
    public String formatOid() {
        return UUIDs.toOIDString(SAMPLE);
    }

    /// Measures UUID to byte array conversion.
    @Benchmark
    public byte[] toBytes() {
        return UUIDs.toBytes(SAMPLE);
    }

    /// Measures UUID from byte array conversion.
    @Benchmark
    public UUID fromBytes() {
        return UUIDs.fromBytes(SAMPLE_BYTES);
    }

    /// Measures unsigned UUID comparison.
    @Benchmark
    public int compare() {
        return UUIDs.compare(SAMPLE, V7_SAMPLE);
    }

    /// Measures version 7 Unix millisecond timestamp extraction.
    @Benchmark
    public long getUnixTimestampMillis() {
        return UUIDs.getUnixTimestampMillis(V7_SAMPLE);
    }
}
