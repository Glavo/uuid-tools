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

import java.nio.ByteBuffer;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/// Throughput benchmarks that compare uuid-tools operations with JDK UUID
/// operations.
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(1)
@State(Scope.Thread)
@NotNullByDefault
public class UUIDsBenchmark {

    /// Sample UUID used by parse and format benchmarks.
    private static final UUID SAMPLE = new UUID(0x0123_4567_89AB_4DEFL, 0xA123_4567_89AB_CDEFL);

    /// Standard textual representation of [#SAMPLE].
    private static final String SAMPLE_STANDARD = "01234567-89ab-4def-a123-456789abcdef";

    /// Sample UUID with unsigned ordering different from signed ordering.
    private static final UUID UNSIGNED_ORDER_SAMPLE = new UUID(0x8123_4567_89AB_4DEFL, 0xA123_4567_89AB_CDEFL);

    /// Binary representation of [#SAMPLE].
    private static final byte[] SAMPLE_BYTES = UUIDs.toBytes(SAMPLE);

    /// Measures JDK random UUID generation with its default random source.
    @Benchmark
    public UUID jdkRandomUUID() {
        return UUID.randomUUID();
    }

    /// Measures uuid-tools version 4 generation with its default random source.
    @Benchmark
    public UUID uuidToolsGenerateV4() {
        return UUIDs.generateV4();
    }

    /// Measures uuid-tools version 7 generation with its default random source.
    @Benchmark
    public UUID uuidToolsGenerateV7() {
        return UUIDs.generateV7();
    }

    /// Measures uuid-tools standard UUID parsing.
    @Benchmark
    public UUID uuidToolsParseStandard() {
        return UUIDs.parse(SAMPLE_STANDARD);
    }

    /// Measures JDK standard UUID parsing.
    @Benchmark
    public UUID jdkFromString() {
        return UUID.fromString(SAMPLE_STANDARD);
    }

    /// Measures uuid-tools UUID to byte array conversion.
    @Benchmark
    public byte[] uuidToolsToBytes() {
        return UUIDs.toBytes(SAMPLE);
    }

    /// Measures equivalent UUID to byte array conversion using JDK primitives.
    @Benchmark
    public byte[] jdkToBytesWithByteBuffer() {
        return ByteBuffer.allocate(16)
                .putLong(SAMPLE.getMostSignificantBits())
                .putLong(SAMPLE.getLeastSignificantBits())
                .array();
    }

    /// Measures uuid-tools UUID from byte array conversion.
    @Benchmark
    public UUID uuidToolsFromBytes() {
        return UUIDs.fromBytes(SAMPLE_BYTES);
    }

    /// Measures equivalent UUID from byte array conversion using JDK primitives.
    @Benchmark
    public UUID jdkFromBytesWithByteBuffer() {
        ByteBuffer buffer = ByteBuffer.wrap(SAMPLE_BYTES);
        return new UUID(buffer.getLong(), buffer.getLong());
    }

    /// Measures uuid-tools unsigned UUID comparison.
    @Benchmark
    public int uuidToolsCompare() {
        return UUIDs.compare(SAMPLE, UNSIGNED_ORDER_SAMPLE);
    }

    /// Measures JDK UUID comparison.
    @Benchmark
    public int jdkCompareTo() {
        return SAMPLE.compareTo(UNSIGNED_ORDER_SAMPLE);
    }
}
