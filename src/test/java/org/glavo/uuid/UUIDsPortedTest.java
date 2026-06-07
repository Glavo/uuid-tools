// Copyright (c) 2026 Glavo
// SPDX-License-Identifier: MPL-2.0

package org.glavo.uuid;

import org.jetbrains.annotations.NotNullByDefault;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashSet;
import java.util.Random;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Additional behavior tests adapted from uuid-creator's public examples and
/// coverage areas.
@NotNullByDefault
class UUIDsPortedTest {

    /// A sample UUID used by uuid-creator codec documentation.
    private static final UUID SAMPLE = UUID.fromString("01234567-89ab-4def-a123-456789abcdef");

    /// The canonical text form of [#SAMPLE].
    private static final String SAMPLE_STANDARD = "01234567-89ab-4def-a123-456789abcdef";

    /// The compact text form of [#SAMPLE].
    private static final String SAMPLE_COMPACT = "0123456789ab4defa123456789abcdef";

    /// The Base62 text form of [#SAMPLE].
    private static final String SAMPLE_BASE62 = "0296tiiBY28FKCYq1PVSGd";

    /// Accepts all explicit text formats supported by [UUIDs#parse(String)].
    @Test
    void parseAcceptsExplicitTextFormats() {
        assertEquals(SAMPLE, UUIDs.parse(SAMPLE_STANDARD));
        assertEquals(SAMPLE, UUIDs.parse(SAMPLE_COMPACT));
        assertEquals(SAMPLE, UUIDs.parse("{" + SAMPLE_STANDARD + "}"));
        assertEquals(SAMPLE, UUIDs.parse("urn:uuid:" + SAMPLE_STANDARD));
        assertEquals(SAMPLE, UUIDs.parse("URN:UUID:" + SAMPLE_STANDARD.toUpperCase()));
    }

    /// Rejects text formats that are intentionally exposed through separate
    /// methods.
    @Test
    void parseRejectsBase62Text() {
        assertThrows(IllegalArgumentException.class, () -> UUIDs.parse(SAMPLE_BASE62));
        assertEquals(SAMPLE, UUIDs.parseBase62(SAMPLE_BASE62));
    }

    /// Encodes and decodes the published Base62 sample value.
    @Test
    void base62MatchesPublishedSample() {
        assertEquals(SAMPLE_BASE62, UUIDs.toBase62String(SAMPLE));
        assertEquals(SAMPLE, UUIDs.parseBase62(SAMPLE_BASE62));
    }

    /// Encodes object identifier strings for important unsigned 128-bit
    /// boundary values.
    @Test
    void oidStringHandlesUnsignedBoundaries() {
        assertEquals("2.25.0", UUIDs.toOIDString(UUIDs.NIL));
        assertEquals("2.25.1", UUIDs.toOIDString(new UUID(0L, 1L)));
        assertEquals("2.25.340282366920938463463374607431768211455", UUIDs.toOIDString(UUIDs.MAX));
    }

    /// Converts boundary UUIDs through the 16-byte binary representation.
    @Test
    void byteConversionHandlesBoundaries() {
        byte[] nil = new byte[16];
        byte[] max = {
                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF
        };

        assertArrayEquals(nil, UUIDs.toBytes(UUIDs.NIL));
        assertEquals(UUIDs.NIL, UUIDs.fromBytes(nil));
        assertArrayEquals(max, UUIDs.toBytes(UUIDs.MAX));
        assertEquals(UUIDs.MAX, UUIDs.fromBytes(max));
    }

    /// Decodes bytes from the requested offset without reading surrounding
    /// bytes.
    @Test
    void fromBytesReadsOnlyRequestedWindow() {
        byte[] bytes = new byte[20];
        byte[] sampleBytes = UUIDs.toBytes(SAMPLE);
        System.arraycopy(sampleBytes, 0, bytes, 2, sampleBytes.length);
        bytes[0] = 0x55;
        bytes[1] = 0x66;
        bytes[18] = 0x77;
        bytes[19] = 0x11;

        assertEquals(SAMPLE, UUIDs.fromBytes(bytes, 2));
    }

    /// Hashes only the remaining bytes of a byte buffer and consumes them.
    @Test
    void nameBasedUuidConsumesRemainingByteBuffer() {
        byte[] name = "www.example.com".getBytes(StandardCharsets.UTF_8);
        byte[] bytes = new byte[name.length + 3];
        bytes[0] = 0x55;
        bytes[1] = 0x66;
        System.arraycopy(name, 0, bytes, 2, name.length);
        bytes[bytes.length - 1] = 0x77;

        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        buffer.position(2);
        buffer.limit(2 + name.length);

        assertEquals(UUIDs.generateV5(UUIDs.NAMESPACE_DNS, name),
                UUIDs.generateV5(UUIDs.NAMESPACE_DNS, buffer));
        assertEquals(buffer.limit(), buffer.position());
    }

    /// Uses exactly two 64-bit random values for version 4 generation.
    @Test
    void generateV4UsesTwoRandomLongs() {
        Random random = new Random() {
            private int index;

            @Override
            public long nextLong() {
                return switch (index++) {
                    case 0 -> 0x0123_4567_89AB_CDEFL;
                    case 1 -> 0xFEDC_BA98_7654_3210L;
                    default -> throw new AssertionError("generateV4 requested too many random values");
                };
            }
        };

        assertEquals(UUID.fromString("01234567-89ab-4def-bedc-ba9876543210"), UUIDs.generateV4(random));
    }

    /// Sorts UUIDs as unsigned 128-bit integers.
    @Test
    void comparatorUsesUnsignedOrdering() {
        UUID positiveLeastSignificantBits = new UUID(0L, Long.MAX_VALUE);
        UUID negativeLeastSignificantBits = new UUID(0L, Long.MIN_VALUE);
        UUID negativeMostSignificantBits = new UUID(Long.MIN_VALUE, 0L);

        assertTrue(UUIDs.compare(positiveLeastSignificantBits, negativeLeastSignificantBits) < 0);
        assertTrue(UUIDs.compare(negativeLeastSignificantBits, negativeMostSignificantBits) < 0);
        assertEquals(UUIDs.compare(positiveLeastSignificantBits, negativeLeastSignificantBits),
                UUIDs.comparator().compare(positiveLeastSignificantBits, negativeLeastSignificantBits));
    }

    /// Generates a small uniqueness sample from default random-based methods.
    @Test
    void defaultGenerationProducesUniqueSample() {
        Set<UUID> values = new LinkedHashSet<>();
        for (int i = 0; i < 512; i++) {
            assertTrue(values.add(UUIDs.generateV4()));
            assertTrue(values.add(UUIDs.generateV7()));
        }
        assertEquals(1024, values.size());
    }

    /// Keeps all time-based fields intact when converting between version 1 and
    /// version 6.
    @Test
    void v1V6ConversionPreservesFields() {
        UUID v1 = UUIDs.v1(0x0FED_CBA9_8765_4321L, 0x2345, 0x0123_4567_89ABL);
        UUID v6 = UUIDs.convertV1ToV6(v1);

        assertEquals(UUIDs.getGregorianTimestamp(v1), UUIDs.getGregorianTimestamp(v6));
        assertEquals(UUIDs.getClockSequence(v1), UUIDs.getClockSequence(v6));
        assertEquals(UUIDs.getNode(v1), UUIDs.getNode(v6));
        assertEquals(v1, UUIDs.convertV6ToV1(v6));
    }

    /// Rejects binary input that cannot contain exactly one UUID.
    @Test
    void fromBytesRejectsInvalidWindows() {
        assertThrows(IllegalArgumentException.class, () -> UUIDs.fromBytes(new byte[15]));
        assertThrows(IllegalArgumentException.class, () -> UUIDs.fromBytes(new byte[17]));
        assertThrows(IndexOutOfBoundsException.class, () -> UUIDs.fromBytes(new byte[18], 3));
    }

    /// Identifies nil and max UUIDs by value instead of object identity.
    @Test
    void nilAndMaxChecksUseValueEquality() {
        assertTrue(UUIDs.isNil(new UUID(0L, 0L)));
        assertTrue(UUIDs.isMax(new UUID(-1L, -1L)));
        assertFalse(UUIDs.isNil(new UUID(0L, 1L)));
        assertFalse(UUIDs.isMax(new UUID(-1L, -2L)));
    }
}
