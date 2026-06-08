// Copyright (c) 2026 Glavo
// SPDX-License-Identifier: MPL-2.0

package org.glavo.uuid;

import com.github.f4b6a3.uuid.codec.base.Base62Codec;
import org.jetbrains.annotations.NotNullByDefault;
import org.jetbrains.annotations.Unmodifiable;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.SplittableRandom;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/// Detailed Base62 codec tests with fixed vectors, independent reference
/// checks, and uuid-creator compatibility coverage.
@NotNullByDefault
class UUIDsBase62Test {
    /// The Base62 digit set used by uuid-creator and uuid-tools.
    private static final String BASE62_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    /// The Base62 radix as a reusable `BigInteger`.
    private static final BigInteger BASE62_RADIX = BigInteger.valueOf(62L);

    /// The uuid-creator Base62 codec used as an external compatibility oracle.
    private static final Base62Codec UUID_CREATOR_BASE62 = Base62Codec.INSTANCE;

    /// Fixed Base62 vectors covering leading zeroes and unsigned 128-bit
    /// boundaries.
    private static final Base62Fixture @Unmodifiable [] BASE62_FIXTURES = {
            new Base62Fixture(UUIDs.NIL, "0000000000000000000000"),
            new Base62Fixture(new UUID(0L, 1L), "0000000000000000000001"),
            new Base62Fixture(new UUID(0L, 61L), "000000000000000000000z"),
            new Base62Fixture(new UUID(0L, 62L), "0000000000000000000010"),
            new Base62Fixture(new UUID(0L, Long.MAX_VALUE), "00000000000AzL8n0Y58m7"),
            new Base62Fixture(new UUID(0L, Long.MIN_VALUE), "00000000000AzL8n0Y58m8"),
            new Base62Fixture(new UUID(Long.MIN_VALUE, 0L), "3tX16dB2jpss4tZORYcqo4"),
            new Base62Fixture(
                    UUID.fromString("01234567-89ab-4def-a123-456789abcdef"),
                    "0296tiiBY28FKCYq1PVSGd"),
            new Base62Fixture(
                    UUID.fromString("550e8400-e29b-41d4-a716-446655440000"),
                    "2aUyqjCzEIiEcYMKj7TZtw"),
            new Base62Fixture(new UUID(-1L, -2L), "7n42DGM5Tflk9n8mt7Fhc6"),
            new Base62Fixture(UUIDs.MAX, "7n42DGM5Tflk9n8mt7Fhc7"),
    };

    /// Checks fixed Base62 vectors against encoding and decoding.
    @Test
    void base62FixedVectorsRoundTrip() {
        for (Base62Fixture fixture : BASE62_FIXTURES) {
            assertEquals(fixture.encoded(), UUIDs.toBase62String(fixture.uuid()));
            assertEquals(fixture.uuid(), UUIDs.parseBase62(fixture.encoded()));
        }
    }

    /// Matches uuid-creator's Base62 codec for fixed and deterministic random
    /// UUID values.
    @Test
    void base62MatchesUuidCreator() {
        for (Base62Fixture fixture : BASE62_FIXTURES) {
            assertMatchesUuidCreator(fixture.uuid());
        }

        SplittableRandom random = new SplittableRandom(62L);
        for (int i = 0; i < 512; i++) {
            assertMatchesUuidCreator(nextUuid(random));
        }
    }

    /// Matches an independent unsigned `BigInteger` Base62 codec for
    /// deterministic random UUID values.
    @Test
    void base62MatchesIndependentBigIntegerCodec() {
        for (Base62Fixture fixture : BASE62_FIXTURES) {
            assertMatchesBigIntegerCodec(fixture.uuid());
        }

        SplittableRandom random = new SplittableRandom(0x6261_7365_3632L);
        for (int i = 0; i < 512; i++) {
            assertMatchesBigIntegerCodec(nextUuid(random));
        }
    }

    /// Rejects Base62 strings whose unsigned value is larger than 128 bits.
    @Test
    void parseBase62RejectsOverflowBoundaries() {
        assertThrows(IllegalArgumentException.class,
                () -> UUIDs.parseBase62("7n42DGM5Tflk9n8mt7Fhc8"));
        assertThrows(IllegalArgumentException.class,
                () -> UUIDs.parseBase62("7n42DGM5Tflk9n8mt7Fhcz"));
        assertThrows(IllegalArgumentException.class,
                () -> UUIDs.parseBase62("8000000000000000000000"));
        assertThrows(IllegalArgumentException.class,
                () -> UUIDs.parseBase62("zzzzzzzzzzzzzzzzzzzzzz"));
    }

    /// Rejects values that do not have exactly 22 Base62 digits.
    @Test
    void parseBase62RejectsInvalidLengths() {
        assertThrows(IllegalArgumentException.class, () -> UUIDs.parseBase62(""));
        assertThrows(IllegalArgumentException.class, () -> UUIDs.parseBase62("0"));
        assertThrows(IllegalArgumentException.class,
                () -> UUIDs.parseBase62("000000000000000000000"));
        assertThrows(IllegalArgumentException.class,
                () -> UUIDs.parseBase62("00000000000000000000000"));
        assertThrows(IllegalArgumentException.class,
                () -> UUIDs.parseBase62("00000000000000000000000000000000"));
    }

    /// Rejects ASCII characters that are outside the Base62 alphabet.
    @Test
    void parseBase62RejectsInvalidAsciiDigits() {
        for (char c = 0; c < 128; c++) {
            if (BASE62_ALPHABET.indexOf(c) < 0) {
                String candidate = "000000000000000000000" + c;
                assertThrows(IllegalArgumentException.class, () -> UUIDs.parseBase62(candidate),
                        "Expected invalid Base62 character U+" + String.format("%04X", (int) c));
            }
        }
    }

    /// Rejects non-ASCII characters that resemble Base62 digits.
    @Test
    void parseBase62RejectsNonAsciiDigits() {
        assertThrows(IllegalArgumentException.class,
                () -> UUIDs.parseBase62("000000000000000000000\uFF10"));
        assertThrows(IllegalArgumentException.class,
                () -> UUIDs.parseBase62("000000000000000000000\uFF21"));
        assertThrows(IllegalArgumentException.class,
                () -> UUIDs.parseBase62("000000000000000000000\uFF41"));
        assertThrows(IllegalArgumentException.class,
                () -> UUIDs.parseBase62("000000000000000000000\u0391"));
    }

    /// Confirms fixed-width Base62 output preserves unsigned UUID ordering
    /// under lexicographic string comparison.
    @Test
    void fixedWidthBase62SortsByUnsignedUuidValue() {
        for (Base62Fixture left : BASE62_FIXTURES) {
            for (Base62Fixture right : BASE62_FIXTURES) {
                int uuidComparison = Integer.signum(UUIDs.compare(left.uuid(), right.uuid()));
                int textComparison = Integer.signum(left.encoded().compareTo(right.encoded()));
                assertEquals(uuidComparison, textComparison);
            }
        }
    }

    /// Asserts that uuid-tools and uuid-creator encode and decode a UUID in
    /// the same way.
    private static void assertMatchesUuidCreator(UUID uuid) {
        String encoded = UUIDs.toBase62String(uuid);
        assertEquals(UUID_CREATOR_BASE62.encode(uuid), encoded);
        assertEquals(uuid, UUIDs.parseBase62(encoded));
        assertEquals(uuid, UUID_CREATOR_BASE62.decode(encoded));
    }

    /// Asserts that uuid-tools and an independent `BigInteger` implementation
    /// encode and decode a UUID in the same way.
    private static void assertMatchesBigIntegerCodec(UUID uuid) {
        String encoded = UUIDs.toBase62String(uuid);
        assertEquals(encodeWithBigInteger(uuid), encoded);
        assertEquals(uuid, decodeWithBigInteger(encoded));
        assertEquals(uuid, UUIDs.parseBase62(encoded));
    }

    /// Encodes a UUID with an independent unsigned `BigInteger`
    /// implementation.
    private static String encodeWithBigInteger(UUID uuid) {
        BigInteger value = new BigInteger(1, toBytes(uuid));
        char[] output = new char[22];

        for (int i = output.length - 1; i >= 0; i--) {
            BigInteger[] division = value.divideAndRemainder(BASE62_RADIX);
            output[i] = BASE62_ALPHABET.charAt(division[1].intValue());
            value = division[0];
        }

        return new String(output);
    }

    /// Decodes a Base62 string with an independent unsigned `BigInteger`
    /// implementation.
    private static UUID decodeWithBigInteger(String encoded) {
        BigInteger value = BigInteger.ZERO;

        for (int i = 0; i < encoded.length(); i++) {
            int digit = BASE62_ALPHABET.indexOf(encoded.charAt(i));
            if (digit < 0) {
                throw new IllegalArgumentException("Invalid Base62 digit");
            }
            value = value.multiply(BASE62_RADIX).add(BigInteger.valueOf(digit));
        }

        byte[] bytes = value.toByteArray();
        byte[] normalized = new byte[16];
        int copyLength = Math.min(bytes.length, normalized.length);
        System.arraycopy(bytes, bytes.length - copyLength, normalized, normalized.length - copyLength, copyLength);

        ByteBuffer buffer = ByteBuffer.wrap(normalized);
        return new UUID(buffer.getLong(), buffer.getLong());
    }

    /// Converts a UUID to its unsigned 128-bit big-endian bytes.
    private static byte[] toBytes(UUID uuid) {
        byte[] bytes = new byte[16];
        ByteBuffer.wrap(bytes)
                .putLong(uuid.getMostSignificantBits())
                .putLong(uuid.getLeastSignificantBits());
        return bytes;
    }

    /// Creates a deterministic UUID from a random source.
    private static UUID nextUuid(SplittableRandom random) {
        return new UUID(random.nextLong(), random.nextLong());
    }

    /// A fixed Base62 test vector.
    ///
    /// @param uuid    the UUID value
    /// @param encoded the 22-character Base62 representation
    @NotNullByDefault
    private record Base62Fixture(UUID uuid, String encoded) {
    }
}
