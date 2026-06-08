// Copyright (c) 2026 Glavo
// Copyright (c) 2018-2023 Fabio Lima
// SPDX-License-Identifier: MPL-2.0 AND MIT

package org.glavo.uuid;

import com.github.f4b6a3.uuid.UuidCreator;
import com.github.f4b6a3.uuid.util.UuidTime;
import com.github.f4b6a3.uuid.util.UuidUtil;
import org.jetbrains.annotations.NotNullByDefault;
import org.jetbrains.annotations.Unmodifiable;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.SplittableRandom;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Broad UUID behavior tests adapted from uuid-creator's utility, comparator,
/// factory, and codec test coverage areas.
@NotNullByDefault
class UUIDsComprehensivePortedTest {
    /// Default loop count used for deterministic randomized checks.
    private static final int DEFAULT_LOOP_MAX = 512;

    /// A mask for the 60-bit Gregorian timestamp field.
    private static final long GREGORIAN_TIMESTAMP_MASK = 0x0FFF_FFFF_FFFF_FFFFL;

    /// A mask for the 48-bit node identifier field.
    private static final long NODE_MASK = 0x0000_FFFF_FFFF_FFFFL;

    /// A mask for the 14-bit clock sequence field.
    private static final int CLOCK_SEQUENCE_MASK = 0x3FFF;

    /// Fixed UUID values used by cross-library codec checks.
    private static final UUID @Unmodifiable [] FIXED_UUIDS = {
            UUIDs.NIL,
            new UUID(0L, 1L),
            UUIDs.NAMESPACE_DNS,
            UUIDs.NAMESPACE_URL,
            UUIDs.NAMESPACE_OID,
            UUIDs.NAMESPACE_X500,
            UUID.fromString("01234567-89ab-4def-a123-456789abcdef"),
            UUID.fromString("550e8400-e29b-41d4-a716-446655440000"),
            new UUID(Long.MIN_VALUE, 0L),
            new UUID(0L, Long.MIN_VALUE),
            UUIDs.MAX,
    };

    /// Valid UUID text forms accepted by `UUIDs.parse`.
    private static final String @Unmodifiable [] VALID_TEXT_FORMS = {
            "01234567-89ab-4def-a123-456789abcdef",
            "01234567-89AB-4DEF-A123-456789ABCDEF",
            "0123456789ab4defa123456789abcdef",
            "0123456789AB4DEFA123456789ABCDEF",
            "{01234567-89ab-4def-a123-456789abcdef}",
            "urn:uuid:01234567-89ab-4def-a123-456789abcdef",
            "URN:UUID:01234567-89AB-4DEF-A123-456789ABCDEF",
    };

    /// Invalid UUID text samples adapted from uuid-creator GUID validation
    /// coverage.
    private static final String @Unmodifiable [] INVALID_TEXT_FORMS = {
            "",
            "0-0-0-0-0",
            "this should be invalid",
            "01234567-89ab-4def-abcdef01-23456789",
            "01234567-89ab-4def-abcd-ef01-3456789",
            "01234567-89ab-4def-abcddef0123456789",
            "01234567-89ab-4def-abcd-SOPQRSTUVXYZ",
            "01234567-89ab-4def-!@#$-ef0123456789",
            "01234567-89ab-4def-a123-456789abcdeg",
            "0123456789ab4defa123456789abcdeg",
            "[01234567-89ab-4def-a123-456789abcdef]",
            "urn:uuid:0123456789ab4defa123456789abcdef",
            "uuid:01234567-89ab-4def-a123-456789abcdef",
    };

    /// Compares constants, standard text, and binary conversion with
    /// uuid-creator.
    @Test
    void constantsTextAndBytesMatchUuidCreator() {
        assertEquals(UuidCreator.getNil(), UUIDs.NIL);
        assertEquals(UuidCreator.getMax(), UUIDs.MAX);

        for (UUID uuid : FIXED_UUIDS) {
            assertEquals(UuidCreator.toString(uuid), uuid.toString());
            assertEquals(UuidCreator.fromString(uuid.toString()), UUIDs.parse(uuid.toString()));
            assertArrayEquals(UuidCreator.toBytes(uuid), UUIDs.toBytes(uuid));
            assertEquals(UuidCreator.fromBytes(UUIDs.toBytes(uuid)), UUIDs.fromBytes(UUIDs.toBytes(uuid)));
        }
    }

    /// Parses all supported explicit text forms and rejects malformed UUID text.
    @Test
    void parseAcceptsSupportedFormsAndRejectsMalformedSamples() {
        UUID expected = UUID.fromString("01234567-89ab-4def-a123-456789abcdef");
        for (String text : VALID_TEXT_FORMS) {
            assertEquals(expected, UUIDs.parse(text));
        }

        for (String text : INVALID_TEXT_FORMS) {
            assertThrows(IllegalArgumentException.class, () -> UUIDs.parse(text), text);
        }

        assertThrows(NullPointerException.class, () -> UUIDs.parse(null));
    }

    /// Constructs version-1 UUIDs with the same optional arguments as
    /// uuid-creator.
    @Test
    void version1ConstructorsMatchUuidCreator() {
        SplittableRandom random = new SplittableRandom(1L);
        for (int i = 0; i < DEFAULT_LOOP_MAX; i++) {
            Instant instant = nextInstantWithUuidTickPrecision(random);
            int clockSequence = random.nextInt() & CLOCK_SEQUENCE_MASK;
            long node = random.nextLong() & NODE_MASK;

            UUID expected = UuidCreator.getTimeBased(instant, clockSequence, node);
            UUID actual = UUIDs.v1(instant, clockSequence, node);

            assertEquals(expected, actual);
            assertEquals(UuidUtil.getTimestamp(expected), UUIDs.getGregorianTimestamp(actual));
            assertEquals(UuidUtil.getInstant(expected), UUIDs.getInstant(actual));
            assertEquals(UuidUtil.getClockSequence(expected), UUIDs.getClockSequence(actual));
            assertEquals(UuidUtil.getNodeIdentifier(expected), UUIDs.getNode(actual));
        }
    }

    /// Constructs version-6 UUIDs with the same optional arguments as
    /// uuid-creator.
    @Test
    void version6ConstructorsMatchUuidCreator() {
        SplittableRandom random = new SplittableRandom(6L);
        for (int i = 0; i < DEFAULT_LOOP_MAX; i++) {
            Instant instant = nextInstantWithUuidTickPrecision(random);
            int clockSequence = random.nextInt() & CLOCK_SEQUENCE_MASK;
            long node = random.nextLong() & NODE_MASK;

            UUID expected = UuidCreator.getTimeOrdered(instant, clockSequence, node);
            UUID actual = UUIDs.v6(instant, clockSequence, node);

            assertEquals(expected, actual);
            assertEquals(UuidUtil.getTimestamp(expected), UUIDs.getGregorianTimestamp(actual));
            assertEquals(UuidUtil.getInstant(expected), UUIDs.getInstant(actual));
            assertEquals(UuidUtil.getClockSequence(expected), UUIDs.getClockSequence(actual));
            assertEquals(UuidUtil.getNodeIdentifier(expected), UUIDs.getNode(actual));
        }
    }

    /// Constructs version-7 min and max UUIDs with the same timestamp boundary
    /// layout as uuid-creator.
    @Test
    void version7MinAndMaxConstructorsMatchUuidCreator() {
        SplittableRandom random = new SplittableRandom(7L);
        for (int i = 0; i < DEFAULT_LOOP_MAX; i++) {
            long epochMilli = random.nextLong(1L << 48);
            Instant instant = Instant.ofEpochMilli(epochMilli);

            UUID min = UUIDs.v7(instant, 0, 0L);
            UUID max = UUIDs.v7(instant, -1, -1L);

            assertEquals(UuidCreator.getTimeOrderedEpochMin(instant), min);
            assertEquals(UuidCreator.getTimeOrderedEpochMax(instant), max);
            assertEquals(epochMilli, UUIDs.getUnixTimestampMillis(min));
            assertEquals(epochMilli, UUIDs.getUnixTimestampMillis(max));
            assertEquals(0, UUIDs.getV7RandA(min));
            assertEquals(0L, UUIDs.getV7RandB(min));
            assertEquals(0xFFF, UUIDs.getV7RandA(max));
            assertEquals(-1L >>> 2, UUIDs.getV7RandB(max));
        }
    }

    /// Extracts DCE Security fields in the same way as uuid-creator.
    @Test
    void version2FieldsMatchUuidCreatorGeneratedValues() {
        SplittableRandom random = new SplittableRandom(2L);
        for (int i = 0; i < DEFAULT_LOOP_MAX; i++) {
            int localDomain = random.nextInt(3);
            int localIdentifier = random.nextInt();
            UUID creatorUuid = UuidCreator.getDceSecurity((byte) localDomain, localIdentifier);

            assertEquals(UuidUtil.getLocalDomain(creatorUuid) & 0xFF, UUIDs.getDceLocalDomain(creatorUuid));
            assertEquals(UuidUtil.getLocalIdentifier(creatorUuid) & 0xFFFF_FFFFL,
                    UUIDs.getDceLocalIdentifier(creatorUuid));

            long gregorianTimestamp = random.nextLong() & GREGORIAN_TIMESTAMP_MASK;
            int clockSequence = random.nextInt() & 0x3F;
            long node = random.nextLong() & NODE_MASK;
            UUID uuid = UUIDs.v2(gregorianTimestamp, localDomain, Integer.toUnsignedLong(localIdentifier),
                    clockSequence, node);

            assertEquals(gregorianTimestamp & 0xFFFF_FFFF_0000_0000L, UUIDs.getGregorianTimestamp(uuid));
            assertEquals(localDomain, UUIDs.getDceLocalDomain(uuid));
            assertEquals(Integer.toUnsignedLong(localIdentifier), UUIDs.getDceLocalIdentifier(uuid));
            assertEquals(clockSequence, UUIDs.getClockSequence(uuid));
            assertEquals(node, UUIDs.getNode(uuid));
        }
    }

    /// Matches uuid-creator's utility field extraction for supported UUID
    /// versions.
    @Test
    void fieldAccessorsMatchUuidCreatorUtilities() {
        SplittableRandom random = new SplittableRandom(0xF1E1D5L);
        for (int i = 0; i < DEFAULT_LOOP_MAX; i++) {
            long gregorianTimestamp = random.nextLong() & GREGORIAN_TIMESTAMP_MASK;
            int clockSequence = random.nextInt() & CLOCK_SEQUENCE_MASK;
            long node = random.nextLong() & NODE_MASK;

            assertCommonTimeFields(UUIDs.v1(gregorianTimestamp, clockSequence, node));
            assertCommonTimeFields(UUIDs.v6(gregorianTimestamp, clockSequence, node));
        }
    }

    /// Ensures constructors mask caller-supplied fields into their documented
    /// UUID bit ranges.
    @Test
    void constructorsMaskInputsIntoUuidFields() {
        UUID v1 = UUIDs.v1(-1L, -1, -1L);
        assertEquals(1, v1.version());
        assertEquals(2, v1.variant());
        assertEquals(GREGORIAN_TIMESTAMP_MASK, UUIDs.getGregorianTimestamp(v1));
        assertEquals(CLOCK_SEQUENCE_MASK, UUIDs.getClockSequence(v1));
        assertEquals(NODE_MASK, UUIDs.getNode(v1));

        UUID v2 = UUIDs.v2(-1L, -1, -1L, -1, -1L);
        assertEquals(2, v2.version());
        assertEquals(2, v2.variant());
        assertEquals(0xFF, UUIDs.getDceLocalDomain(v2));
        assertEquals(0xFFFF_FFFFL, UUIDs.getDceLocalIdentifier(v2));
        assertEquals(0x3F, UUIDs.getClockSequence(v2));
        assertEquals(NODE_MASK, UUIDs.getNode(v2));

        UUID v4 = UUIDs.v4(-1L, -1L);
        assertEquals(4, v4.version());
        assertEquals(2, v4.variant());

        UUID v6 = UUIDs.v6(-1L, -1, -1L);
        assertEquals(6, v6.version());
        assertEquals(2, v6.variant());
        assertEquals(GREGORIAN_TIMESTAMP_MASK, UUIDs.getGregorianTimestamp(v6));
        assertEquals(CLOCK_SEQUENCE_MASK, UUIDs.getClockSequence(v6));
        assertEquals(NODE_MASK, UUIDs.getNode(v6));

        UUID v7 = UUIDs.v7(-1L, -1, -1L);
        assertEquals(7, v7.version());
        assertEquals(2, v7.variant());
        assertEquals((1L << 48) - 1L, UUIDs.getUnixTimestampMillis(v7));
        assertEquals(0xFFF, UUIDs.getV7RandA(v7));
        assertEquals(-1L >>> 2, UUIDs.getV7RandB(v7));

        UUID v8 = UUIDs.v8(-1L, -1L);
        assertEquals(8, v8.version());
        assertEquals(2, v8.variant());
    }

    /// Checks exact UUID states at each constructor's all-zero and all-one
    /// boundaries.
    @Test
    void constructorsProduceExactBoundaryStates() {
        assertEquals(UUID.fromString("00000000-0000-1000-8000-000000000000"),
                UUIDs.v1(0L, 0, 0L));
        assertEquals(UUID.fromString("ffffffff-ffff-1fff-bfff-ffffffffffff"),
                UUIDs.v1(-1L, -1, -1L));

        assertEquals(UUID.fromString("00000000-0000-2000-8000-000000000000"),
                UUIDs.v2(0L, 0, 0L, 0, 0L));
        assertEquals(UUID.fromString("ffffffff-ffff-2fff-bfff-ffffffffffff"),
                UUIDs.v2(-1L, -1, -1L, -1, -1L));

        assertEquals(UUID.fromString("00000000-0000-6000-8000-000000000000"),
                UUIDs.v6(0L, 0, 0L));
        assertEquals(UUID.fromString("ffffffff-ffff-6fff-bfff-ffffffffffff"),
                UUIDs.v6(-1L, -1, -1L));

        assertEquals(UUID.fromString("00000000-0000-7000-8000-000000000000"),
                UUIDs.v7(0L, 0, 0L));
        assertEquals(UUID.fromString("ffffffff-ffff-7fff-bfff-ffffffffffff"),
                UUIDs.v7(-1L, -1, -1L));

        assertEquals(UUID.fromString("00000000-0000-8000-8000-000000000000"),
                UUIDs.v8(0L, 0L));
        assertEquals(UUID.fromString("ffffffff-ffff-8fff-bfff-ffffffffffff"),
                UUIDs.v8(-1L, -1L));

        assertEquals(UUID.fromString("ffffffff-ffff-0fff-bfff-ffffffffffff"),
                UUIDs.newWithVersion(-1L, -1L, 0));
        assertEquals(UUID.fromString("ffffffff-ffff-ffff-bfff-ffffffffffff"),
                UUIDs.newWithVersion(-1L, -1L, -1));
    }

    /// Checks timestamp extraction at the Gregorian and Unix epoch boundaries,
    /// and at the largest encodable timestamp for version-1 and version-6.
    @Test
    void timestampAccessorsHandleBoundaryStates() {
        Instant gregorianEpoch = Instant.parse("1582-10-15T00:00:00Z");
        Instant maximumGregorianInstant = Instant.parse("5236-03-31T21:21:00.684697500Z");
        long maximumV7Millis = (1L << 48) - 1L;

        for (UUID uuid : new UUID[]{UUIDs.v1(0L, 0, 0L), UUIDs.v6(0L, 0, 0L)}) {
            assertEquals(0L, UUIDs.getGregorianTimestamp(uuid));
            assertEquals(gregorianEpoch, UUIDs.getInstant(uuid));
            assertEquals(gregorianEpoch.toEpochMilli(), UUIDs.getUnixTimestampMillis(uuid));
        }

        for (UUID uuid : new UUID[]{
                UUIDs.v1(GREGORIAN_TIMESTAMP_MASK, 0, 0L),
                UUIDs.v6(GREGORIAN_TIMESTAMP_MASK, 0, 0L),
        }) {
            assertEquals(GREGORIAN_TIMESTAMP_MASK, UUIDs.getGregorianTimestamp(uuid));
            assertEquals(maximumGregorianInstant, UUIDs.getInstant(uuid));
            assertEquals(maximumGregorianInstant.toEpochMilli(), UUIDs.getUnixTimestampMillis(uuid));
        }

        assertEquals(Instant.EPOCH, UUIDs.getInstant(UUIDs.v7(0L, 0, 0L)));
        assertEquals(0L, UUIDs.getUnixTimestampMillis(UUIDs.v7(0L, 0, 0L)));
        assertEquals(Instant.ofEpochMilli(maximumV7Millis), UUIDs.getInstant(UUIDs.v7(-1L, 0, 0L)));
        assertEquals(maximumV7Millis, UUIDs.getUnixTimestampMillis(UUIDs.v7(-1L, 0, 0L)));
    }

    /// Checks field states immediately around version-7 payload boundaries.
    @Test
    void version7PayloadAccessorsHandleBoundaryStates() {
        UUID minimum = UUIDs.v7(0L, 0, 0L);
        UUID maximum = UUIDs.v7(-1L, -1, -1L);

        assertEquals(0L, UUIDs.getUnixTimestampMillis(minimum));
        assertEquals(0, UUIDs.getV7RandA(minimum));
        assertEquals(0L, UUIDs.getV7RandB(minimum));

        assertEquals((1L << 48) - 1L, UUIDs.getUnixTimestampMillis(maximum));
        assertEquals(0xFFF, UUIDs.getV7RandA(maximum));
        assertEquals(-1L >>> 2, UUIDs.getV7RandB(maximum));

        assertEquals(0, UUIDs.getV7RandA(UUIDs.v7(0L, 0x1000, 0L)));
        assertEquals(1, UUIDs.getV7RandA(UUIDs.v7(0L, 0x1001, 0L)));
        assertEquals(0L, UUIDs.getV7RandB(UUIDs.v7(0L, 0, 1L << 62)));
        assertEquals(1L, UUIDs.getV7RandB(UUIDs.v7(0L, 0, (1L << 62) + 1L)));
    }

    /// Accepts byte-array windows at the first and last possible offsets while
    /// preserving bytes outside the UUID window.
    @Test
    void byteConversionAcceptsBoundaryOffsets() {
        UUID uuid = UUID.fromString("01234567-89ab-4def-a123-456789abcdef");
        byte[] expected = UUIDs.toBytes(uuid);
        byte[] leadingWindow = new byte[20];
        byte[] trailingWindow = new byte[20];

        leadingWindow[16] = 0x55;
        leadingWindow[17] = 0x66;
        leadingWindow[18] = 0x77;
        leadingWindow[19] = 0x11;
        UUIDs.toBytes(uuid, leadingWindow, 0);
        assertEquals(0x55, leadingWindow[16]);
        assertEquals(0x66, leadingWindow[17]);
        assertEquals(0x77, leadingWindow[18]);
        assertEquals(0x11, leadingWindow[19]);
        assertEquals(uuid, UUIDs.fromBytes(leadingWindow, 0));

        trailingWindow[0] = 0x55;
        trailingWindow[1] = 0x66;
        trailingWindow[2] = 0x77;
        trailingWindow[3] = 0x11;
        UUIDs.toBytes(uuid, trailingWindow, 4);
        assertEquals(0x55, trailingWindow[0]);
        assertEquals(0x66, trailingWindow[1]);
        assertEquals(0x77, trailingWindow[2]);
        assertEquals(0x11, trailingWindow[3]);
        assertEquals(uuid, UUIDs.fromBytes(trailingWindow, 4));

        byte[] actual = new byte[16];
        System.arraycopy(trailingWindow, 4, actual, 0, actual.length);
        assertArrayEquals(expected, actual);
    }

    /// Consumes byte buffers correctly when their remaining window is empty or
    /// positioned at the end of a larger backing array.
    @Test
    void nameBasedByteBuffersHandleBoundaryWindows() {
        ByteBuffer empty = ByteBuffer.allocate(8);
        empty.position(8);
        assertEquals(UUIDs.generateV3(UUIDs.NAMESPACE_DNS, new byte[0]),
                UUIDs.generateV3(UUIDs.NAMESPACE_DNS, empty));
        assertEquals(8, empty.position());

        byte[] bytes = {0x55, 0x66, 0x77, 'n', 'a', 'm', 'e'};
        ByteBuffer tail = ByteBuffer.wrap(bytes);
        tail.position(3);
        assertEquals(UUIDs.generateV5(UUIDs.NAMESPACE_DNS, new byte[]{'n', 'a', 'm', 'e'}),
                UUIDs.generateV5(UUIDs.NAMESPACE_DNS, tail));
        assertEquals(tail.limit(), tail.position());
    }

    /// Checks the unsigned comparison contract against `BigInteger`,
    /// canonical text order, and comparator ordering.
    @Test
    void comparatorMatchesUnsignedNumericAndTextOrder() {
        SplittableRandom random = new SplittableRandom(0xC0A4A4E);
        for (int i = 0; i < DEFAULT_LOOP_MAX; i++) {
            UUID left = nextUuid(random);
            UUID right = nextUuid(random);

            int expected = unsignedValue(left).compareTo(unsignedValue(right));
            assertEquals(Integer.signum(expected), Integer.signum(UUIDs.compare(left, right)));
            assertEquals(Integer.signum(expected), Integer.signum(UUIDs.comparator().compare(left, right)));
            assertEquals(Integer.signum(expected), Integer.signum(left.toString().compareTo(right.toString())));
            assertEquals(0, UUIDs.compare(left, new UUID(left.getMostSignificantBits(), left.getLeastSignificantBits())));
            assertEquals(0, UUIDs.comparator().compare(right,
                    new UUID(right.getMostSignificantBits(), right.getLeastSignificantBits())));
        }
    }

    /// Verifies name-based generation for byte-buffer windows, including
    /// read-only buffers, against uuid-creator.
    @Test
    void nameBasedByteBufferWindowsMatchUuidCreator() {
        byte[] names = {
                0x55, 0x66,
                'e', 'x', 'a', 'm', 'p', 'l', 'e',
                0x77, 0x11,
        };
        ByteBuffer window = ByteBuffer.wrap(names);
        window.position(2);
        window.limit(9);
        ByteBuffer readOnlyWindow = window.asReadOnlyBuffer();

        byte[] expectedName = new byte[7];
        ByteBuffer.wrap(names, 2, 7).get(expectedName);

        assertEquals(UuidCreator.getNameBasedMd5(UUIDs.NAMESPACE_DNS, expectedName),
                UUIDs.generateV3(UUIDs.NAMESPACE_DNS, window.slice()));
        assertEquals(UuidCreator.getNameBasedSha1(UUIDs.NAMESPACE_DNS, expectedName),
                UUIDs.generateV5(UUIDs.NAMESPACE_DNS, readOnlyWindow.slice()));
    }

    /// Rejects unsupported field access on UUID versions that do not carry the
    /// requested field groups.
    @Test
    void unsupportedFieldAccessorsThrow() {
        UUID v3 = UUIDs.generateV3(UUIDs.NAMESPACE_DNS, "example.com");
        UUID v4 = UUIDs.v4(0L, 0L);
        UUID v5 = UUIDs.generateV5(UUIDs.NAMESPACE_DNS, "example.com");
        UUID v8 = UUIDs.v8(0L, 0L);

        for (UUID uuid : new UUID[]{UUIDs.NIL, v3, v4, v5, v8, UUIDs.MAX}) {
            assertFalse(UUIDs.isTimeBased(uuid));
            assertThrows(IllegalArgumentException.class, () -> UUIDs.getInstant(uuid));
            assertThrows(IllegalArgumentException.class, () -> UUIDs.getGregorianTimestamp(uuid));
            assertThrows(IllegalArgumentException.class, () -> UUIDs.getUnixTimestampMillis(uuid));
            assertThrows(IllegalArgumentException.class, () -> UUIDs.getClockSequence(uuid));
            assertThrows(IllegalArgumentException.class, () -> UUIDs.getNode(uuid));
            assertThrows(IllegalArgumentException.class, () -> UUIDs.getDceLocalDomain(uuid));
            assertThrows(IllegalArgumentException.class, () -> UUIDs.getDceLocalIdentifier(uuid));
            assertThrows(IllegalArgumentException.class, () -> UUIDs.getV7RandA(uuid));
            assertThrows(IllegalArgumentException.class, () -> UUIDs.getV7RandB(uuid));
        }
    }

    /// Asserts common uuid-creator timestamp, clock-sequence, and node
    /// extraction for version-1 and version-6 UUIDs.
    private static void assertCommonTimeFields(UUID uuid) {
        assertTrue(UUIDs.isTimeBased(uuid));
        assertEquals(UuidUtil.getTimestamp(uuid), UUIDs.getGregorianTimestamp(uuid));
        assertEquals(UuidUtil.getInstant(uuid), UUIDs.getInstant(uuid));
        assertEquals(UuidUtil.getClockSequence(uuid), UUIDs.getClockSequence(uuid));
        assertEquals(UuidUtil.getNodeIdentifier(uuid), UUIDs.getNode(uuid));
    }

    /// Creates a deterministic UUID from a random source.
    private static UUID nextUuid(SplittableRandom random) {
        return new UUID(random.nextLong(), random.nextLong());
    }

    /// Creates an instant whose nanosecond value is exactly representable in
    /// UUID 100 ns ticks.
    private static Instant nextInstantWithUuidTickPrecision(SplittableRandom random) {
        long gregorianTimestamp = random.nextLong() & GREGORIAN_TIMESTAMP_MASK;
        return UuidTime.fromGregTimestamp(gregorianTimestamp);
    }

    /// Converts a UUID to an unsigned 128-bit integer.
    private static BigInteger unsignedValue(UUID uuid) {
        return new BigInteger(1, UUIDs.toBytes(uuid));
    }
}
