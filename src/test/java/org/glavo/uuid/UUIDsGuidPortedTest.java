// Copyright (c) 2026 Glavo
// Copyright (c) 2018-2023 Fabio Lima
// SPDX-License-Identifier: MPL-2.0 AND MIT

package org.glavo.uuid;

import org.jetbrains.annotations.NotNullByDefault;
import org.jetbrains.annotations.Nullable;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.InstantSource;
import java.util.Arrays;
import java.util.Random;
import java.util.SplittableRandom;
import java.util.UUID;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Behavior tests ported from uuid-creator's `GUIDTest` and adapted to the
/// `UUIDs` static API.
@NotNullByDefault
class UUIDsGuidPortedTest {

    /// Default loop count used by the ported randomized checks.
    private static final int DEFAULT_LOOP_MAX = 100;

    /// Number of bytes in the binary UUID representation.
    private static final int UUID_BYTES = 16;

    /// Secure random source used by explicit-random generation checks.
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /// Offset between the Gregorian and Unix epochs in seconds.
    private static final long GREGORIAN_EPOCH_OFFSET_SECONDS = 12_219_292_800L;

    /// Standard hyphenated UUID text pattern used by the GUID parser tests.
    private static final Pattern STANDARD_PATTERN = Pattern.compile(
            "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
            Pattern.CASE_INSENSITIVE);

    /// Creates UUIDs from raw halves in the same way as the GUID long
    /// constructor.
    @Test
    void constructorFromLongs() {
        SplittableRandom random = new SplittableRandom(1);
        for (int i = 0; i < DEFAULT_LOOP_MAX; i++) {
            long msb = random.nextLong();
            long lsb = random.nextLong();
            UUID uuid = new UUID(msb, lsb);
            assertEquals(msb, uuid.getMostSignificantBits());
            assertEquals(lsb, uuid.getLeastSignificantBits());
        }
    }

    /// Creates UUIDs from another JDK UUID in the same way as the GUID UUID
    /// constructor.
    @Test
    void constructorFromJdkUuid() {
        SplittableRandom random = new SplittableRandom(1);
        for (int i = 0; i < DEFAULT_LOOP_MAX; i++) {
            long msb = random.nextLong();
            long lsb = random.nextLong();
            UUID source = new UUID(msb, lsb);
            UUID uuid = new UUID(source.getMostSignificantBits(), source.getLeastSignificantBits());
            assertEquals(msb, uuid.getMostSignificantBits());
            assertEquals(lsb, uuid.getLeastSignificantBits());
        }
    }

    /// Parses standard UUID text in the same way as the GUID string
    /// constructor.
    @Test
    void constructorFromString() {
        SplittableRandom random = new SplittableRandom(1);
        for (int i = 0; i < DEFAULT_LOOP_MAX; i++) {
            long msb = random.nextLong();
            long lsb = random.nextLong();
            UUID expected = new UUID(msb, lsb);
            UUID uuid = UUIDs.parse(expected.toString());
            assertEquals(msb, uuid.getMostSignificantBits());
            assertEquals(lsb, uuid.getLeastSignificantBits());
        }
    }

    /// Creates UUIDs from 16-byte arrays in the same way as the GUID byte
    /// constructor.
    @Test
    void constructorFromBytes() {
        SplittableRandom seeder = new SplittableRandom(1);
        for (int i = 0; i < DEFAULT_LOOP_MAX; i++) {
            byte[] bytes = new byte[UUID_BYTES];
            new Random(seeder.nextLong()).nextBytes(bytes);
            UUID uuid = UUIDs.fromBytes(bytes);
            assertArrayEquals(bytes, UUIDs.toBytes(uuid));
        }

        assertThrows(NullPointerException.class, () -> UUIDs.fromBytes(null));
        assertThrows(IllegalArgumentException.class, () -> UUIDs.fromBytes(new byte[UUID_BYTES + 1]));
    }

    /// Generates valid version-1 UUIDs with default and explicit sources.
    @Test
    void generateV1() {
        testV1(UUIDs::generateV1);
        Random random = new Random(1);
        testV1(() -> UUIDs.generateV1(InstantSource.fixed(Instant.now()), random));
        testV1(() -> UUIDs.generateV1(InstantSource.fixed(Instant.now()), SECURE_RANDOM));
    }

    /// Applies the common version-1 generation assertions.
    private static void testV1(Supplier<UUID> supplier) {
        UUID previous = supplier.get();
        for (int i = 0; i < DEFAULT_LOOP_MAX; i++) {
            long before = System.currentTimeMillis();
            UUID uuid = supplier.get();
            long timestamp = UUIDs.getUnixTimestampMillis(uuid);
            long after = System.currentTimeMillis();
            assertGeneratedUuid(uuid, previous, 1);
            assertTrue(before <= timestamp && timestamp <= after);
            previous = uuid;
        }
    }

    /// Generates valid version-2 UUIDs and exposes DCE local fields.
    @Test
    void generateV2() {
        UUID previous = UUIDs.generateV2(0, 0);
        for (int i = 0; i < DEFAULT_LOOP_MAX; i++) {
            int localDomain = i;
            int localIdentifier = i * 31;
            UUID uuid = UUIDs.generateV2(localDomain, localIdentifier);
            assertGeneratedUuid(uuid, previous, 2);
            assertEquals(localDomain, UUIDs.getDceLocalDomain(uuid));
            assertEquals(localIdentifier, UUIDs.getDceLocalIdentifier(uuid));
            previous = uuid;
        }
    }

    /// Generates deterministic version-3 UUIDs from strings and byte arrays.
    @Test
    void generateV3() {
        UUID previous = UUIDs.generateV3(UUIDs.NIL, "");
        SplittableRandom random = new SplittableRandom(1);
        for (int i = 0; i < DEFAULT_LOOP_MAX; i++) {
            UUID namespace = nextUuid(random);
            String name = nextUuid(random).toString();
            UUID uuid = UUIDs.generateV3(namespace, name);
            assertNotNull(uuid);
            assertNotEquals(previous, uuid);
            assertEquals(3, uuid.version());
            assertNotEquals(UUIDs.NIL, uuid);
            assertNotEquals(UUIDs.MAX, uuid);
            assertNotEquals(UUIDs.generateV3(null, name), UUIDs.generateV3(namespace, name));
            assertNotEquals(UUIDs.generateV3(UUIDs.NIL, name), UUIDs.generateV3(namespace, name));
            assertNotEquals(UUIDs.generateV3(namespace, name), UUIDs.generateV5(namespace, name));
            assertEquals(UUIDs.generateV3(null, name), UUIDs.generateV3(null, name));
            assertEquals(UUIDs.generateV3(UUIDs.NIL, name), UUIDs.generateV3(UUIDs.NIL, name));
            assertEquals(UUIDs.generateV3(namespace, name), UUIDs.generateV3(namespace, name));
            assertEquals(UUIDs.generateV3(namespace, name),
                    UUIDs.generateV3(namespace, name.getBytes(StandardCharsets.UTF_8)));
            assertEquals(UUID.nameUUIDFromBytes(name.getBytes(StandardCharsets.UTF_8)),
                    UUIDs.generateV3(null, name));
            previous = uuid;
        }

        UUID uuid = UUIDs.generateV3(UUIDs.NAMESPACE_DNS, "www.example.com");
        assertEquals("5df41881-3aed-3515-88a7-2f4a814cf09e", uuid.toString());
    }

    /// Generates valid version-4 UUIDs with default and explicit sources.
    @Test
    void generateV4() {
        testV4(UUIDs::generateV4);
        Random random = new Random(1);
        testV4(() -> UUIDs.generateV4(random));
        testV4(() -> UUIDs.generateV4(SECURE_RANDOM));
    }

    /// Applies the common version-4 generation assertions.
    private static void testV4(Supplier<UUID> supplier) {
        UUID previous = supplier.get();
        for (int i = 0; i < DEFAULT_LOOP_MAX; i++) {
            UUID uuid = supplier.get();
            assertGeneratedUuid(uuid, previous, 4);
            previous = uuid;
        }
    }

    /// Generates deterministic version-5 UUIDs from strings and byte arrays.
    @Test
    void generateV5() {
        UUID previous = UUIDs.generateV5(UUIDs.NIL, "");
        SplittableRandom random = new SplittableRandom(1);
        for (int i = 0; i < DEFAULT_LOOP_MAX; i++) {
            UUID namespace = nextUuid(random);
            String name = nextUuid(random).toString();
            UUID uuid = UUIDs.generateV5(namespace, name);
            assertNotNull(uuid);
            assertNotEquals(previous, uuid);
            assertEquals(5, uuid.version());
            assertNotEquals(UUIDs.NIL, uuid);
            assertNotEquals(UUIDs.MAX, uuid);
            assertNotEquals(UUIDs.generateV5(null, name), UUIDs.generateV5(namespace, name));
            assertNotEquals(UUIDs.generateV5(UUIDs.NIL, name), UUIDs.generateV5(namespace, name));
            assertNotEquals(UUIDs.generateV5(namespace, name), UUIDs.generateV3(namespace, name));
            assertEquals(UUIDs.generateV5(null, name), UUIDs.generateV5(null, name));
            assertEquals(UUIDs.generateV5(UUIDs.NIL, name), UUIDs.generateV5(UUIDs.NIL, name));
            assertEquals(UUIDs.generateV5(namespace, name), UUIDs.generateV5(namespace, name));
            assertEquals(UUIDs.generateV5(namespace, name),
                    UUIDs.generateV5(namespace, name.getBytes(StandardCharsets.UTF_8)));
            previous = uuid;
        }

        UUID uuid = UUIDs.generateV5(UUIDs.NAMESPACE_DNS, "www.example.com");
        assertEquals("2ed6657d-e927-568b-95e1-2665a8aea6a2", uuid.toString());
    }

    /// Generates valid version-6 UUIDs with default and explicit sources.
    @Test
    void generateV6() {
        testV6(UUIDs::generateV6);
        Random random = new Random(1);
        testV6(() -> UUIDs.generateV6(InstantSource.fixed(Instant.now()), random));
        testV6(() -> UUIDs.generateV6(InstantSource.fixed(Instant.now()), SECURE_RANDOM));
    }

    /// Applies the common version-6 generation assertions.
    private static void testV6(Supplier<UUID> supplier) {
        UUID previous = supplier.get();
        for (int i = 0; i < DEFAULT_LOOP_MAX; i++) {
            long before = System.currentTimeMillis();
            UUID uuid = supplier.get();
            long timestamp = UUIDs.getUnixTimestampMillis(uuid);
            long after = System.currentTimeMillis();
            assertGeneratedUuid(uuid, previous, 6);
            assertTrue(before <= timestamp && timestamp <= after);
            previous = uuid;
        }
    }

    /// Generates valid version-7 UUIDs with default and explicit sources.
    @Test
    void generateV7() {
        testV7(UUIDs::generateV7);
        Random random = new Random(1);
        testV7(() -> UUIDs.generateV7(InstantSource.fixed(Instant.now()), random));
        testV7(() -> UUIDs.generateV7(InstantSource.fixed(Instant.now()), SECURE_RANDOM));
    }

    /// Applies the common version-7 generation assertions.
    private static void testV7(Supplier<UUID> supplier) {
        UUID previous = supplier.get();
        for (int i = 0; i < DEFAULT_LOOP_MAX; i++) {
            long before = System.currentTimeMillis();
            UUID uuid = supplier.get();
            long timestamp = UUIDs.getUnixTimestampMillis(uuid);
            long after = System.currentTimeMillis();
            assertGeneratedUuid(uuid, previous, 7);
            assertTrue(before <= timestamp && timestamp <= after);
            previous = uuid;
        }
    }

    /// Preserves UUID halves when converting to JDK UUID objects.
    @Test
    void toJdkUuid() {
        SplittableRandom random = new SplittableRandom(1);
        for (int i = 0; i < DEFAULT_LOOP_MAX; i++) {
            long msb = random.nextLong();
            long lsb = random.nextLong();
            UUID uuid = new UUID(msb, lsb);
            assertEquals(msb, uuid.getMostSignificantBits());
            assertEquals(lsb, uuid.getLeastSignificantBits());
        }
    }

    /// Formats UUIDs with the same standard text as JDK UUID.
    @Test
    void toStringMatchesJdkUuid() {
        SplittableRandom random = new SplittableRandom(1);
        for (int i = 0; i < DEFAULT_LOOP_MAX; i++) {
            UUID uuid = nextUuid(random);
            assertEquals(UUID.fromString(uuid.toString()).toString(), uuid.toString());
        }
    }

    /// Converts UUIDs to bytes without changing byte order.
    @Test
    void toBytes() {
        SplittableRandom seeder = new SplittableRandom(1);
        for (int i = 0; i < DEFAULT_LOOP_MAX; i++) {
            byte[] expected = new byte[UUID_BYTES];
            new Random(seeder.nextLong()).nextBytes(expected);
            UUID uuid = UUIDs.fromBytes(expected);
            assertArrayEquals(expected, UUIDs.toBytes(uuid));
        }
    }

    /// Keeps hash codes stable for the same UUID value.
    @Test
    void hashCodeMatchesUuidValue() {
        SplittableRandom seeder = new SplittableRandom(1);
        for (int i = 0; i < DEFAULT_LOOP_MAX; i++) {
            byte[] bytes = new byte[UUID_BYTES];
            new Random(seeder.nextLong()).nextBytes(bytes);
            UUID uuid = UUIDs.fromBytes(bytes);
            assertEquals(uuid.hashCode(), uuid.hashCode());
            assertEquals(uuid.hashCode(), UUIDs.fromBytes(bytes.clone()).hashCode());
        }
    }

    /// Keeps equality, string, and byte representations aligned.
    @Test
    void equalsMatchesUuidValue() {
        SplittableRandom seeder = new SplittableRandom(1);
        for (int i = 0; i < DEFAULT_LOOP_MAX; i++) {
            byte[] bytes = new byte[UUID_BYTES];
            new Random(seeder.nextLong()).nextBytes(bytes);
            UUID uuid1 = UUIDs.fromBytes(bytes);
            UUID uuid2 = UUIDs.fromBytes(bytes.clone());
            assertEquals(uuid1, uuid2);
            assertEquals(uuid1.toString(), uuid2.toString());
            assertArrayEquals(UUIDs.toBytes(uuid1), UUIDs.toBytes(uuid2));

            byte[] changed = bytes.clone();
            for (int j = 0; j < changed.length; j++) {
                changed[j]++;
            }
            UUID uuid3 = UUIDs.fromBytes(changed);
            assertNotEquals(uuid1, uuid3);
            assertNotEquals(uuid1.toString(), uuid3.toString());
            assertFalse(Arrays.equals(UUIDs.toBytes(uuid1), UUIDs.toBytes(uuid3)));
        }
    }

    /// Compares UUIDs as unsigned 128-bit integers and matches canonical text
    /// ordering.
    @Test
    void compareToUsesUnsignedNumericOrder() {
        SplittableRandom random = new SplittableRandom(1);
        for (int i = 0; i < DEFAULT_LOOP_MAX; i++) {
            assertUnsignedComparison(random.nextLong(), random.nextLong(), random.nextLong(), random.nextLong());
        }

        for (int i = 0; i < DEFAULT_LOOP_MAX; i++) {
            assertUnsignedComparison(0L, random.nextLong(), 0L, random.nextLong());
        }

        for (int i = 0; i < DEFAULT_LOOP_MAX; i++) {
            assertUnsignedComparison(random.nextLong(), 0L, random.nextLong(), 0L);
        }
    }

    /// Converts Unix instants to Gregorian UUID timestamps.
    @Test
    void gregorianTimestampConversion() {
        assertGregorianInstant(Instant.parse("1582-10-15T00:00:00.000Z").toEpochMilli());
        assertGregorianInstant(Instant.parse("1970-01-01T00:00:00.000Z").toEpochMilli());
        assertGregorianInstant(Instant.parse("1955-11-12T06:38:00.000Z").toEpochMilli());
        assertGregorianInstant(Instant.parse("1985-10-26T09:00:00.000Z").toEpochMilli());
        assertGregorianInstant(Instant.parse("2015-10-21T07:28:00.000Z").toEpochMilli());
    }

    /// Generates MD5 name-based UUIDs without a namespace like the JDK helper.
    @Test
    void md5NameHashWithoutNamespaceMatchesJdk() {
        String name = "THIS IS A TEST";
        UUID uuid = UUIDs.generateV3(null, name);
        UUID jdkUuid = UUID.nameUUIDFromBytes(name.getBytes(StandardCharsets.UTF_8));
        assertEquals(jdkUuid, uuid);
    }

    /// Creates name-based UUIDs from digest bytes and rejects invalid digest
    /// sizes.
    @Test
    void nameBasedDigestConstructorsValidateInput() {
        byte[] md5Digest = {
                0x00, 0x01, 0x02, 0x03,
                0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0A, 0x0B,
                0x0C, 0x0D, 0x0E, 0x0F
        };
        byte[] sha1Digest = {
                0x00, 0x01, 0x02, 0x03,
                0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0A, 0x0B,
                0x0C, 0x0D, 0x0E, 0x0F,
                0x10, 0x11, 0x12, 0x13
        };

        assertEquals(UUID.fromString("00010203-0405-3607-8809-0a0b0c0d0e0f"), UUIDs.v3(md5Digest));
        assertEquals(UUID.fromString("00010203-0405-5607-8809-0a0b0c0d0e0f"), UUIDs.v5(sha1Digest));
        assertThrows(IllegalArgumentException.class, () -> UUIDs.v3(new byte[UUID_BYTES - 1]));
        assertThrows(IllegalArgumentException.class, () -> UUIDs.v5(new byte[UUID_BYTES]));
    }

    /// Sets version and RFC 9562 variant bits while preserving payload bits.
    @Test
    void newWithVersionMasksVersionArgument() {
        for (int i = 0; i < 32; i++) {
            UUID uuid = UUIDs.newWithVersion(
                    UUIDs.NIL.getMostSignificantBits(), UUIDs.NIL.getLeastSignificantBits(), i);
            assertEquals(0L, uuid.getMostSignificantBits() & 0xFFFF_FFFF_FFFF_0FFFL);
            assertEquals(0L, uuid.getLeastSignificantBits() & 0x3FFF_FFFF_FFFF_FFFFL);
            assertEquals(i % 16, uuid.version());
            assertEquals(2, uuid.variant());
        }
    }

    /// Checks GUID-style standard text validity.
    @Test
    void standardTextValidator() {
        testGuidValidator(UUIDsGuidPortedTest::isStandardUuidText);
    }

    /// Parses canonical UUID text and rejects GUID-style invalid inputs.
    @Test
    void parser() {
        SplittableRandom random = new SplittableRandom(1);
        for (int i = 0; i < DEFAULT_LOOP_MAX; i++) {
            String string = nextUuid(random).toString();
            UUID uuid = UUIDs.parse(string);
            assertEquals(string, uuid.toString());
        }

        testGuidValidator(UUIDsGuidPortedTest::isParseableStandardUuidText);

        testGuidValidator(string -> {
            boolean expected = string != null && STANDARD_PATTERN.matcher(string).matches();
            boolean result = isStandardUuidText(string);
            assertEquals(expected, result);
            return expected && result;
        });
    }

    /// Applies GUID's standard UUID text validation examples.
    private static void testGuidValidator(Function<@Nullable String, Boolean> validator) {
        assertFalse(validator.apply(null), "Null UUID string should be invalid.");
        assertFalse(validator.apply(""), "UUID with empty string should be invalid.");
        assertFalse(validator.apply("0-0-0-0-0"), "UUID 0-0-0-0-0 should be invalid.");
        assertFalse(validator.apply("this should be invalid"), "UUID text should be invalid.");
        assertTrue(validator.apply("01234567-89ab-4def-abcd-ef0123456789"),
                "UUID with length equal to 36 should be valid.");
        assertFalse(validator.apply("01234567-89ab-4def-abcdef01-23456789"),
                "UUID with length 36 and hyphen in wrong position should be invalid.");
        assertFalse(validator.apply("01234567-89ab-4def-abcd-ef01-3456789"),
                "UUID with length equal to 36 with an extra hyphen should be invalid.");
        assertFalse(validator.apply("01234567-89ab-4def-abcddef0123456789"),
                "UUID with length equal to 36 with a missing hyphen should be invalid.");
        assertFalse(validator.apply("0123456789ab4defabcdef0123456789"),
                "UUID without hyphens should be invalid for GUID-style validation.");
        assertTrue(validator.apply(UUIDs.generateV4(new Random(1)).toString()),
                "UUID generated by random generation should be valid.");
        assertTrue(validator.apply("01234567-89ab-4def-abcd-ef0123456789"),
                "UUID in lower case should be valid.");
        assertTrue(validator.apply("01234567-89AB-4DEF-ABCD-EF0123456789"),
                "UUID in upper case should be valid.");
        assertTrue(validator.apply("01234567-89ab-4DEF-abcd-EF0123456789"),
                "UUID in upper and lower case should be valid.");
        assertFalse(validator.apply("01234567-89ab-4def-abcd-SOPQRSTUVXYZ"),
                "UUID string with non-hexadecimal chars should be invalid.");
        assertFalse(validator.apply("01234567-89ab-4def-!@#$-ef0123456789"),
                "UUID string with non-alphanumeric chars should be invalid.");
    }

    /// Applies common validity checks for generated UUIDs.
    private static void assertGeneratedUuid(UUID uuid, UUID previous, int version) {
        assertNotNull(uuid);
        assertNotEquals(previous, uuid);
        assertNotEquals(UUIDs.NIL, uuid);
        assertNotEquals(UUIDs.MAX, uuid);
        assertEquals(version, uuid.version());
        assertEquals(2, uuid.variant());
    }

    /// Creates a UUID from deterministic random halves.
    private static UUID nextUuid(SplittableRandom random) {
        return new UUID(random.nextLong(), random.nextLong());
    }

    /// Asserts unsigned numeric comparison against BigInteger and canonical
    /// string order.
    private static void assertUnsignedComparison(long msb1, long lsb1, long msb2, long lsb2) {
        UUID uuid1 = new UUID(msb1, lsb1);
        UUID uuid2 = new UUID(msb2, lsb2);
        UUID uuid3 = new UUID(msb2, lsb2);
        BigInteger number1 = new BigInteger(1, UUIDs.toBytes(uuid1));
        BigInteger number2 = new BigInteger(1, UUIDs.toBytes(uuid2));
        BigInteger number3 = new BigInteger(1, UUIDs.toBytes(uuid3));

        assertEquals(number1.compareTo(number2) > 0, UUIDs.compare(uuid1, uuid2) > 0);
        assertEquals(number1.compareTo(number2) < 0, UUIDs.compare(uuid1, uuid2) < 0);
        assertEquals(number2.compareTo(number3) == 0, UUIDs.comparator().compare(uuid2, uuid3) == 0);
        assertEquals(number1.compareTo(number2) > 0, uuid1.toString().compareTo(uuid2.toString()) > 0);
        assertEquals(number1.compareTo(number2) < 0, uuid1.toString().compareTo(uuid2.toString()) < 0);
        assertEquals(number2.compareTo(number3) == 0, uuid2.toString().compareTo(uuid3.toString()) == 0);
    }

    /// Asserts Gregorian timestamp conversion for a Unix millisecond instant.
    private static void assertGregorianInstant(long time) {
        Instant instant = Instant.ofEpochMilli(time);
        UUID uuid = UUIDs.v1(instant, 0, 0);
        assertEquals(GREGORIAN_EPOCH_OFFSET_SECONDS + instant.getEpochSecond(),
                UUIDs.getGregorianTimestamp(uuid) / 10_000_000L);
    }

    /// Returns whether text is valid canonical UUID text under GUID rules.
    private static boolean isStandardUuidText(@Nullable String string) {
        return string != null && STANDARD_PATTERN.matcher(string).matches();
    }

    /// Returns whether text can be parsed as a standard 36-character UUID.
    private static boolean isParseableStandardUuidText(@Nullable String string) {
        if (string == null || string.length() != 36) {
            return false;
        }
        try {
            UUIDs.parse(string);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}
