// Copyright (c) 2026 Glavo
// SPDX-License-Identifier: MPL-2.0

package org.glavo.uuid;

import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.InstantSource;
import java.util.Random;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class UUIDsTest {

    // RFC 9562 Appendix A well-known namespace UUIDs
    private static final UUID NS_DNS = UUID.fromString("6ba7b810-9dad-11d1-80b4-00c04fd430c8");

    // ---- Constants ----

    @Test
    void nilIsAllZeros() {
        assertEquals(0L, UUIDs.NIL.getMostSignificantBits());
        assertEquals(0L, UUIDs.NIL.getLeastSignificantBits());
        assertEquals("00000000-0000-0000-0000-000000000000", UUIDs.NIL.toString());
    }

    @Test
    void maxIsAllOnes() {
        assertEquals(-1L, UUIDs.MAX.getMostSignificantBits());
        assertEquals(-1L, UUIDs.MAX.getLeastSignificantBits());
        assertEquals("ffffffff-ffff-ffff-ffff-ffffffffffff", UUIDs.MAX.toString());
    }

    @Test
    void namespaceDnsMatchesRfc() {
        assertEquals(UUID.fromString("6ba7b810-9dad-11d1-80b4-00c04fd430c8"), UUIDs.NAMESPACE_DNS);
    }

    @Test
    void namespaceUrlMatchesRfc() {
        assertEquals(UUID.fromString("6ba7b811-9dad-11d1-80b4-00c04fd430c8"), UUIDs.NAMESPACE_URL);
    }

    @Test
    void namespaceOidMatchesRfc() {
        assertEquals(UUID.fromString("6ba7b812-9dad-11d1-80b4-00c04fd430c8"), UUIDs.NAMESPACE_OID);
    }

    @Test
    void namespaceX500MatchesRfc() {
        assertEquals(UUID.fromString("6ba7b814-9dad-11d1-80b4-00c04fd430c8"), UUIDs.NAMESPACE_X500);
    }

    @Test
    void dceDomainConstantsMatchRegisteredValues() {
        assertEquals(0, UUIDs.DCE_DOMAIN_PERSON);
        assertEquals(1, UUIDs.DCE_DOMAIN_GROUP);
        assertEquals(2, UUIDs.DCE_DOMAIN_ORG);
    }

    // ---- Parsing ----

    @Test
    void parseStandardFormat() {
        UUID expected = UUID.fromString("550e8400-e29b-41d4-a716-446655440000");
        assertEquals(expected, UUIDs.parse("550e8400-e29b-41d4-a716-446655440000"));
    }

    @Test
    void parseCompactFormat() {
        UUID expected = UUID.fromString("550e8400-e29b-41d4-a716-446655440000");
        assertEquals(expected, UUIDs.parse("550e8400e29b41d4a716446655440000"));
    }

    @Test
    void parseWindowsRegistryFormat() {
        UUID expected = UUID.fromString("550e8400-e29b-41d4-a716-446655440000");
        assertEquals(expected, UUIDs.parse("{550e8400-e29b-41d4-a716-446655440000}"));
    }

    @Test
    void parseUrnFormat() {
        UUID expected = UUID.fromString("550e8400-e29b-41d4-a716-446655440000");
        assertEquals(expected, UUIDs.parse("urn:uuid:550e8400-e29b-41d4-a716-446655440000"));
    }

    @Test
    void parseUrnCaseInsensitive() {
        UUID expected = UUID.fromString("550e8400-e29b-41d4-a716-446655440000");
        assertEquals(expected, UUIDs.parse("URN:UUID:550e8400-e29b-41d4-a716-446655440000"));
    }

    @Test
    void parseJavaStyleShortHyphenatedFormat() {
        assertEquals(UUID.fromString("00000001-0001-0001-0001-000000000001"),
                UUIDs.parse("1-1-1-1-1"));
    }

    @Test
    void parseJavaStyleHyphenatedFormatUsesLowBits() {
        assertEquals(UUID.fromString("56789012-2345-2345-2345-000000000001"),
                UUIDs.parse("123456789012-12345-12345-12345-1"));
    }

    @Test
    void parseJavaStyleHyphenatedFormatWithNonCanonicalDashPositions() {
        assertEquals(UUID.fromString("23456789-1234-1234-1234-012345678901"),
                UUIDs.parse("123456789-1234-1234-1234-12345678901"));
    }

    @Test
    void parseJavaStyleHyphenatedFormatWithPlusSign() {
        assertEquals(UUID.fromString("00000001-0001-0001-0001-000000000001"),
                UUIDs.parse("+1-+1-+1-+1-+1"));
    }

    @Test
    void parseJavaStyleCanonicalLengthHyphenatedFormatWithPlusSign() {
        assertEquals(UUID.fromString("02345678-1234-1234-1234-123456789012"),
                UUIDs.parse("+2345678-1234-1234-1234-123456789012"));
    }

    @Test
    void parseInvalidThrows() {
        assertThrows(IllegalArgumentException.class, () -> UUIDs.parse("not-a-uuid"));
        assertThrows(IllegalArgumentException.class, () -> UUIDs.parse("550e8400-e29b-41d4-a716-44665544000g"));
        assertThrows(IllegalArgumentException.class, () -> UUIDs.parse("[550e8400-e29b-41d4-a716-446655440000]"));
        assertThrows(IllegalArgumentException.class, () -> UUIDs.parse("1-1-1-1"));
        assertThrows(IllegalArgumentException.class, () -> UUIDs.parse("1-1-1-1-1-1"));
    }

    // ---- Formatting ----

    @Test
    void toCompactStringRemovesHyphens() {
        UUID uuid = UUID.fromString("550e8400-e29b-41d4-a716-446655440000");
        assertEquals("550e8400e29b41d4a716446655440000", UUIDs.toCompactString(uuid));
    }

    @Test
    void toURNStringPrefixesUrn() {
        UUID uuid = UUID.fromString("550e8400-e29b-41d4-a716-446655440000");
        assertEquals("urn:uuid:550e8400-e29b-41d4-a716-446655440000", UUIDs.toURNString(uuid));
    }

    @Test
    void toBase62StringNil() {
        assertEquals("0000000000000000000000", UUIDs.toBase62String(UUIDs.NIL));
    }

    @Test
    void toBase62StringRoundTrip() {
        UUID uuid = UUID.fromString("550e8400-e29b-41d4-a716-446655440000");
        String base62 = UUIDs.toBase62String(uuid);
        assertEquals(22, base62.length());
        assertEquals(uuid, UUIDs.parse(base62));
    }

    @Test
    void parseBase62Max() {
        String base62Max = UUIDs.toBase62String(UUIDs.MAX);
        assertEquals("7n42DGM5Tflk9n8mt7Fhc7", base62Max);
        assertEquals(UUIDs.MAX, UUIDs.parse(base62Max));
    }

    @Test
    void parseBase62RejectsOverflow() {
        assertThrows(IllegalArgumentException.class, () -> UUIDs.parse("zzzzzzzzzzzzzzzzzzzzzz"));
    }

    @Test
    void toOIDStringProducesValidOid() {
        UUID uuid = UUIDs.NIL;
        assertEquals("2.25.0", UUIDs.toOIDString(uuid));
    }

    @Test
    void toOIDStringNonZero() {
        // UUID 00000000-0000-0000-0000-000000000001 = integer 1
        UUID uuid = new UUID(0L, 1L);
        assertEquals("2.25.1", UUIDs.toOIDString(uuid));
    }

    // ---- Comparison ----

    @Test
    void compareNilLessThanMax() {
        assertTrue(UUIDs.compare(UUIDs.NIL, UUIDs.MAX) < 0);
        assertTrue(UUIDs.compare(UUIDs.MAX, UUIDs.NIL) > 0);
    }

    @Test
    void compareEqualUuids() {
        UUID uuid = UUID.fromString("550e8400-e29b-41d4-a716-446655440000");
        assertEquals(0, UUIDs.compare(uuid, uuid));
    }

    @Test
    void comparatorConsistentWithCompare() {
        UUID a = UUID.fromString("00000000-0000-0000-0000-000000000001");
        UUID b = UUID.fromString("00000000-0000-0000-0000-000000000002");
        assertEquals(UUIDs.compare(a, b), UUIDs.comparator().compare(a, b));
    }

    // ---- Version 1 (time-based) ----

    @Test
    void v1FromGregorianTimestamp() {
        UUID result = UUIDs.v1(0x01B2_1DD2_1381_4000L, 0x1234, 0x1234_5678_9ABCL);
        assertEquals(1, result.version());
        assertEquals(2, result.variant());
        assertEquals(UUID.fromString("13814000-1dd2-11b2-9234-123456789abc"), result);
    }

    @Test
    void v1FromInstant() {
        UUID result = UUIDs.v1(Instant.EPOCH, 0, 0);
        assertEquals(UUID.fromString("13814000-1dd2-11b2-8000-000000000000"), result);
        assertEquals(Instant.EPOCH, UUIDs.getInstant(result));
    }

    @Test
    void generateV1ProducesValidUuid() {
        Instant instant = Instant.ofEpochSecond(1, 123_456_700);
        UUID result = UUIDs.generateV1(InstantSource.fixed(instant), new Random(0));
        assertEquals(1, result.version());
        assertEquals(2, result.variant());
        assertEquals(instant, UUIDs.getInstant(result));
        assertNotEquals(0L, result.getLeastSignificantBits() & (1L << 40));
    }

    // ---- Version 2 (DCE Security) ----

    @Test
    void v2FromGregorianTimestamp() {
        UUID result = UUIDs.v2(0x01B2_1DD2_1381_4000L, UUIDs.DCE_DOMAIN_GROUP,
                0x1234_5678L, 0x3F, 0x1234_5678_9ABCL);
        assertEquals(2, result.version());
        assertEquals(2, result.variant());
        assertEquals(UUID.fromString("12345678-1dd2-21b2-bf01-123456789abc"), result);
    }

    @Test
    void v2FromInstant() {
        UUID result = UUIDs.v2(Instant.EPOCH, UUIDs.DCE_DOMAIN_PERSON, 501, 0, 0);
        assertEquals(UUID.fromString("000001f5-1dd2-21b2-8000-000000000000"), result);
    }

    @Test
    void getInstantFromV2ReturnsLowerBoundTimestamp() {
        UUID result = UUIDs.v2(Instant.EPOCH, UUIDs.DCE_DOMAIN_PERSON, 501, 0, 0);
        assertEquals(Instant.parse("1969-12-31T23:59:27.276236800Z"), UUIDs.getInstant(result));
    }

    @Test
    void generateV2ProducesValidUuid() {
        Instant instant = Instant.ofEpochSecond(1, 123_456_700);
        UUID result = UUIDs.generateV2(UUIDs.DCE_DOMAIN_PERSON, 501, InstantSource.fixed(instant), new Random(0));
        assertEquals(2, result.version());
        assertEquals(2, result.variant());
        assertEquals(501L, result.getMostSignificantBits() >>> 32);
        assertEquals(UUIDs.DCE_DOMAIN_PERSON, (int) ((result.getLeastSignificantBits() >>> 48) & 0xFFL));
        assertNotEquals(0L, result.getLeastSignificantBits() & (1L << 40));
    }

    // ---- Version 3 (MD5) ----

    @Test
    void v3FromMd5Digest() {
        byte[] digest = {
                0x00, 0x01, 0x02, 0x03,
                0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0A, 0x0B,
                0x0C, 0x0D, 0x0E, 0x0F
        };
        UUID result = UUIDs.v3(digest);
        assertEquals(3, result.version());
        assertEquals(2, result.variant());
        assertEquals(UUID.fromString("00010203-0405-3607-8809-0a0b0c0d0e0f"), result);
    }

    @Test
    void v3RejectsInvalidMd5DigestLength() {
        assertThrows(IllegalArgumentException.class, () -> UUIDs.v3(new byte[15]));
        assertThrows(IllegalArgumentException.class, () -> UUIDs.v3(new byte[17]));
    }

    @Test
    void generateV3WithDnsNamespace() {
        UUID result = UUIDs.generateV3(NS_DNS, "www.example.com");
        assertEquals(3, result.version());
        assertEquals(2, result.variant());
        assertEquals(UUID.fromString("5df41881-3aed-3515-88a7-2f4a814cf09e"), result);
    }

    @Test
    void generateV3ByteArrayMatchesString() {
        UUID fromString = UUIDs.generateV3(NS_DNS, "www.example.com");
        UUID fromBytes = UUIDs.generateV3(NS_DNS, "www.example.com".getBytes(StandardCharsets.UTF_8));
        assertEquals(fromString, fromBytes);
    }

    @Test
    void generateV3ByteBufferMatchesString() {
        UUID fromString = UUIDs.generateV3(NS_DNS, "www.example.com");
        byte[] nameBytes = "www.example.com".getBytes(StandardCharsets.UTF_8);
        UUID fromBuffer = UUIDs.generateV3(NS_DNS, ByteBuffer.wrap(nameBytes));
        assertEquals(fromString, fromBuffer);
    }

    @Test
    void generateV3WithNullNamespace() {
        UUID result = UUIDs.generateV3(null, "test");
        assertEquals(3, result.version());
        assertEquals(2, result.variant());
    }

    // ---- Version 4 (random) ----

    @Test
    void v4SetsVersionAndVariant() {
        UUID result = UUIDs.v4(0xFFFFFFFFFFFFFFFFL, 0xFFFFFFFFFFFFFFFFL);
        assertEquals(4, result.version());
        assertEquals(2, result.variant());
    }

    @Test
    void generateV4ProducesValidUuid() {
        UUID result = UUIDs.generateV4();
        assertEquals(4, result.version());
        assertEquals(2, result.variant());
    }

    // ---- Version 5 (SHA-1) ----

    @Test
    void v5FromSha1Digest() {
        byte[] digest = {
                0x00, 0x01, 0x02, 0x03,
                0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0A, 0x0B,
                0x0C, 0x0D, 0x0E, 0x0F,
                0x10, 0x11, 0x12, 0x13
        };
        UUID result = UUIDs.v5(digest);
        assertEquals(5, result.version());
        assertEquals(2, result.variant());
        assertEquals(UUID.fromString("00010203-0405-5607-8809-0a0b0c0d0e0f"), result);
    }

    @Test
    void v5RejectsInvalidSha1DigestLength() {
        assertThrows(IllegalArgumentException.class, () -> UUIDs.v5(new byte[16]));
        assertThrows(IllegalArgumentException.class, () -> UUIDs.v5(new byte[21]));
    }

    @Test
    void generateV5WithDnsNamespace() {
        UUID result = UUIDs.generateV5(NS_DNS, "www.example.com");
        assertEquals(5, result.version());
        assertEquals(2, result.variant());
        assertEquals(UUID.fromString("2ed6657d-e927-568b-95e1-2665a8aea6a2"), result);
    }

    @Test
    void generateV5ByteArrayMatchesString() {
        UUID fromString = UUIDs.generateV5(NS_DNS, "www.example.com");
        UUID fromBytes = UUIDs.generateV5(NS_DNS, "www.example.com".getBytes(StandardCharsets.UTF_8));
        assertEquals(fromString, fromBytes);
    }

    // ---- Version 6 (reordered time-based) ----

    @Test
    void v6FromGregorianTimestamp() {
        UUID result = UUIDs.v6(0x01B2_1DD2_1381_4000L, 0x1234, 0x1234_5678_9ABCL);
        assertEquals(6, result.version());
        assertEquals(2, result.variant());
        assertEquals(UUID.fromString("1b21dd21-3814-6000-9234-123456789abc"), result);
    }

    @Test
    void v6FromInstant() {
        UUID result = UUIDs.v6(Instant.EPOCH, 0, 0);
        assertEquals(UUID.fromString("1b21dd21-3814-6000-8000-000000000000"), result);
        assertEquals(Instant.EPOCH, UUIDs.getInstant(result));
    }

    @Test
    void v6OrdersByTimestamp() {
        UUID earlier = UUIDs.v6(0x01B2_1DD2_1381_4000L, 0, 0);
        UUID later = UUIDs.v6(0x01B2_1DD2_1381_4001L, 0, 0);
        assertTrue(UUIDs.compare(earlier, later) < 0);
    }

    @Test
    void generateV6ProducesValidUuid() {
        Instant instant = Instant.ofEpochSecond(1, 123_456_700);
        UUID result = UUIDs.generateV6(InstantSource.fixed(instant), new Random(0));
        assertEquals(6, result.version());
        assertEquals(2, result.variant());
        assertEquals(instant, UUIDs.getInstant(result));
        assertNotEquals(0L, result.getLeastSignificantBits() & (1L << 40));
    }

    // ---- Version 7 (time-ordered) ----

    @Test
    void v7HasCorrectVersionAndVariant() {
        UUID result = UUIDs.v7(1_000_000_000L, 0xABCD_EF01_2345_6789L);
        assertEquals(7, result.version());
        assertEquals(2, result.variant());
    }

    @Test
    void v7PreservesTimestamp() {
        long epochMilli = 1_718_000_000_000L;
        UUID result = UUIDs.v7(epochMilli, 0L);
        long extractedMilli = result.getMostSignificantBits() >>> 16;
        assertEquals(epochMilli, extractedMilli);
    }

    @Test
    void v7FromInstant() {
        Instant instant = Instant.ofEpochMilli(1_718_000_000_000L);
        UUID fromInstant = UUIDs.v7(instant, 0L);
        UUID fromMilli = UUIDs.v7(1_718_000_000_000L, 0L);
        assertEquals(fromMilli, fromInstant);
    }

    @Test
    void generateV7ProducesValidUuid() {
        UUID result = UUIDs.generateV7();
        assertEquals(7, result.version());
        assertEquals(2, result.variant());
    }

    // ---- Version 8 (custom) ----

    @Test
    void v8SetsVersionAndVariant() {
        UUID result = UUIDs.v8(0L, 0L);
        assertEquals(8, result.version());
        assertEquals(2, result.variant());
    }

    // ---- Timestamp extraction ----

    @Test
    void getInstantFromV7() {
        long epochMilli = 1_718_000_000_000L;
        UUID uuid = UUIDs.v7(epochMilli, 0L);
        Instant instant = UUIDs.getInstant(uuid);
        assertEquals(Instant.ofEpochMilli(epochMilli), instant);
    }

    @Test
    void getInstantFromV1() {
        // Well-known v1 UUID: the DNS namespace UUID is version 1
        UUID v1 = UUID.fromString("6ba7b810-9dad-11d1-80b4-00c04fd430c8");
        assertEquals(1, v1.version());
        Instant instant = UUIDs.getInstant(v1);
        assertNotNull(instant);
        // The DNS namespace UUID was created around 1998-02-04
        assertTrue(instant.isAfter(Instant.parse("1998-02-01T00:00:00Z")));
        assertTrue(instant.isBefore(Instant.parse("1998-02-28T00:00:00Z")));
    }

    @Test
    void getInstantUnsupportedVersionThrows() {
        UUID v4 = UUIDs.generateV4();
        assertThrows(IllegalArgumentException.class, () -> UUIDs.getInstant(v4));
    }

    // ---- newWithVersion ----

    @Test
    void newWithVersionSetsVersionAndVariant() {
        UUID result = UUIDs.newWithVersion(0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_FFFF_FFFF_FFFFL, 4);
        assertEquals(4, result.version());
        assertEquals(2, result.variant());
    }

    @Test
    void newWithVersionPreservesOtherBits() {
        UUID result = UUIDs.newWithVersion(0L, 0L, 0);
        assertEquals(0, result.version());
        assertEquals(2, result.variant());
    }

    // ---- Parse round-trip ----

    @Test
    void parseRoundTripWithCompact() {
        UUID original = UUID.fromString("550e8400-e29b-41d4-a716-446655440000");
        UUID parsed = UUIDs.parse(UUIDs.toCompactString(original));
        assertEquals(original, parsed);
    }

    @Test
    void parseRoundTripWithUrn() {
        UUID original = UUID.fromString("550e8400-e29b-41d4-a716-446655440000");
        // URN contains standard format inside, so parse should handle it
        String urn = UUIDs.toURNString(original);
        UUID parsed = UUIDs.parse(urn);
        assertEquals(original, parsed);
    }
}
