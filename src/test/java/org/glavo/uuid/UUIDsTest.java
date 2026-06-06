// Copyright (c) 2026 Glavo
// SPDX-License-Identifier: MPL-2.0

package org.glavo.uuid;

import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
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
    void parseInvalidThrows() {
        assertThrows(IllegalArgumentException.class, () -> UUIDs.parse("not-a-uuid"));
        assertThrows(IllegalArgumentException.class, () -> UUIDs.parse("550e8400-e29b-41d4-a716-44665544000g"));
        assertThrows(IllegalArgumentException.class, () -> UUIDs.parse("[550e8400-e29b-41d4-a716-446655440000]"));
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

    // ---- Version 3 (MD5) ----

    @Test
    void v3WithDnsNamespace() {
        UUID result = UUIDs.v3(NS_DNS, "www.example.com");
        assertEquals(3, result.version());
        assertEquals(2, result.variant());
        assertEquals(UUID.fromString("5df41881-3aed-3515-88a7-2f4a814cf09e"), result);
    }

    @Test
    void v3ByteArrayMatchesString() {
        UUID fromString = UUIDs.v3(NS_DNS, "www.example.com");
        UUID fromBytes = UUIDs.v3(NS_DNS, "www.example.com".getBytes(StandardCharsets.UTF_8));
        assertEquals(fromString, fromBytes);
    }

    @Test
    void v3ByteBufferMatchesString() {
        UUID fromString = UUIDs.v3(NS_DNS, "www.example.com");
        byte[] nameBytes = "www.example.com".getBytes(StandardCharsets.UTF_8);
        UUID fromBuffer = UUIDs.v3(NS_DNS, ByteBuffer.wrap(nameBytes));
        assertEquals(fromString, fromBuffer);
    }

    @Test
    void v3WithNullNamespace() {
        UUID result = UUIDs.v3(null, "test");
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
    void v5WithDnsNamespace() {
        UUID result = UUIDs.v5(NS_DNS, "www.example.com");
        assertEquals(5, result.version());
        assertEquals(2, result.variant());
        assertEquals(UUID.fromString("2ed6657d-e927-568b-95e1-2665a8aea6a2"), result);
    }

    @Test
    void v5ByteArrayMatchesString() {
        UUID fromString = UUIDs.v5(NS_DNS, "www.example.com");
        UUID fromBytes = UUIDs.v5(NS_DNS, "www.example.com".getBytes(StandardCharsets.UTF_8));
        assertEquals(fromString, fromBytes);
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
