// Copyright (c) 2026 Glavo
// SPDX-License-Identifier: MPL-2.0

package org.glavo.uuid;

import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class UUIDsTest {

    // RFC 9562 Appendix A well-known namespace UUIDs
    private static final UUID NS_DNS = UUID.fromString("6ba7b810-9dad-11d1-80b4-00c04fd430c8");

    @Test
    void nilIsAllZeros() {
        assertEquals(0L, UUIDs.NIL.getMostSignificantBits());
        assertEquals(0L, UUIDs.NIL.getLeastSignificantBits());
        assertEquals(0, UUIDs.NIL.version());
    }

    // RFC 9562 Appendix B.1: v3 with DNS namespace and "www.example.com"
    @Test
    void v3WithDnsNamespace() {
        UUID result = UUIDs.v3("www.example.com", NS_DNS);
        assertEquals(3, result.version());
        assertEquals(2, result.variant());
        assertEquals(UUID.fromString("5df41881-3aed-3515-88a7-2f4a814cf09e"), result);
    }

    @Test
    void v3ByteArrayMatchesString() {
        UUID fromString = UUIDs.v3("www.example.com", NS_DNS);
        UUID fromBytes = UUIDs.v3("www.example.com".getBytes(java.nio.charset.StandardCharsets.UTF_8), NS_DNS);
        assertEquals(fromString, fromBytes);
    }

    @Test
    void v3ByteBufferMatchesString() {
        UUID fromString = UUIDs.v3("www.example.com", NS_DNS);
        byte[] nameBytes = "www.example.com".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        UUID fromBuffer = UUIDs.v3(ByteBuffer.wrap(nameBytes), NS_DNS);
        assertEquals(fromString, fromBuffer);
    }

    @Test
    void v3WithNullNamespace() {
        UUID result = UUIDs.v3("test", null);
        assertEquals(3, result.version());
        assertEquals(2, result.variant());
    }

    // RFC 9562 Appendix B.2: v5 with DNS namespace and "www.example.com"
    @Test
    void v5WithDnsNamespace() {
        UUID result = UUIDs.v5("www.example.com", NS_DNS);
        assertEquals(5, result.version());
        assertEquals(2, result.variant());
        assertEquals(UUID.fromString("2ed6657d-e927-568b-95e1-2665a8aea6a2"), result);
    }

    @Test
    void v5ByteArrayMatchesString() {
        UUID fromString = UUIDs.v5("www.example.com", NS_DNS);
        UUID fromBytes = UUIDs.v5("www.example.com".getBytes(java.nio.charset.StandardCharsets.UTF_8), NS_DNS);
        assertEquals(fromString, fromBytes);
    }

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
        // Extract the 48-bit timestamp from the most significant bits
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
    void newWithVersionSetsVersionAndVariant() {
        UUID result = UUIDs.newWithVersion(0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_FFFF_FFFF_FFFFL, 4);
        assertEquals(4, result.version());
        assertEquals(2, result.variant());
    }

    @Test
    void newWithVersionPreservesOtherBits() {
        UUID result = UUIDs.newWithVersion(0L, 0L, 0);
        assertEquals(0, result.version());
        // Variant bits should be set to 10 even with zero input
        assertEquals(2, result.variant());
    }
}
