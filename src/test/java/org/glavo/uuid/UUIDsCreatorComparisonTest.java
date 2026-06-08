// Copyright (c) 2026 Glavo
// SPDX-License-Identifier: MPL-2.0

package org.glavo.uuid;

import com.github.f4b6a3.uuid.UuidCreator;
import org.jetbrains.annotations.NotNullByDefault;
import org.jetbrains.annotations.Unmodifiable;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;

/// Cross-library compatibility tests against uuid-creator.
@NotNullByDefault
class UUIDsCreatorComparisonTest {
    /// Namespaces used for name-based UUID comparison.
    private static final UUID @Unmodifiable [] NAMESPACES = {
            UUIDs.NAMESPACE_DNS,
            UUIDs.NAMESPACE_URL,
            UUIDs.NAMESPACE_OID,
            UUIDs.NAMESPACE_X500,
            UUIDs.NIL,
            UUID.fromString("01234567-89ab-cdef-0123-456789abcdef"),
    };

    /// UTF-8 string names used for name-based UUID comparison.
    private static final String @Unmodifiable [] STRING_NAMES = {
            "",
            "example.com",
            "www.example.com",
            "https://example.com/resource?id=42",
            "urn:example:uuid-tools",
            "uuid-tools-\u00FCnicode",
            "emoji-\uD83D\uDD11",
    };

    /// Binary names used for name-based UUID comparison.
    private static final byte @Unmodifiable [] @Unmodifiable [] BYTE_NAMES = {
            {},
            "example.com".getBytes(StandardCharsets.UTF_8),
            {0, 1, 2, 3, 4, 5, 6, 7},
            {(byte) 0xFF, 0, (byte) 0x80, 0x7F, 0x55, (byte) 0xAA},
            "uuid-tools-\u00FCnicode".getBytes(StandardCharsets.UTF_8),
    };

    /// Generates version-3 UUIDs from string names like uuid-creator.
    @Test
    void generateV3StringNamesMatchUuidCreator() {
        for (UUID namespace : NAMESPACES) {
            for (String name : STRING_NAMES) {
                assertEquals(
                        UuidCreator.getNameBasedMd5(namespace, name),
                        UUIDs.generateV3(namespace, name));
            }
        }
    }

    /// Generates version-3 UUIDs from byte-array names like uuid-creator.
    @Test
    void generateV3ByteNamesMatchUuidCreator() {
        for (UUID namespace : NAMESPACES) {
            for (byte[] name : BYTE_NAMES) {
                UUID expected = UuidCreator.getNameBasedMd5(namespace, name);
                assertEquals(expected, UUIDs.generateV3(namespace, name));
                assertEquals(expected, UUIDs.generateV3(namespace, ByteBuffer.wrap(name)));
            }
        }
    }

    /// Generates version-5 UUIDs from string names like uuid-creator.
    @Test
    void generateV5StringNamesMatchUuidCreator() {
        for (UUID namespace : NAMESPACES) {
            for (String name : STRING_NAMES) {
                assertEquals(
                        UuidCreator.getNameBasedSha1(namespace, name),
                        UUIDs.generateV5(namespace, name));
            }
        }
    }

    /// Generates version-5 UUIDs from byte-array names like uuid-creator.
    @Test
    void generateV5ByteNamesMatchUuidCreator() {
        for (UUID namespace : NAMESPACES) {
            for (byte[] name : BYTE_NAMES) {
                UUID expected = UuidCreator.getNameBasedSha1(namespace, name);
                assertEquals(expected, UUIDs.generateV5(namespace, name));
                assertEquals(expected, UUIDs.generateV5(namespace, ByteBuffer.wrap(name)));
            }
        }
    }
}
