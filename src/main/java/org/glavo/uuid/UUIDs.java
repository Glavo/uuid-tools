// Copyright (c) 2026 Glavo
// SPDX-License-Identifier: MPL-2.0

package org.glavo.uuid;

import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNullByDefault;
import org.jetbrains.annotations.Nullable;

import java.io.Serial;
import java.io.Serializable;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.InstantSource;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.UUID;
import java.util.random.RandomGenerator;

/// Utility class for creating, parsing, formatting, and comparing [UUID]
/// instances of various versions defined by
/// [RFC 9562](https://www.rfc-editor.org/rfc/rfc9562).
///
/// Supported UUID versions:
///
/// - **Version 3** — name-based UUID using MD5 hashing (RFC 9562 § 5.3).
/// - **Version 4** — random UUID (RFC 9562 § 5.4).
/// - **Version 5** — name-based UUID using SHA-1 hashing (RFC 9562 § 5.5).
/// - **Version 7** — time-ordered UUID combining a Unix epoch millisecond
///   timestamp with random bits (RFC 9562 § 5.7).
/// - **Version 8** — custom/experimental UUID (RFC 9562 § 5.8).
///
/// This class provides:
///
/// - Well-known constants: [#NIL], [#MAX], and the four predefined namespace
///   UUIDs ([#NAMESPACE_DNS], [#NAMESPACE_URL], [#NAMESPACE_OID],
///   [#NAMESPACE_X500]).
/// - Parsing from multiple string formats via [#parse(String)].
/// - Formatting to compact, URN, OID, and Base62 string representations.
/// - Timestamp extraction from time-based UUIDs via [#getInstant(UUID)].
/// - Unsigned lexicographic comparison via [#compare(UUID, UUID)] and
///   [#comparator()].
/// - The low-level helper [#newWithVersion(long, long, int)] for stamping
///   version and variant bits onto arbitrary 128-bit values.
///
/// All public methods are thread-safe.
@NotNullByDefault
public final class UUIDs {

    // ========================================================================
    // Constants
    // ========================================================================

    /// The nil UUID whose 128 bits are all zero (`00000000-0000-0000-0000-000000000000`),
    /// as defined by RFC 9562 § 5.9.
    public static final UUID NIL = new UUID(0L, 0L);

    /// The max UUID whose 128 bits are all one (`ffffffff-ffff-ffff-ffff-ffffffffffff`),
    /// as defined by RFC 9562 § 5.10.
    public static final UUID MAX = new UUID(-1L, -1L);

    /// The predefined DNS namespace UUID (`6ba7b810-9dad-11d1-80b4-00c04fd430c8`),
    /// as defined by RFC 9562 § 6.6.
    public static final UUID NAMESPACE_DNS = new UUID(0x6ba7b8109dad11d1L, 0x80b400c04fd430c8L);

    /// The predefined URL namespace UUID (`6ba7b811-9dad-11d1-80b4-00c04fd430c8`),
    /// as defined by RFC 9562 § 6.6.
    public static final UUID NAMESPACE_URL = new UUID(0x6ba7b8119dad11d1L, 0x80b400c04fd430c8L);

    /// The predefined OID namespace UUID (`6ba7b812-9dad-11d1-80b4-00c04fd430c8`),
    /// as defined by RFC 9562 § 6.6.
    public static final UUID NAMESPACE_OID = new UUID(0x6ba7b8129dad11d1L, 0x80b400c04fd430c8L);

    /// The predefined X.500 DN namespace UUID (`6ba7b814-9dad-11d1-80b4-00c04fd430c8`),
    /// as defined by RFC 9562 § 6.6.
    public static final UUID NAMESPACE_X500 = new UUID(0x6ba7b8149dad11d1L, 0x80b400c04fd430c8L);

    // ========================================================================
    // Parsing
    // ========================================================================

    /// Parses a UUID from its string representation.
    ///
    /// The following formats are recognized based on the input length:
    ///
    /// | Length | Format                  | Example                                        |
    /// |--------|-------------------------|------------------------------------------------|
    /// | 36     | Standard hyphenated     | `550e8400-e29b-41d4-a716-446655440000`          |
    /// | 32     | Compact (no hyphens)    | `550e8400e29b41d4a716446655440000`              |
    /// | 38     | Windows registry        | `{550e8400-e29b-41d4-a716-446655440000}`        |
    /// | 45     | URN                     | `urn:uuid:550e8400-e29b-41d4-a716-446655440000` |
    /// | 22     | Base62                  | `6aGFHbkMKi3UrLaRLGaKzG`                       |
    ///
    /// @param value the string to parse
    /// @return the parsed UUID
    /// @throws IllegalArgumentException if the string is not a valid UUID in any recognized format
    ///                                  or if a Base62 value is outside the UUID range
    @Contract(pure = true)
    public static UUID parse(String value) {
        int length = value.length(); // implicit null check

        if (length == 36) {
            return parseStandard(value, 0);
        } else if (length == 32) {
            return parseCompact(value);
        } else if (length == 38) {
            // Windows registry format: {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
            if (value.charAt(0) != '{' || value.charAt(37) != '}') {
                throw new IllegalArgumentException("Invalid UUID string: " + value);
            }
            return parseStandard(value, 1);
        } else if (length == 45) {
            // URN format: urn:uuid:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
            if (!value.regionMatches(true, 0, "urn:uuid:", 0, 9)) {
                throw new IllegalArgumentException("Invalid UUID string: " + value);
            }
            return parseStandard(value, 9);
        } else if (length == 22) {
            return parseBase62(value);
        } else {
            throw new IllegalArgumentException("Invalid UUID string: " + value);
        }
    }

    // ========================================================================
    // Timestamp extraction
    // ========================================================================

    /// Extracts the timestamp from a time-based UUID as an [Instant].
    ///
    /// Supported versions:
    ///
    /// - **Version 1**: Gregorian 100-nanosecond timestamp (RFC 9562 § 5.1).
    /// - **Version 6**: Reordered Gregorian timestamp (RFC 9562 § 5.6).
    /// - **Version 7**: Unix epoch millisecond timestamp (RFC 9562 § 5.7).
    ///
    /// @param uuid the UUID to extract the timestamp from
    /// @return the timestamp as an [Instant]
    /// @throws IllegalArgumentException if the UUID version does not contain a timestamp
    @Contract(pure = true)
    public static Instant getInstant(UUID uuid) {
        int version = uuid.version();
        return switch (version) {
            case 1 -> instantFromGregorianTimestamp(getV1Timestamp(uuid));
            case 6 -> instantFromGregorianTimestamp(getV6Timestamp(uuid));
            case 7 -> Instant.ofEpochMilli(uuid.getMostSignificantBits() >>> 16);
            default -> throw new IllegalArgumentException("UUID version " + version + " does not contain a timestamp");
        };
    }

    // ========================================================================
    // Formatting
    // ========================================================================

    /// Returns the compact (no hyphens) 32-character lowercase hex string
    /// representation of the UUID.
    ///
    /// Example: `550e8400e29b41d4a716446655440000`
    ///
    /// @param uuid the UUID to format
    /// @return the compact hex string
    @Contract(pure = true)
    public static String toCompactString(UUID uuid) {
        return HEX_FORMAT.toHexDigits(uuid.getMostSignificantBits())
                + HEX_FORMAT.toHexDigits(uuid.getLeastSignificantBits());
    }

    /// Returns the URN representation of the UUID as defined by RFC 9562 § 3.
    ///
    /// Example: `urn:uuid:550e8400-e29b-41d4-a716-446655440000`
    ///
    /// @param uuid the UUID to format
    /// @return the URN string
    @Contract(pure = true)
    public static String toURNString(UUID uuid) {
        return "urn:uuid:" + uuid;
    }

    /// Returns the Base62-encoded string representation of the UUID.
    ///
    /// The 128-bit UUID value is interpreted as an unsigned integer and
    /// encoded using the digit set `0-9A-Za-z`. The result is left-padded
    /// with `0` characters to a fixed length of 22 characters.
    ///
    /// Example: the nil UUID produces `0000000000000000000000`.
    ///
    /// @param uuid the UUID to format
    /// @return the 22-character Base62 string
    @Contract(pure = true)
    public static String toBase62String(UUID uuid) {
        long mostSigBits = uuid.getMostSignificantBits();
        long leastSigBits = uuid.getLeastSignificantBits();
        long word0 = mostSigBits >>> 32;
        long word1 = mostSigBits & UINT_MASK;
        long word2 = leastSigBits >>> 32;
        long word3 = leastSigBits & UINT_MASK;
        char[] buf = new char[22];
        // Divide the unsigned 128-bit value by 62 through four 32-bit limbs.
        for (int i = 21; i >= 0; i--) {
            long remainder = 0L;

            long dividend = word0;
            word0 = dividend / 62L;
            remainder = dividend % 62L;

            dividend = (remainder << 32) | word1;
            word1 = dividend / 62L;
            remainder = dividend % 62L;

            dividend = (remainder << 32) | word2;
            word2 = dividend / 62L;
            remainder = dividend % 62L;

            dividend = (remainder << 32) | word3;
            word3 = dividend / 62L;
            buf[i] = BASE62_CHARS[(int) (dividend % 62L)];
        }
        return new String(buf);
    }

    /// Returns the OID (Object Identifier) representation of the UUID,
    /// under the joint ISO/ITU-T UUID arc `2.25`.
    ///
    /// The 128-bit UUID value is interpreted as an unsigned integer and
    /// appended to the `2.25.` prefix.
    ///
    /// Example: `2.25.113059749145936325402354257176981405696`
    ///
    /// @param uuid the UUID to format
    /// @return the OID string
    @Contract(pure = true)
    public static String toOIDString(UUID uuid) {
        byte[] bytes = new byte[17]; // 1 extra byte for unsigned interpretation
        long msb = uuid.getMostSignificantBits();
        long lsb = uuid.getLeastSignificantBits();
        for (int i = 0; i < 8; i++) {
            bytes[i + 1] = (byte) (msb >>> (56 - i * 8));
            bytes[i + 9] = (byte) (lsb >>> (56 - i * 8));
        }
        return "2.25." + new BigInteger(bytes);
    }

    // ========================================================================
    // Comparison
    // ========================================================================

    /// Compares two UUIDs using unsigned lexicographic ordering on their
    /// 128-bit values.
    ///
    /// This ordering treats the UUID as a single unsigned 128-bit integer,
    /// comparing the most significant 64 bits first, then the least
    /// significant 64 bits.
    ///
    /// @param uuid1 the first UUID
    /// @param uuid2 the second UUID
    /// @return a negative value, zero, or a positive value as `uuid1` is less
    ///         than, equal to, or greater than `uuid2`
    @Contract(pure = true)
    public static int compare(UUID uuid1, UUID uuid2) {
        return compare(uuid1.getMostSignificantBits(), uuid1.getLeastSignificantBits(),
                uuid2.getMostSignificantBits(), uuid2.getLeastSignificantBits());
    }

    /// Compares two UUIDs represented as raw 64-bit halves using unsigned
    /// lexicographic ordering.
    ///
    /// @param mostSigBits1  most significant 64 bits of the first UUID
    /// @param leastSigBits1 least significant 64 bits of the first UUID
    /// @param mostSigBits2  most significant 64 bits of the second UUID
    /// @param leastSigBits2 least significant 64 bits of the second UUID
    /// @return a negative value, zero, or a positive value as the first UUID
    ///         is less than, equal to, or greater than the second
    @Contract(pure = true)
    public static int compare(long mostSigBits1, long leastSigBits1,
                              long mostSigBits2, long leastSigBits2) {
        int cmp = Long.compareUnsigned(mostSigBits1, mostSigBits2);
        if (cmp != 0) {
            return cmp;
        }
        return Long.compareUnsigned(leastSigBits1, leastSigBits2);
    }

    /// Returns a serializable [Comparator] that orders UUIDs using unsigned
    /// lexicographic ordering, consistent with [#compare(UUID, UUID)].
    ///
    /// The returned comparator is a singleton and safe for concurrent use.
    ///
    /// @return the UUID comparator
    @Contract(pure = true)
    public static Comparator<UUID> comparator() {
        return UUIDComparator.INSTANCE;
    }

    // ========================================================================
    // Version 3 — MD5 name-based
    // ========================================================================

    /// Creates a version-3 (MD5) name-based UUID from a string name.
    ///
    /// The name is encoded as UTF-8 before hashing. If `namespace` is
    /// non-null, its 16-byte big-endian representation is prepended to the
    /// hash input as specified by RFC 9562 § 5.3.
    ///
    /// @param namespace the optional namespace UUID prepended to the hash input
    /// @param name      the name to hash
    /// @return a version-3 UUID
    @Contract(pure = true)
    public static UUID v3(@Nullable UUID namespace, String name) {
        return v3(namespace, name.getBytes(StandardCharsets.UTF_8));
    }

    /// Creates a version-3 (MD5) name-based UUID from a byte-array name.
    ///
    /// If `namespace` is non-null, its 16-byte big-endian representation is
    /// prepended to the hash input.
    ///
    /// @param namespace the optional namespace UUID prepended to the hash input
    /// @param name      the name bytes to hash
    /// @return a version-3 UUID
    @Contract(pure = true)
    public static UUID v3(@Nullable UUID namespace, byte[] name) {
        return nameBasedUUID(name, namespace, "MD5", 3);
    }

    /// Creates a version-3 (MD5) name-based UUID from a [ByteBuffer] name.
    ///
    /// All remaining bytes in the buffer are consumed. If `namespace` is
    /// non-null, its 16-byte big-endian representation is prepended to the
    /// hash input.
    ///
    /// @param namespace the optional namespace UUID prepended to the hash input
    /// @param name      the buffer whose remaining bytes are hashed
    /// @return a version-3 UUID
    @Contract(pure = true)
    public static UUID v3(@Nullable UUID namespace, ByteBuffer name) {
        return nameBasedUUID(name, namespace, "MD5", 3);
    }

    // ========================================================================
    // Version 4 — random
    // ========================================================================

    /// Creates a version-4 UUID from the given raw 128-bit value.
    ///
    /// The version and variant bits are stamped onto the provided values;
    /// all other bits are preserved. Callers are expected to supply
    /// cryptographically random input.
    ///
    /// @param mostSigBits  the most significant 64 bits (before version stamping)
    /// @param leastSigBits the least significant 64 bits (before variant stamping)
    /// @return a version-4 UUID
    @Contract(pure = true)
    public static UUID v4(long mostSigBits, long leastSigBits) {
        return newWithVersion(mostSigBits, leastSigBits, 4);
    }

    /// Generates a new version-4 UUID using the default [SecureRandom].
    ///
    /// @return a freshly generated version-4 UUID
    public static UUID generateV4() {
        return generateV4(RandomGeneratorHolder.INSTANCE);
    }

    /// Generates a new version-4 UUID using the given random generator.
    ///
    /// @param randomGenerator the source of randomness
    /// @return a freshly generated version-4 UUID
    public static UUID generateV4(RandomGenerator randomGenerator) {
        return v4(randomGenerator.nextLong(), randomGenerator.nextLong());
    }

    // ========================================================================
    // Version 5 — SHA-1 name-based
    // ========================================================================

    /// Creates a version-5 (SHA-1) name-based UUID from a string name.
    ///
    /// The name is encoded as UTF-8 before hashing. If `namespace` is
    /// non-null, its 16-byte big-endian representation is prepended to the
    /// hash input as specified by RFC 9562 § 5.5.
    ///
    /// @param namespace the optional namespace UUID prepended to the hash input
    /// @param name      the name to hash
    /// @return a version-5 UUID
    @Contract(pure = true)
    public static UUID v5(@Nullable UUID namespace, String name) {
        return v5(namespace, name.getBytes(StandardCharsets.UTF_8));
    }

    /// Creates a version-5 (SHA-1) name-based UUID from a byte-array name.
    ///
    /// If `namespace` is non-null, its 16-byte big-endian representation is
    /// prepended to the hash input.
    ///
    /// @param namespace the optional namespace UUID prepended to the hash input
    /// @param name      the name bytes to hash
    /// @return a version-5 UUID
    @Contract(pure = true)
    public static UUID v5(@Nullable UUID namespace, byte[] name) {
        return nameBasedUUID(name, namespace, "SHA-1", 5);
    }

    /// Creates a version-5 (SHA-1) name-based UUID from a [ByteBuffer] name.
    ///
    /// All remaining bytes in the buffer are consumed. If `namespace` is
    /// non-null, its 16-byte big-endian representation is prepended to the
    /// hash input.
    ///
    /// @param namespace the optional namespace UUID prepended to the hash input
    /// @param name      the buffer whose remaining bytes are hashed
    /// @return a version-5 UUID
    @Contract(mutates = "param2")
    public static UUID v5(@Nullable UUID namespace, ByteBuffer name) {
        return nameBasedUUID(name, namespace, "SHA-1", 5);
    }

    // ========================================================================
    // Version 7 — time-ordered
    // ========================================================================

    /// Creates a version-7 UUID from an [Instant] timestamp and random bits.
    ///
    /// The instant is converted to milliseconds since the Unix epoch via
    /// [Instant#toEpochMilli()].
    ///
    /// @param instant    the timestamp
    /// @param randomBits random bits filling the non-timestamp, non-version,
    ///                   non-variant positions
    /// @return a version-7 UUID
    @Contract(pure = true)
    public static UUID v7(Instant instant, long randomBits) {
        return v7(instant.toEpochMilli(), randomBits);
    }

    /// Creates a version-7 UUID from a Unix epoch millisecond timestamp and
    /// random bits.
    ///
    /// The layout follows RFC 9562 § 5.7:
    ///
    /// - Bits 0–47 of `mostSigBits`: the 48-bit Unix timestamp in
    ///   milliseconds.
    /// - Bits 48–51: version (`0111`).
    /// - Bits 52–63: 12 random bits from `randomBits[0..11]`.
    /// - Bits 64–65: variant (`10`).
    /// - Bits 66–127: 62 random bits from `randomBits[12..73]`.
    ///
    /// @param epochMilli the Unix epoch millisecond timestamp
    /// @param randomBits random bits filling the non-timestamp positions
    /// @return a version-7 UUID
    @Contract(pure = true)
    public static UUID v7(long epochMilli, long randomBits) {
        // Most significant 64 bits: 48-bit timestamp | 12 random bits (version set by newWithVersion)
        long mostSigBits = ((epochMilli & 0xFFFF_FFFF_FFFFL) << 16)
                | ((randomBits >>> 52) & 0x0FFFL);
        // Least significant 64 bits: remaining random bits (variant set by newWithVersion)
        long leastSigBits = randomBits << 12 >>> 2;
        return newWithVersion(mostSigBits, leastSigBits, 7);
    }

    /// Generates a new version-7 UUID using the system clock and the default
    /// [SecureRandom].
    ///
    /// @return a freshly generated version-7 UUID
    public static UUID generateV7() {
        return generateV7(InstantSource.system(), RandomGeneratorHolder.INSTANCE);
    }

    /// Generates a new version-7 UUID using the given time source and random
    /// generator.
    ///
    /// Obtains the current millisecond timestamp from `instantSource` and
    /// random bits from `randomGenerator`, then delegates to
    /// [#v7(long, long)].
    ///
    /// @param instantSource   the source of the current time
    /// @param randomGenerator the source of randomness
    /// @return a freshly generated version-7 UUID
    public static UUID generateV7(InstantSource instantSource, RandomGenerator randomGenerator) {
        long milli = instantSource.millis();
        long randomBits = randomGenerator.nextLong();
        return v7(milli, randomBits);
    }

    // ========================================================================
    // Version 8 — custom/experimental
    // ========================================================================

    /// Creates a version-8 (custom) UUID from the given raw 128-bit value.
    ///
    /// Version 8 is reserved for experimental or vendor-specific UUIDs
    /// (RFC 9562 § 5.8). The version and variant bits are stamped onto the
    /// provided values; all other bits are preserved and their interpretation
    /// is application-defined.
    ///
    /// @param mostSigBits  the most significant 64 bits (before version stamping)
    /// @param leastSigBits the least significant 64 bits (before variant stamping)
    /// @return a version-8 UUID
    @Contract(pure = true)
    public static UUID v8(long mostSigBits, long leastSigBits) {
        return newWithVersion(mostSigBits, leastSigBits, 8);
    }

    // ========================================================================
    // Low-level helper
    // ========================================================================

    /// Stamps the given version and the RFC 9562 variant (`10`) onto a raw
    /// 128-bit value and returns the resulting [UUID].
    ///
    /// The version occupies bits 48–51 of `mostSigBits`. The two
    /// most-significant bits of `leastSigBits` are set to `10` (variant 2).
    /// All other bits are preserved from the input.
    ///
    /// @param mostSigBits  the most significant 64 bits
    /// @param leastSigBits the least significant 64 bits
    /// @param version      the UUID version (0–15)
    /// @return a UUID with the specified version and variant bits set
    @Contract(pure = true)
    public static UUID newWithVersion(long mostSigBits, long leastSigBits, int version) {
        // Clear version bits (48–51) and set the requested version
        mostSigBits = (mostSigBits & 0xFFFF_FFFF_FFFF_0FFFL)
                | ((long) (version & 0xF) << 12);
        // Clear variant bits (62–63 of leastSigBits) and set variant 10
        leastSigBits = (leastSigBits & 0x3FFF_FFFF_FFFF_FFFFL)
                | 0x8000_0000_0000_0000L;
        return new UUID(mostSigBits, leastSigBits);
    }

    // ========================================================================
    // Internal helpers
    // ========================================================================

    /// Gregorian epoch offset: the number of 100-nanosecond intervals between
    /// 1582-10-15T00:00:00Z and 1970-01-01T00:00:00Z.
    private static final long GREGORIAN_OFFSET = 0x01B2_1DD2_1381_4000L;

    /// A mask for reading an `int`-sized limb as an unsigned 32-bit value.
    private static final long UINT_MASK = 0xFFFF_FFFFL;

    /// A reusable lowercase hexadecimal formatter.
    private static final HexFormat HEX_FORMAT = HexFormat.of();

    /// The Base62 character set: `0-9A-Za-z`.
    private static final char[] BASE62_CHARS =
            "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".toCharArray();

    /// Holder for the default [SecureRandom] instance, initialized lazily.
    private static final class RandomGeneratorHolder {
        /// The shared [SecureRandom] instance.
        static final SecureRandom INSTANCE = new SecureRandom();
    }

    /// Serializable [Comparator] for UUIDs using unsigned lexicographic ordering.
    private static final class UUIDComparator implements Comparator<UUID>, Serializable {

        /// The singleton instance.
        static final UUIDComparator INSTANCE = new UUIDComparator();

        /// Serial version UID for serialization compatibility.
        @Serial
        private static final long serialVersionUID = 1L;

        @Override
        public int compare(UUID o1, UUID o2) {
            return UUIDs.compare(o1, o2);
        }

        /// Returns the singleton on deserialization.
        @Serial
        private Object readResolve() {
            return INSTANCE;
        }

        @Override
        public String toString() {
            return "UUIDs.comparator()";
        }
    }

    /// Parses a standard hyphenated UUID starting at the given offset within
    /// the string. The 36 characters at `offset` must follow the pattern
    /// `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`.
    private static UUID parseStandard(String value, int offset) {
        if (value.charAt(offset + 8) != '-' || value.charAt(offset + 13) != '-'
                || value.charAt(offset + 18) != '-' || value.charAt(offset + 23) != '-') {
            throw new IllegalArgumentException("Invalid UUID string: " + value);
        }
        long msb = parseHex(value, offset, offset + 8);
        msb = (msb << 16) | parseHex(value, offset + 9, offset + 13);
        msb = (msb << 16) | parseHex(value, offset + 14, offset + 18);
        long lsb = parseHex(value, offset + 19, offset + 23);
        lsb = (lsb << 48) | parseHex(value, offset + 24, offset + 36);
        return new UUID(msb, lsb);
    }

    /// Parses a compact 32-character hex UUID string (no hyphens).
    private static UUID parseCompact(String value) {
        long msb = parseHex(value, 0, 16);
        long lsb = parseHex(value, 16, 32);
        return new UUID(msb, lsb);
    }

    /// Parses a 22-character Base62 string into a UUID.
    private static UUID parseBase62(String value) {
        long word0 = 0L;
        long word1 = 0L;
        long word2 = 0L;
        long word3 = 0L;
        for (int i = 0; i < 22; i++) {
            int digit = base62Digit(value.charAt(i));
            if (digit < 0) {
                throw new IllegalArgumentException("Invalid UUID string: " + value);
            }

            // Multiply the unsigned 128-bit accumulator by 62 and add the digit.
            long product = word3 * 62L + digit;
            word3 = product & UINT_MASK;
            long carry = product >>> 32;

            product = word2 * 62L + carry;
            word2 = product & UINT_MASK;
            carry = product >>> 32;

            product = word1 * 62L + carry;
            word1 = product & UINT_MASK;
            carry = product >>> 32;

            product = word0 * 62L + carry;
            word0 = product & UINT_MASK;
            carry = product >>> 32;
            if (carry != 0L) {
                throw new IllegalArgumentException("Invalid UUID string: " + value);
            }
        }
        long mostSigBits = (word0 << 32) | word1;
        long leastSigBits = (word2 << 32) | word3;
        return new UUID(mostSigBits, leastSigBits);
    }

    /// Returns the Base62 digit value for a character, or -1 if invalid.
    private static int base62Digit(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'A' && c <= 'Z') return c - 'A' + 10;
        if (c >= 'a' && c <= 'z') return c - 'a' + 36;
        return -1;
    }

    /// Parses a hex substring as an unsigned long value.
    private static long parseHex(String value, int start, int end) {
        long result = 0;
        for (int i = start; i < end; i++) {
            int digit = Character.digit(value.charAt(i), 16);
            if (digit < 0) {
                throw new IllegalArgumentException("Invalid UUID string: " + value);
            }
            result = (result << 4) | digit;
        }
        return result;
    }

    /// Extracts the 60-bit Gregorian timestamp from a version-1 UUID.
    private static long getV1Timestamp(UUID uuid) {
        long msb = uuid.getMostSignificantBits();
        // time_low (bits 0–31) | time_mid (bits 32–47) | time_hi (bits 48–59)
        long timeLow = (msb >>> 32) & 0xFFFFFFFFL;
        long timeMid = (msb >>> 16) & 0xFFFFL;
        long timeHi = msb & 0x0FFFL;
        return (timeHi << 48) | (timeMid << 32) | timeLow;
    }

    /// Extracts the 60-bit Gregorian timestamp from a version-6 UUID.
    private static long getV6Timestamp(UUID uuid) {
        long msb = uuid.getMostSignificantBits();
        // time_high (bits 0–31) | time_mid (bits 32–47) | time_low (bits 48–59)
        long timeHighMid = (msb >>> 16) & 0xFFFF_FFFF_FFFFL;
        long timeLow = msb & 0x0FFFL;
        return (timeHighMid << 12) | timeLow;
    }

    /// Converts a 60-bit Gregorian 100-nanosecond timestamp to an [Instant].
    private static Instant instantFromGregorianTimestamp(long timestamp) {
        // Convert from Gregorian epoch (1582-10-15) to Unix epoch (1970-01-01)
        long unixNanos100 = timestamp - GREGORIAN_OFFSET;
        long seconds = Math.floorDiv(unixNanos100, 10_000_000L);
        long nanoAdjustment = Math.floorMod(unixNanos100, 10_000_000L) * 100L;
        return Instant.ofEpochSecond(seconds, nanoAdjustment);
    }

    /// Computes a name-based UUID (version 3 or 5) from a byte-array name.
    private static UUID nameBasedUUID(byte[] name, @Nullable UUID namespace, String algorithm, int version) {
        MessageDigest digest = getDigest(algorithm);
        if (namespace != null) {
            feedUUID(digest, namespace);
        }
        digest.update(name);
        return uuidFromHash(digest.digest(), version);
    }

    /// Computes a name-based UUID (version 3 or 5) from a [ByteBuffer] name.
    private static UUID nameBasedUUID(ByteBuffer name, @Nullable UUID namespace, String algorithm, int version) {
        MessageDigest digest = getDigest(algorithm);
        if (namespace != null) {
            feedUUID(digest, namespace);
        }
        digest.update(name);
        return uuidFromHash(digest.digest(), version);
    }

    /// Feeds the 16-byte big-endian representation of a UUID into a digest.
    private static void feedUUID(MessageDigest digest, UUID uuid) {
        long msb = uuid.getMostSignificantBits();
        long lsb = uuid.getLeastSignificantBits();
        byte[] bytes = new byte[16];
        for (int i = 0; i < 8; i++) {
            bytes[i] = (byte) (msb >>> (56 - i * 8));
            bytes[i + 8] = (byte) (lsb >>> (56 - i * 8));
        }
        digest.update(bytes);
    }

    /// Constructs a UUID from the first 16 bytes of a hash digest, applying
    /// the given version and RFC 9562 variant.
    private static UUID uuidFromHash(byte[] hash, int version) {
        long mostSigBits = 0;
        long leastSigBits = 0;
        for (int i = 0; i < 8; i++) {
            mostSigBits = (mostSigBits << 8) | (hash[i] & 0xFFL);
        }
        for (int i = 8; i < 16; i++) {
            leastSigBits = (leastSigBits << 8) | (hash[i] & 0xFFL);
        }
        return newWithVersion(mostSigBits, leastSigBits, version);
    }

    /// Returns a [MessageDigest] for the given algorithm, wrapping the checked
    /// exception in an [InternalError] since MD5 and SHA-1 are always
    /// available in conforming JREs.
    private static MessageDigest getDigest(String algorithm) {
        try {
            return MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new InternalError("Missing algorithm: " + algorithm, e);
        }
    }

    /// Private constructor prevents instantiation.
    private UUIDs() {
    }
}
