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

/// Utility methods for [UUID]: creation, parsing, formatting, and comparison.
/// Implements UUID versions defined by
/// [RFC 9562](https://www.rfc-editor.org/rfc/rfc9562) and the DCE Security
/// version-2 layout.
///
/// Provides constants ([#NIL], [#MAX], four namespace UUIDs), multi-format
/// parsing, compact/URN/OID/Base62 formatting, unsigned comparison, timestamp
/// extraction, and the low-level helper [#newWithVersion(long, long, int)].
///
/// <h2 id="choosing-a-uuid-version">Choosing a UUID version</h2>
///
/// * **Time-ordered** — use [version 7](#uuid-version-7). It embeds a Unix
///   millisecond timestamp and sorts chronologically, making it the preferred
///   choice for database keys and distributed event ordering.
/// * **Deterministic from a name** — use [version 5](#uuid-version-5) (SHA-1).
///   Given the same namespace and name, the UUID is always identical.
/// * **Fully random** — use [version 4](#uuid-version-4).
/// * **Custom layout** — use [version 8](#uuid-version-8) and manage all
///   non-version, non-variant bits yourself.
/// * **Legacy interoperability** — versions [1](#uuid-version-1),
///   [2](#uuid-version-2), [3](#uuid-version-3), and [6](#uuid-version-6)
///   exist for compatibility with older systems. Prefer version 7 over
///   versions 1 and 6 for new designs, and version 5 over version 3.
///
/// <h2 id="uuid-versions">UUID versions</h2>
///
/// <h3 id="uuid-version-7">Version 7 — time-ordered</h3>
///
/// Stores a 48-bit Unix millisecond timestamp in the most significant bits,
/// followed by random bits. UUIDs generated in order are therefore roughly
/// sorted by creation time. This is the preferred version for time-based UUIDs
/// in new applications.
/// See [#v7(long, int, long)], [#v7(Instant, int, long)], [#generateV7()], and
/// [#generateV7(InstantSource, RandomGenerator)].
///
/// <h3 id="uuid-version-4">Version 4 — random</h3>
///
/// All non-version, non-variant bits are random.
/// See [#generateV4()], [#generateV4(RandomGenerator)], [#v4(long, long)].
///
/// <h3 id="uuid-version-5">Version 5 — SHA-1 name-based</h3>
///
/// Deterministic: the same namespace and name always produce the same UUID.
/// Uses SHA-1 truncated to 128 bits.
/// See [#generateV5(UUID, String)], [#v5(byte[])].
///
/// <h3 id="uuid-version-8">Version 8 — custom</h3>
///
/// Application-defined layout. The caller is responsible for all
/// non-version, non-variant bits.
/// See [#v8(long, long)].
///
/// <h3 id="uuid-version-1">Version 1 — time-based (legacy)</h3>
///
/// Uses a 60-bit 100-nanosecond Gregorian timestamp, a 14-bit clock sequence,
/// and a 48-bit node. The timestamp bits are not in sort order, so version-1
/// UUIDs do not sort chronologically. Version 7 is the preferred replacement.
/// See [#v1(long, int, long)], [#v1(Instant, int, long)], [#generateV1()].
///
/// <h3 id="uuid-version-6">Version 6 — reordered time-based (legacy)</h3>
///
/// Same fields as version 1 with the timestamp bits reordered for
/// chronological sorting. Version 7 is simpler and equally sortable, so
/// version 6 is only needed for interoperability with existing version-6 data.
/// See [#v6(long, int, long)], [#v6(Instant, int, long)], [#generateV6()].
///
/// <h3 id="uuid-version-3">Version 3 — MD5 name-based (legacy)</h3>
///
/// Same as version 5 but uses MD5. Provided for interoperability with
/// existing version-3 UUIDs; version 5 is preferred for new usage.
/// See [#generateV3(UUID, String)], [#generateV3(UUID, byte[])],
/// [#generateV3(UUID, ByteBuffer)], [#v3(byte[])].
///
/// <h3 id="uuid-version-2">Version 2 — DCE Security (legacy)</h3>
///
/// Legacy DCE Security UUIDs. Use only for interoperability with systems that
/// require local person, group, or organization identifiers. Version 2 replaces
/// the low 32 timestamp bits with a local identifier and replaces the low
/// 8 clock-sequence bits with a local domain, so timestamps are approximate and
/// only 64 clock-sequence values remain.
/// See [#v2(long, int, long, int, long)], [#v2(Instant, int, long, int, long)],
/// [#generateV2(int, long)].
@NotNullByDefault
public final class UUIDs {

    // ========================================================================
    // Constants
    // ========================================================================

    /// All-zero UUID (`00000000-0000-0000-0000-000000000000`). RFC 9562 § 5.9.
    public static final UUID NIL = new UUID(0L, 0L);

    /// All-one UUID (`ffffffff-ffff-ffff-ffff-ffffffffffff`). RFC 9562 § 5.10.
    public static final UUID MAX = new UUID(-1L, -1L);

    /// DNS namespace UUID (`6ba7b810-9dad-11d1-80b4-00c04fd430c8`). RFC 9562 § 6.6.
    public static final UUID NAMESPACE_DNS = new UUID(0x6ba7b8109dad11d1L, 0x80b400c04fd430c8L);

    /// URL namespace UUID (`6ba7b811-9dad-11d1-80b4-00c04fd430c8`). RFC 9562 § 6.6.
    public static final UUID NAMESPACE_URL = new UUID(0x6ba7b8119dad11d1L, 0x80b400c04fd430c8L);

    /// OID namespace UUID (`6ba7b812-9dad-11d1-80b4-00c04fd430c8`). RFC 9562 § 6.6.
    public static final UUID NAMESPACE_OID = new UUID(0x6ba7b8129dad11d1L, 0x80b400c04fd430c8L);

    /// X.500 DN namespace UUID (`6ba7b814-9dad-11d1-80b4-00c04fd430c8`). RFC 9562 § 6.6.
    public static final UUID NAMESPACE_X500 = new UUID(0x6ba7b8149dad11d1L, 0x80b400c04fd430c8L);

    /// DCE Security local domain for person identifiers, such as POSIX UIDs.
    public static final int DCE_DOMAIN_PERSON = 0;

    /// DCE Security local domain for group identifiers, such as POSIX GIDs.
    public static final int DCE_DOMAIN_GROUP = 1;

    /// DCE Security local domain for organization identifiers.
    public static final int DCE_DOMAIN_ORG = 2;

    // ========================================================================
    // Parsing
    // ========================================================================

    /// Parses a UUID from a string. Supports formats:
    ///
    /// | Format                  | Example                                        |
    /// |-------------------------|------------------------------------------------|
    /// | Standard                | `550e8400-e29b-41d4-a716-446655440000`          |
    /// | Loose                   | `1-1-1-1-1`                                    |
    /// | Compact                 | `550e8400e29b41d4a716446655440000`              |
    /// | Windows registry        | `{550e8400-e29b-41d4-a716-446655440000}`        |
    /// | URN                     | `urn:uuid:550e8400-e29b-41d4-a716-446655440000` |
    /// | Base62                  | `6aGFHbkMKi3UrLaRLGaKzG`                       |
    ///
    /// @param value the string to parse
    /// @return the parsed UUID
    /// @throws IllegalArgumentException if the string is not a valid UUID in any recognized format
    ///                                  or if a Base62 value is outside the UUID range
    @Contract(pure = true)
    public static UUID parse(String value) {
        int length = value.length(); // implicit null check

        if (length == 38 && value.charAt(0) == '{' && value.charAt(37) == '}') {
            // Windows registry format: {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
            return parseStandard(value, 1);
        }

        if (length == 45 && value.regionMatches(true, 0, "urn:uuid:", 0, 9)) {
            // URN format: urn:uuid:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
            return parseStandard(value, 9);
        }

        if (length <= 36) {
            int dash1 = -1;
            int dash2 = -1;
            int dash3 = -1;
            int dash4 = -1;
            int dashCount = 0;
            boolean allHexDigits = true;
            boolean allJavaHexChars = true;
            boolean allBase62Digits = true;
            for (int i = 0; i < length; i++) {
                char ch = value.charAt(i);
                if (ch == '-') {
                    dashCount++;
                    allBase62Digits = false;
                    if (dashCount == 1) {
                        dash1 = i;
                    } else if (dashCount == 2) {
                        dash2 = i;
                    } else if (dashCount == 3) {
                        dash3 = i;
                    } else if (dashCount == 4) {
                        dash4 = i;
                    }
                } else if (ch == '+') {
                    allHexDigits = false;
                    allBase62Digits = false;
                } else {
                    int hexDigit = hexDigit(ch);
                    if (hexDigit < 0) {
                        allHexDigits = false;
                        allJavaHexChars = false;
                    }
                    if (base62Digit(ch) < 0) {
                        allBase62Digits = false;
                    }
                }
            }

            if (dashCount > 0) {
                if (length == 36 && dash1 == 8 && dash2 == 13 && dash3 == 18 && dash4 == 23
                        && dashCount == 4 && allHexDigits) {
                    long msb = parseHexUnchecked(value, 0, 8);
                    msb = (msb << 16) | parseHexUnchecked(value, 9, 13);
                    msb = (msb << 16) | parseHexUnchecked(value, 14, 18);
                    long lsb = parseHexUnchecked(value, 19, 23);
                    lsb = (lsb << 48) | parseHexUnchecked(value, 24, 36);
                    return new UUID(msb, lsb);
                }
                if (!allJavaHexChars) {
                    throw new IllegalArgumentException("Invalid UUID string: " + value);
                }
                return parseLenientStandard(value, dash1, dash2, dash3, dash4, dashCount);
            }

            if (length == 32 && allHexDigits) {
                long msb = parseHexUnchecked(value, 0, 16);
                long lsb = parseHexUnchecked(value, 16, 32);
                return new UUID(msb, lsb);
            }

            if (length == 22 && allBase62Digits) {
                return parseBase62(value);
            }
        }

        throw new IllegalArgumentException("Invalid UUID string: " + value);
    }

    // ========================================================================
    // Timestamp extraction
    // ========================================================================

    /// Extracts the embedded timestamp from a version-1, -2, -6, or -7 UUID.
    ///
    /// For version-2 UUIDs, the low 32 timestamp bits are not available because
    /// they are replaced by the local identifier, so this method returns the
    /// lower-bound timestamp with those bits set to zero.
    ///
    /// @param uuid the UUID to extract the timestamp from
    /// @return the timestamp as an [Instant]
    /// @throws IllegalArgumentException if the UUID version does not carry a timestamp
    @Contract(pure = true)
    public static Instant getInstant(UUID uuid) {
        int version = uuid.version();
        return switch (version) {
            case 1 -> instantFromGregorianTimestamp(getV1Timestamp(uuid));
            case 2 -> instantFromGregorianTimestamp(getV2Timestamp(uuid));
            case 6 -> instantFromGregorianTimestamp(getV6Timestamp(uuid));
            case 7 -> Instant.ofEpochMilli(uuid.getMostSignificantBits() >>> 16);
            default -> throw new IllegalArgumentException("UUID version " + version + " does not contain a timestamp");
        };
    }

    // ========================================================================
    // Formatting
    // ========================================================================

    /// Formats the UUID as a 32-character lowercase hex string without hyphens.
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

    /// Formats the UUID as a URN string per RFC 9562 § 3.
    ///
    /// Example: `urn:uuid:550e8400-e29b-41d4-a716-446655440000`
    ///
    /// @param uuid the UUID to format
    /// @return the URN string
    @Contract(pure = true)
    public static String toURNString(UUID uuid) {
        return "urn:uuid:" + uuid;
    }

    /// Formats the UUID as a 22-character Base62 string (digit set `0-9A-Za-z`).
    ///
    /// The 128-bit value is treated as unsigned, encoded in Base62, and
    /// left-padded with `0` to exactly 22 characters.
    ///
    /// Example: the nil UUID encodes as `0000000000000000000000`.
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
        byte[] buf = new byte[22];
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

    /// Formats the UUID as an OID under the joint ISO/ITU-T UUID arc `2.25`.
    ///
    /// The 128-bit value is treated as unsigned and appended to `2.25.`.
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

    /// Compares two UUIDs as unsigned 128-bit integers.
    ///
    /// Compares the most significant 64 bits first, then the least
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

    /// Compares two UUIDs from raw 64-bit halves as unsigned 128-bit integers.
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

    /// A serializable [Comparator] using unsigned 128-bit ordering.
    ///
    /// Singleton, safe for concurrent use, consistent with [#compare(UUID, UUID)].
    ///
    /// @return the UUID comparator
    @Contract(pure = true)
    public static Comparator<UUID> comparator() {
        return UUIDComparator.INSTANCE;
    }

    // ========================================================================
    // Version 1 — time-based
    // ========================================================================

    /// Creates a version-1 UUID from an [Instant], clock sequence, and node.
    ///
    /// @param instant       the timestamp
    /// @param clockSequence the 14-bit clock sequence; only the low 14 bits are used
    /// @param node          the 48-bit node value; only the low 48 bits are used
    /// @return a version-1 UUID
    @Contract(pure = true)
    public static UUID v1(Instant instant, int clockSequence, long node) {
        return v1(gregorianTimestamp(instant), clockSequence, node);
    }

    /// Creates a version-1 UUID from a 60-bit Gregorian 100-nanosecond timestamp,
    /// clock sequence, and node.
    ///
    /// @param gregorianTimestamp the timestamp since 1582-10-15T00:00:00Z; only the low 60 bits are used
    /// @param clockSequence      the 14-bit clock sequence; only the low 14 bits are used
    /// @param node               the 48-bit node value; only the low 48 bits are used
    /// @return a version-1 UUID
    @Contract(pure = true)
    public static UUID v1(long gregorianTimestamp, int clockSequence, long node) {
        long timestamp = gregorianTimestamp & GREGORIAN_TIMESTAMP_MASK;
        long mostSigBits = ((timestamp & UINT_MASK) << 32)
                | (((timestamp >>> 32) & 0xFFFFL) << 16)
                | ((timestamp >>> 48) & 0x0FFFL);
        long leastSigBits = (((long) clockSequence & CLOCK_SEQUENCE_MASK) << 48)
                | (node & NODE_MASK);
        return newWithVersion(mostSigBits, leastSigBits, 1);
    }

    /// Generates a version-1 UUID from the system clock and default [SecureRandom].
    ///
    /// @return a version-1 UUID
    public static UUID generateV1() {
        return generateV1(InstantSource.system(), RandomGeneratorHolder.INSTANCE);
    }

    /// Generates a version-1 UUID from the given time source and random generator.
    ///
    /// The clock sequence and node are drawn from `randomGenerator`. The node
    /// has its multicast bit set to indicate a non-IEEE random node.
    ///
    /// @param instantSource   the source of the current time
    /// @param randomGenerator the source of randomness
    /// @return a version-1 UUID
    public static UUID generateV1(InstantSource instantSource, RandomGenerator randomGenerator) {
        return v1(instantSource.instant(), randomClockSequence(randomGenerator), randomNode(randomGenerator));
    }

    // ========================================================================
    // Version 2 — DCE Security
    // ========================================================================

    /// Creates a version-2 UUID from an [Instant], DCE local domain,
    /// local identifier, clock sequence, and node.
    ///
    /// The instant is converted to a Gregorian 100-nanosecond timestamp before
    /// delegating to [#v2(long, int, long, int, long)].
    ///
    /// @param instant         the timestamp instant
    /// @param localDomain     the 8-bit DCE local domain; only the low 8 bits are encoded
    /// @param localIdentifier the 32-bit local identifier; only the low 32 bits are encoded
    /// @param clockSequence   the 6-bit clock sequence; only the low 6 bits are encoded
    /// @param node            the 48-bit node value; only the low 48 bits are encoded
    /// @return a version-2 UUID
    @Contract(pure = true)
    public static UUID v2(Instant instant, int localDomain, long localIdentifier, int clockSequence, long node) {
        return v2(gregorianTimestamp(instant), localDomain, localIdentifier, clockSequence, node);
    }

    /// Creates a version-2 UUID from a Gregorian 100-nanosecond timestamp,
    /// DCE local domain, local identifier, clock sequence, and node.
    ///
    /// The low 32 timestamp bits are replaced by `localIdentifier`, and the
    /// low 8 clock-sequence bits are replaced by `localDomain`.
    ///
    /// @param gregorianTimestamp the timestamp; only bits 32..59 are encoded
    /// @param localDomain        the 8-bit DCE local domain; only the low 8 bits are encoded
    /// @param localIdentifier    the 32-bit local identifier; only the low 32 bits are encoded
    /// @param clockSequence      the 6-bit clock sequence; only the low 6 bits are encoded
    /// @param node               the 48-bit node value; only the low 48 bits are encoded
    /// @return a version-2 UUID
    @Contract(pure = true)
    public static UUID v2(long gregorianTimestamp, int localDomain, long localIdentifier,
                          int clockSequence, long node) {
        long timestamp = gregorianTimestamp & GREGORIAN_TIMESTAMP_MASK;
        long mostSigBits = ((localIdentifier & UINT_MASK) << 32)
                | (((timestamp >>> 32) & 0xFFFFL) << 16)
                | ((timestamp >>> 48) & 0x0FFFL);
        long leastSigBits = ((((long) clockSequence & DCE_CLOCK_SEQUENCE_MASK) << 8)
                | ((long) localDomain & DCE_LOCAL_DOMAIN_MASK)) << 48
                | (node & NODE_MASK);
        return newWithVersion(mostSigBits, leastSigBits, 2);
    }

    /// Generates a version-2 UUID using the system clock and the default
    /// [SecureRandom].
    ///
    /// @param localDomain     the DCE local domain
    /// @param localIdentifier the local identifier for that domain
    /// @return a freshly generated version-2 UUID
    public static UUID generateV2(int localDomain, long localIdentifier) {
        return generateV2(localDomain, localIdentifier, InstantSource.system(), RandomGeneratorHolder.INSTANCE);
    }

    /// Generates a version-2 UUID using the given time source and random
    /// generator.
    ///
    /// The clock sequence and node are drawn from `randomGenerator`. The node
    /// has its multicast bit set to indicate a non-IEEE random node.
    ///
    /// @param localDomain     the DCE local domain
    /// @param localIdentifier the local identifier for that domain
    /// @param instantSource   the source of the current time
    /// @param randomGenerator the source of randomness
    /// @return a freshly generated version-2 UUID
    public static UUID generateV2(int localDomain, long localIdentifier,
                                  InstantSource instantSource, RandomGenerator randomGenerator) {
        return v2(instantSource.instant(), localDomain, localIdentifier,
                randomDceClockSequence(randomGenerator), randomNode(randomGenerator));
    }

    // ========================================================================
    // Version 3 — MD5 name-based
    // ========================================================================

    /// Creates a version-3 UUID from a 16-byte MD5 digest.
    ///
    /// @param md5Digest the 16-byte MD5 digest
    /// @return a version-3 UUID
    /// @throws IllegalArgumentException if `md5Digest` is not exactly 16 bytes long
    @Contract(pure = true)
    public static UUID v3(byte[] md5Digest) {
        if (md5Digest.length != 16) {
            throw new IllegalArgumentException("MD5 digest must be 16 bytes");
        }
        return uuidFromHash(md5Digest, 3);
    }

    /// Generates a version-3 UUID from a string name, encoded as UTF-8.
    ///
    /// @param namespace the namespace UUID prepended to the hash input, or `null` for no namespace
    /// @param name      the name
    /// @return a version-3 UUID
    @Contract(pure = true)
    public static UUID generateV3(@Nullable UUID namespace, String name) {
        return generateV3(namespace, name.getBytes(StandardCharsets.UTF_8));
    }

    /// Generates a version-3 UUID from a byte array name.
    ///
    /// @param namespace the namespace UUID prepended to the hash input, or `null` for no namespace
    /// @param name      the name bytes
    /// @return a version-3 UUID
    @Contract(pure = true)
    public static UUID generateV3(@Nullable UUID namespace, byte[] name) {
        return nameBasedUUID(name, namespace, "MD5", 3);
    }

    /// Generates a version-3 UUID from the remaining bytes of a [ByteBuffer].
    ///
    /// @param namespace the namespace UUID prepended to the hash input, or `null` for no namespace
    /// @param name      the buffer; its remaining bytes are consumed
    /// @return a version-3 UUID
    @Contract(mutates = "param2")
    public static UUID generateV3(@Nullable UUID namespace, ByteBuffer name) {
        return nameBasedUUID(name, namespace, "MD5", 3);
    }

    // ========================================================================
    // Version 4 — random
    // ========================================================================

    /// Creates a version-4 UUID from raw 128-bit data.
    ///
    /// @param mostSigBits  the most significant 64 bits (version bits are overwritten)
    /// @param leastSigBits the least significant 64 bits (variant bits are overwritten)
    /// @return a version-4 UUID
    @Contract(pure = true)
    public static UUID v4(long mostSigBits, long leastSigBits) {
        return newWithVersion(mostSigBits, leastSigBits, 4);
    }

    /// Generates a version-4 UUID using the default [SecureRandom].
    ///
    /// @return a freshly generated version-4 UUID
    public static UUID generateV4() {
        return generateV4(RandomGeneratorHolder.INSTANCE);
    }

    /// Generates a version-4 UUID using the given random generator.
    ///
    /// @param randomGenerator the source of randomness
    /// @return a freshly generated version-4 UUID
    public static UUID generateV4(RandomGenerator randomGenerator) {
        return v4(randomGenerator.nextLong(), randomGenerator.nextLong());
    }

    // ========================================================================
    // Version 5 — SHA-1 name-based
    // ========================================================================

    /// Creates a version-5 UUID from a 20-byte SHA-1 digest.
    ///
    /// @param sha1Digest the 20-byte SHA-1 digest
    /// @return a version-5 UUID
    /// @throws IllegalArgumentException if `sha1Digest` is not exactly 20 bytes long
    @Contract(pure = true)
    public static UUID v5(byte[] sha1Digest) {
        if (sha1Digest.length != 20) {
            throw new IllegalArgumentException("SHA-1 digest must be 20 bytes");
        }
        return uuidFromHash(sha1Digest, 5);
    }

    /// Generates a version-5 UUID from a string name.
    ///
    /// The name is encoded as UTF-8 before hashing.
    ///
    /// @param namespace the optional namespace UUID prepended to the hash input
    /// @param name      the name to hash
    /// @return a version-5 UUID
    @Contract(pure = true)
    public static UUID generateV5(@Nullable UUID namespace, String name) {
        return generateV5(namespace, name.getBytes(StandardCharsets.UTF_8));
    }

    /// Generates a version-5 UUID from a byte array name.
    ///
    /// @param namespace the namespace UUID prepended to the hash input, or `null` for no namespace
    /// @param name      the name bytes
    /// @return a version-5 UUID
    @Contract(pure = true)
    public static UUID generateV5(@Nullable UUID namespace, byte[] name) {
        return nameBasedUUID(name, namespace, "SHA-1", 5);
    }

    /// Generates a version-5 UUID from the remaining bytes of a [ByteBuffer].
    ///
    /// @param namespace the namespace UUID prepended to the hash input, or `null` for no namespace
    /// @param name      the buffer; its remaining bytes are consumed
    /// @return a version-5 UUID
    @Contract(mutates = "param2")
    public static UUID generateV5(@Nullable UUID namespace, ByteBuffer name) {
        return nameBasedUUID(name, namespace, "SHA-1", 5);
    }

    // ========================================================================
    // Version 6 — reordered time-based
    // ========================================================================

    /// Creates a version-6 UUID from an [Instant], clock sequence, and node.
    ///
    /// @param instant       the timestamp
    /// @param clockSequence the 14-bit clock sequence; only the low 14 bits are used
    /// @param node          the 48-bit node value; only the low 48 bits are used
    /// @return a version-6 UUID
    @Contract(pure = true)
    public static UUID v6(Instant instant, int clockSequence, long node) {
        return v6(gregorianTimestamp(instant), clockSequence, node);
    }

    /// Creates a version-6 UUID from a 60-bit Gregorian 100-nanosecond timestamp,
    /// clock sequence, and node.
    ///
    /// @param gregorianTimestamp the timestamp since 1582-10-15T00:00:00Z; only the low 60 bits are used
    /// @param clockSequence      the 14-bit clock sequence; only the low 14 bits are used
    /// @param node               the 48-bit node value; only the low 48 bits are used
    /// @return a version-6 UUID
    @Contract(pure = true)
    public static UUID v6(long gregorianTimestamp, int clockSequence, long node) {
        long timestamp = gregorianTimestamp & GREGORIAN_TIMESTAMP_MASK;
        long mostSigBits = ((timestamp >>> 12) << 16) | (timestamp & 0x0FFFL);
        long leastSigBits = (((long) clockSequence & CLOCK_SEQUENCE_MASK) << 48)
                | (node & NODE_MASK);
        return newWithVersion(mostSigBits, leastSigBits, 6);
    }

    /// Generates a version-6 UUID from the system clock and default [SecureRandom].
    ///
    /// @return a version-6 UUID
    public static UUID generateV6() {
        return generateV6(InstantSource.system(), RandomGeneratorHolder.INSTANCE);
    }

    /// Generates a version-6 UUID from the given time source and random generator.
    ///
    /// The clock sequence and node are drawn from `randomGenerator`. The node
    /// has its multicast bit set to indicate a non-IEEE random node.
    ///
    /// @param instantSource   the source of the current time
    /// @param randomGenerator the source of randomness
    /// @return a version-6 UUID
    public static UUID generateV6(InstantSource instantSource, RandomGenerator randomGenerator) {
        return v6(instantSource.instant(), randomClockSequence(randomGenerator), randomNode(randomGenerator));
    }

    // ========================================================================
    // Version 7 — time-ordered
    // ========================================================================

    /// Creates a version-7 UUID from an [Instant], a 12-bit `rand_a` value,
    /// and a 62-bit `rand_b` value.
    ///
    /// @param instant the timestamp
    /// @param randA   the `rand_a` value; only the low 12 bits are encoded
    /// @param randB   the `rand_b` value; only the low 62 bits are encoded
    /// @return a version-7 UUID
    @Contract(pure = true)
    public static UUID v7(Instant instant, int randA, long randB) {
        return v7(instant.toEpochMilli(), randA, randB);
    }

    /// Creates a version-7 UUID from a Unix epoch millisecond timestamp,
    /// a 12-bit `rand_a` value, and a 62-bit `rand_b` value.
    ///
    /// @param epochMilli the Unix epoch millisecond timestamp
    /// @param randA      the `rand_a` value; only the low 12 bits are encoded
    /// @param randB      the `rand_b` value; only the low 62 bits are encoded
    /// @return a version-7 UUID
    @Contract(pure = true)
    public static UUID v7(long epochMilli, int randA, long randB) {
        long mostSigBits = ((epochMilli & 0xFFFF_FFFF_FFFFL) << 16)
                | ((long) randA & V7_RANDOM_A_MASK);
        long leastSigBits = randB & V7_RANDOM_B_MASK;
        return newWithVersion(mostSigBits, leastSigBits, 7);
    }

    /// Generates a version-7 UUID from the system clock and default [SecureRandom].
    ///
    /// @return a version-7 UUID
    public static UUID generateV7() {
        return generateV7(InstantSource.system(), RandomGeneratorHolder.INSTANCE);
    }

    /// Generates a version-7 UUID from the given time source and random generator.
    ///
    /// @param instantSource   the source of the current time
    /// @param randomGenerator the source of randomness
    /// @return a version-7 UUID
    public static UUID generateV7(InstantSource instantSource, RandomGenerator randomGenerator) {
        long milli = instantSource.millis();
        long randomBits = randomGenerator.nextLong();
        return v7(milli, (int) (randomBits >>> 52), randomBits);
    }

    // ========================================================================
    // Version 8 — custom/experimental
    // ========================================================================

    /// Creates a version-8 (custom) UUID from raw 128-bit data.
    ///
    /// @param mostSigBits  the most significant 64 bits (version bits are overwritten)
    /// @param leastSigBits the least significant 64 bits (variant bits are overwritten)
    /// @return a version-8 UUID
    @Contract(pure = true)
    public static UUID v8(long mostSigBits, long leastSigBits) {
        return newWithVersion(mostSigBits, leastSigBits, 8);
    }

    // ========================================================================
    // Low-level helper
    // ========================================================================

    /// Sets the version field (bits 48–51 of `mostSigBits`) and the RFC 9562
    /// variant bits (top two bits of `leastSigBits` to `10`). All other bits
    /// are preserved.
    ///
    /// @param mostSigBits  the most significant 64 bits
    /// @param leastSigBits the least significant 64 bits
    /// @param version      the UUID version (0–15)
    /// @return a UUID with the specified version and variant
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

    /// A mask for the 60-bit Gregorian timestamp field used by version 1, 2,
    /// and 6 UUIDs.
    private static final long GREGORIAN_TIMESTAMP_MASK = 0x0FFF_FFFF_FFFF_FFFFL;

    /// A mask for the 14-bit clock sequence field used by version 1 and
    /// version 6 UUIDs.
    private static final int CLOCK_SEQUENCE_MASK = 0x3FFF;

    /// A mask for the 6-bit clock sequence field used by version 2 UUIDs.
    private static final int DCE_CLOCK_SEQUENCE_MASK = 0x3F;

    /// A mask for the 8-bit local domain field used by version 2 UUIDs.
    private static final int DCE_LOCAL_DOMAIN_MASK = 0xFF;

    /// A mask for the 48-bit node field used by version 1, 2, and 6 UUIDs.
    private static final long NODE_MASK = 0xFFFF_FFFF_FFFFL;

    /// A mask for the 12-bit `rand_a` field used by version 7 UUIDs.
    private static final int V7_RANDOM_A_MASK = 0x0FFF;

    /// A mask for the 62-bit `rand_b` field used by version 7 UUIDs.
    private static final long V7_RANDOM_B_MASK = 0x3FFF_FFFF_FFFF_FFFFL;

    /// The multicast bit in the first octet of a randomly generated node ID.
    private static final long RANDOM_NODE_MULTICAST_MASK = 1L << 40;

    /// A mask for reading an `int`-sized limb as an unsigned 32-bit value.
    private static final long UINT_MASK = 0xFFFF_FFFFL;

    /// A reusable lowercase hexadecimal formatter.
    private static final HexFormat HEX_FORMAT = HexFormat.of();

    /// The Base62 character set: `0-9A-Za-z`.
    private static final byte[] BASE62_CHARS =
            "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".getBytes(StandardCharsets.ISO_8859_1);

    /// Lazy holder for the default [SecureRandom] instance.
    private static final class RandomGeneratorHolder {
        static final SecureRandom INSTANCE = new SecureRandom();
    }

    /// Serializable [Comparator] with unsigned 128-bit ordering.
    private static final class UUIDComparator implements Comparator<UUID>, Serializable {

        /// The singleton instance.
        static final UUIDComparator INSTANCE = new UUIDComparator();

        @Serial
        private static final long serialVersionUID = 1L;

        @Override
        public int compare(UUID o1, UUID o2) {
            return UUIDs.compare(o1, o2);
        }

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
        if (!hasStandardHyphenPositions(value, offset)) {
            throw new IllegalArgumentException("Invalid UUID string: " + value);
        }
        return parseStandardFields(value, offset);
    }

    /// Parses the hexadecimal fields of a standard hyphenated UUID whose
    /// hyphen positions have already been validated.
    private static UUID parseStandardFields(String value, int offset) {
        long msb = parseHex(value, offset, offset + 8);
        msb = (msb << 16) | parseHex(value, offset + 9, offset + 13);
        msb = (msb << 16) | parseHex(value, offset + 14, offset + 18);
        long lsb = parseHex(value, offset + 19, offset + 23);
        lsb = (lsb << 48) | parseHex(value, offset + 24, offset + 36);
        return new UUID(msb, lsb);
    }

    /// Returns whether the 36 characters at `offset` use standard UUID
    /// hyphen positions.
    private static boolean hasStandardHyphenPositions(String value, int offset) {
        return value.charAt(offset + 8) == '-' && value.charAt(offset + 13) == '-'
                && value.charAt(offset + 18) == '-' && value.charAt(offset + 23) == '-';
    }

    /// Parses a hyphenated UUID using [UUID#fromString(String)]-compatible
    /// lenient parsing with precomputed hyphen positions.
    private static UUID parseLenientStandard(String value, int dash1, int dash2, int dash3, int dash4, int dashCount) {
        int length = value.length();
        if (length > 36) {
            throw new IllegalArgumentException("Invalid UUID string: " + value);
        }

        if (dashCount != 4) {
            throw new IllegalArgumentException("Invalid UUID string: " + value);
        }

        long msb = Long.parseLong(value, 0, dash1, 16) & UINT_MASK;
        msb = (msb << 16) | (Long.parseLong(value, dash1 + 1, dash2, 16) & 0xFFFFL);
        msb = (msb << 16) | (Long.parseLong(value, dash2 + 1, dash3, 16) & 0xFFFFL);
        long lsb = Long.parseLong(value, dash3 + 1, dash4, 16) & 0xFFFFL;
        lsb = (lsb << 48) | (Long.parseLong(value, dash4 + 1, length, 16) & 0xFFFF_FFFF_FFFFL);
        return new UUID(msb, lsb);
    }

    /// Parses a prevalidated 22-character Base62 string into a UUID.
    private static UUID parseBase62(String value) {
        long word0 = 0L;
        long word1 = 0L;
        long word2 = 0L;
        long word3 = 0L;
        for (int i = 0; i < 22; i++) {
            int digit = base62Digit(value.charAt(i));

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

    /// Returns the hexadecimal digit value for an ASCII character, or -1 if
    /// invalid.
    private static int hexDigit(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return -1;
    }

    /// Parses a hex substring as an unsigned long value.
    private static long parseHex(String value, int start, int end) {
        long result = 0;
        for (int i = start; i < end; i++) {
            int digit = hexDigit(value.charAt(i));
            if (digit < 0) {
                throw new IllegalArgumentException("Invalid UUID string: " + value);
            }
            result = (result << 4) | digit;
        }
        return result;
    }

    /// Parses a prevalidated ASCII hex substring as an unsigned long value.
    private static long parseHexUnchecked(String value, int start, int end) {
        long result = 0;
        for (int i = start; i < end; i++) {
            result = (result << 4) | hexDigit(value.charAt(i));
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

    /// Extracts the available high 28 bits of the Gregorian timestamp from a
    /// version-2 UUID and returns the low 32 bits as zero.
    private static long getV2Timestamp(UUID uuid) {
        long msb = uuid.getMostSignificantBits();
        long timeMid = (msb >>> 16) & 0xFFFFL;
        long timeHi = msb & 0x0FFFL;
        return (timeHi << 48) | (timeMid << 32);
    }

    /// Extracts the 60-bit Gregorian timestamp from a version-6 UUID.
    private static long getV6Timestamp(UUID uuid) {
        long msb = uuid.getMostSignificantBits();
        // time_high (bits 0–31) | time_mid (bits 32–47) | time_low (bits 48–59)
        long timeHighMid = (msb >>> 16) & 0xFFFF_FFFF_FFFFL;
        long timeLow = msb & 0x0FFFL;
        return (timeHighMid << 12) | timeLow;
    }

    /// Converts an [Instant] to a Gregorian 100-nanosecond timestamp since
    /// 1582-10-15T00:00:00Z.
    private static long gregorianTimestamp(Instant instant) {
        long seconds = Math.multiplyExact(instant.getEpochSecond(), 10_000_000L);
        long nanos100 = instant.getNano() / 100L;
        return Math.addExact(Math.addExact(seconds, nanos100), GREGORIAN_OFFSET);
    }

    /// Converts a 60-bit Gregorian 100-nanosecond timestamp to an [Instant].
    private static Instant instantFromGregorianTimestamp(long timestamp) {
        // Convert from Gregorian epoch (1582-10-15) to Unix epoch (1970-01-01)
        long unixNanos100 = timestamp - GREGORIAN_OFFSET;
        long seconds = Math.floorDiv(unixNanos100, 10_000_000L);
        long nanoAdjustment = Math.floorMod(unixNanos100, 10_000_000L) * 100L;
        return Instant.ofEpochSecond(seconds, nanoAdjustment);
    }

    /// Generates a random 14-bit clock sequence.
    private static int randomClockSequence(RandomGenerator randomGenerator) {
        return randomGenerator.nextInt() & CLOCK_SEQUENCE_MASK;
    }

    /// Generates a random 6-bit DCE Security clock sequence.
    private static int randomDceClockSequence(RandomGenerator randomGenerator) {
        return randomGenerator.nextInt() & DCE_CLOCK_SEQUENCE_MASK;
    }

    /// Generates a random 48-bit node ID with the multicast bit set.
    private static long randomNode(RandomGenerator randomGenerator) {
        return (randomGenerator.nextLong() & NODE_MASK) | RANDOM_NODE_MULTICAST_MASK;
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

    /// Feeds a UUID's 16 big-endian bytes into a digest.
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

    /// Constructs a UUID from the first 16 bytes of a hash digest.
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

    /// Returns a [MessageDigest] for the algorithm. Wraps
    /// [NoSuchAlgorithmException] in [InternalError] — MD5 and SHA-1 are
    /// always present in conforming JREs.
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
