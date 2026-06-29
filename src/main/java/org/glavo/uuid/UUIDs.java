// Copyright (c) 2026 Glavo
// SPDX-License-Identifier: MPL-2.0

package org.glavo.uuid;

import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNullByDefault;
import org.jetbrains.annotations.Nullable;

import java.io.Serial;
import java.io.Serializable;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.InstantSource;
import java.util.Comparator;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import java.util.random.RandomGenerator;

/// Lightweight UUID utilities for generating, parsing, formatting, and
/// comparing [UUID] values.
///
/// This class is the main entry point of uuid-tools. It works directly with
/// JDK [UUID] objects and keeps the API small: constants, versioned
/// generation methods, deterministic field constructors, text and binary
/// conversion, field accessors, and unsigned comparison helpers all live here.
///
/// <h2 id="choosing-a-uuid-version">Choosing a UUID version</h2>
///
/// UUID versions are different layouts, not a release sequence. For most new
/// code, choose by how the value will be used:
///
/// * **Sortable database keys and event IDs**: use [version 7](#uuid-version-7).
///   It embeds a Unix millisecond timestamp and sorts chronologically.
/// * **Opaque random identifiers**: use [version 4](#uuid-version-4).
/// * **Deterministic identifiers from a namespace and name**: use
///   [version 5](#uuid-version-5). The same namespace and name always produce
///   the same UUID.
/// * **Application-defined layouts**: use [version 8](#uuid-version-8) and
///   manage the payload bits yourself.
/// * **Legacy interoperability**: use versions [1](#uuid-version-1),
///   [2](#uuid-version-2), [3](#uuid-version-3), or [6](#uuid-version-6)
///   when an existing system requires those layouts. For new time-based UUIDs,
///   prefer version 7 over versions 1 and 6. For new name-based UUIDs, prefer
///   version 5 over version 3.
///
/// ```java
/// UUID timeOrdered = UUIDs.generateV7();
/// UUID random = UUIDs.generateV4();
/// UUID named = UUIDs.generateV5(UUIDs.NAMESPACE_DNS, "example.com");
/// ```
///
/// <h2 id="text-and-binary-conversion">Text and binary conversion</h2>
///
/// [#parse(String)] accepts unambiguous UUID text forms: standard
/// hyphenated text, compact hexadecimal text, Windows registry text, and URN
/// text. Compact encodings that can be confused with other formats use
/// explicit methods, such as [#parseBase62(String)].
///
/// Binary conversion uses the standard 16-byte big-endian representation:
///
/// ```java
/// byte[] bytes = UUIDs.toBytes(timeOrdered);
/// UUIDs.toBytes(timeOrdered, bytes, 0);
/// UUID decoded = UUIDs.fromBytes(bytes);
/// ```
///
/// <h2 id="comparison-order">Comparison order</h2>
///
/// [#compare(UUID, UUID)] and [#comparator()] compare UUIDs as unsigned
/// 128-bit integers. This matches canonical UUID string order and the order
/// of the standard 16-byte big-endian representation.
///
/// <h2 id="default-random-source">Default random source</h2>
///
/// Default generation methods use a shared lightweight pseudorandom source
/// seeded from [SecureRandom] during first use. It is intended for ordinary
/// UUID generation where throughput and small retained state matter. For
/// security tokens, credentials, keys, or values that require cryptographic
/// random guarantees, pass a [SecureRandom] to the overload that accepts a
/// [RandomGenerator].
///
/// <h2 id="uuid-standards">UUID standards</h2>
///
/// uuid-tools implements UUID versions defined by
/// [RFC 9562](https://www.rfc-editor.org/rfc/rfc9562) and the DCE Security
/// version-2 layout.
///
/// <h2 id="uuid-versions">UUID versions</h2>
///
/// <h3 id="uuid-version-7">Version 7 — time-ordered</h3>
///
/// Stores a 48-bit Unix millisecond timestamp in the most significant bits,
/// followed by the `rand_a` and `rand_b` fields. UUIDs generated in order are
/// therefore roughly sorted by creation time. This is the preferred version
/// for time-based UUIDs in new applications.
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
/// See [#v1(long, int, long)], [#v1(Instant, int, long)], [#generateV1()],
/// and [#convertV1ToV6(UUID)].
///
/// <h3 id="uuid-version-6">Version 6 — reordered time-based (legacy)</h3>
///
/// Same fields as version 1 with the timestamp bits reordered for
/// chronological sorting. Version 7 is simpler and equally sortable, so
/// version 6 is only needed for interoperability with existing version-6 data.
/// See [#v6(long, int, long)], [#v6(Instant, int, long)], [#generateV6()],
/// and [#convertV6ToV1(UUID)].
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

    /// All-zero UUID (`00000000-0000-0000-0000-000000000000`).
    ///
    /// RFC 9562 defines this as the nil UUID. It is useful as a sentinel value
    /// when an all-zero UUID has a defined meaning in a protocol or data model.
    /// See [#isNil(UUID)].
    public static final UUID NIL = new UUID(0L, 0L);

    /// All-one UUID (`ffffffff-ffff-ffff-ffff-ffffffffffff`).
    ///
    /// RFC 9562 defines this as the max UUID. It is useful as an upper-bound
    /// sentinel when UUIDs are treated as unsigned 128-bit values. See
    /// [#isMax(UUID)] and [#compare(UUID, UUID)].
    public static final UUID MAX = new UUID(-1L, -1L);

    /// DNS namespace UUID (`6ba7b810-9dad-11d1-80b4-00c04fd430c8`).
    ///
    /// Use this namespace with [#generateV3(UUID, String)] or
    /// [#generateV5(UUID, String)] when the name is a fully qualified domain
    /// name such as `example.com`.
    public static final UUID NAMESPACE_DNS = new UUID(0x6ba7b8109dad11d1L, 0x80b400c04fd430c8L);

    /// URL namespace UUID (`6ba7b811-9dad-11d1-80b4-00c04fd430c8`).
    ///
    /// Use this namespace with [#generateV3(UUID, String)] or
    /// [#generateV5(UUID, String)] when the name is a URL.
    public static final UUID NAMESPACE_URL = new UUID(0x6ba7b8119dad11d1L, 0x80b400c04fd430c8L);

    /// OID namespace UUID (`6ba7b812-9dad-11d1-80b4-00c04fd430c8`).
    ///
    /// Use this namespace with [#generateV3(UUID, String)] or
    /// [#generateV5(UUID, String)] when the name is an ISO object identifier.
    public static final UUID NAMESPACE_OID = new UUID(0x6ba7b8129dad11d1L, 0x80b400c04fd430c8L);

    /// X.500 DN namespace UUID (`6ba7b814-9dad-11d1-80b4-00c04fd430c8`).
    ///
    /// Use this namespace with [#generateV3(UUID, String)] or
    /// [#generateV5(UUID, String)] when the name is an X.500 distinguished
    /// name.
    public static final UUID NAMESPACE_X500 = new UUID(0x6ba7b8149dad11d1L, 0x80b400c04fd430c8L);

    /// DCE Security local domain for person identifiers, such as POSIX UIDs.
    ///
    /// Pass this value to [#generateV2(int, long)] or
    /// [#v2(long, int, long, int, long)] when creating a version-2 UUID whose
    /// local identifier represents a person.
    public static final int DCE_DOMAIN_PERSON = 0;

    /// DCE Security local domain for group identifiers, such as POSIX GIDs.
    ///
    /// Pass this value to [#generateV2(int, long)] or
    /// [#v2(long, int, long, int, long)] when creating a version-2 UUID whose
    /// local identifier represents a group.
    public static final int DCE_DOMAIN_GROUP = 1;

    /// DCE Security local domain for organization identifiers.
    ///
    /// Pass this value to [#generateV2(int, long)] or
    /// [#v2(long, int, long, int, long)] when creating a version-2 UUID whose
    /// local identifier represents an organization.
    public static final int DCE_DOMAIN_ORG = 2;

    // ========================================================================
    // Parsing
    // ========================================================================

    /// Parses a UUID from a string. Supports unambiguous UUID text formats:
    ///
    /// | Format                  | Example                                        |
    /// |-------------------------|------------------------------------------------|
    /// | Standard                | `550e8400-e29b-41d4-a716-446655440000`          |
    /// | Compact                 | `550e8400e29b41d4a716446655440000`              |
    /// | Windows registry        | `{550e8400-e29b-41d4-a716-446655440000}`        |
    /// | URN                     | `urn:uuid:550e8400-e29b-41d4-a716-446655440000` |
    ///
    /// @param value the string to parse
    /// @return the parsed UUID
    /// @throws IllegalArgumentException if the string is not a valid UUID in any recognized format
    @Contract(pure = true)
    public static UUID parse(String value) {
        int length = value.length(); // implicit null check

        if (length == 36) {
            return parseStandard(value, 0);
        }

        if (length == 32) {
            long msb = parseHex(value, 0, 16);
            long lsb = parseHex(value, 16, 32);
            return new UUID(msb, lsb);
        }

        if (length == 38 && value.charAt(0) == '{' && value.charAt(37) == '}') {
            // Windows registry format: {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
            return parseStandard(value, 1);
        }

        if (length == 45 && value.regionMatches(true, 0, "urn:uuid:", 0, 9)) {
            // URN format: urn:uuid:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
            return parseStandard(value, 9);
        }

        throw new IllegalArgumentException("Invalid UUID string: " + value);
    }

    /// Parses a 22-character Base62 UUID string.
    ///
    /// The 128-bit value is treated as unsigned. The digit set is `0-9A-Za-z`.
    ///
    /// @param value the Base62 UUID string
    /// @return the parsed UUID
    /// @throws IllegalArgumentException if `value` is not a valid 22-character Base62 UUID string
    @Contract(pure = true)
    public static UUID parseBase62(String value) {
        if (value.length() != 22) {
            throw new IllegalArgumentException("Invalid Base62 UUID string: " + value);
        }

        long word0 = 0L;
        long word1 = 0L;
        long word2 = 0L;
        long word3 = 0L;
        for (int i = 0; i < 22; i++) {
            int digit = base62Digit(value.charAt(i));
            if (digit < 0) {
                throw new IllegalArgumentException("Invalid Base62 UUID string: " + value);
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
                throw new IllegalArgumentException("Invalid Base62 UUID string: " + value);
            }
        }
        long mostSigBits = (word0 << 32) | word1;
        long leastSigBits = (word2 << 32) | word3;
        return new UUID(mostSigBits, leastSigBits);
    }

    // ========================================================================
    // Accessors
    // ========================================================================

    /// Returns whether `uuid` is the nil UUID.
    ///
    /// @param uuid the UUID to test
    /// @return `true` if `uuid` equals [#NIL]
    @Contract(pure = true)
    public static boolean isNil(UUID uuid) {
        return uuid.getMostSignificantBits() == 0L && uuid.getLeastSignificantBits() == 0L;
    }

    /// Returns whether `uuid` is the max UUID.
    ///
    /// @param uuid the UUID to test
    /// @return `true` if `uuid` equals [#MAX]
    @Contract(pure = true)
    public static boolean isMax(UUID uuid) {
        return uuid.getMostSignificantBits() == -1L && uuid.getLeastSignificantBits() == -1L;
    }

    /// Returns whether `uuid` has a time-based layout supported by this class.
    ///
    /// This method returns `true` for version 1, 2, 6, and 7 UUIDs. These
    /// versions carry timestamps readable by [#getInstant(UUID)],
    /// [#getGregorianTimestamp(UUID)], and [#getUnixTimestampMillis(UUID)].
    ///
    /// @param uuid the UUID to test
    /// @return `true` if `uuid` is a version 1, 2, 6, or 7 UUID
    @Contract(pure = true)
    public static boolean isTimeBased(UUID uuid) {
        int version = uuid.version();
        return version == 1 || version == 2 || version == 6 || version == 7;
    }

    /// Extracts the embedded timestamp from a version 1, 2, 6, or 7 UUID.
    ///
    /// For version 2 UUIDs, the low 32 timestamp bits are not available because
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
            case 7 -> Instant.ofEpochMilli(getV7UnixTimestampMillis(uuid));
            default -> throw new IllegalArgumentException("UUID version " + version + " does not contain a timestamp");
        };
    }

    /// Extracts the Gregorian 100-nanosecond timestamp from a version 1, 2, 6, or 7 UUID.
    ///
    /// For version 2 UUIDs, the low 32 timestamp bits are not available because
    /// they are replaced by the local identifier, so this method returns the
    /// lower-bound timestamp with those bits set to zero. For version 7 UUIDs,
    /// the encoded Unix millisecond timestamp is converted to Gregorian
    /// 100-nanosecond units with no sub-millisecond precision.
    ///
    /// @param uuid the UUID to extract the timestamp from
    /// @return the Gregorian timestamp
    /// @throws IllegalArgumentException if `uuid` is not a version 1, 2, 6, or 7 UUID
    @Contract(pure = true)
    public static long getGregorianTimestamp(UUID uuid) {
        int version = uuid.version();
        return switch (version) {
            case 1 -> getV1Timestamp(uuid);
            case 2 -> getV2Timestamp(uuid);
            case 6 -> getV6Timestamp(uuid);
            case 7 -> {
                long unixMillis = getV7UnixTimestampMillis(uuid);
                yield GREGORIAN_OFFSET + unixMillis * GREGORIAN_TICKS_PER_MILLI;
            }
            default -> throw new IllegalArgumentException("UUID version " + version
                    + " does not contain a Gregorian timestamp");
        };
    }

    /// Extracts the Unix epoch millisecond timestamp from a version 1, 2, 6, or 7 UUID.
    ///
    /// For version 2 UUIDs, the low 32 Gregorian timestamp bits are not
    /// available because they are replaced by the local identifier, so this
    /// method returns the Unix millisecond value of the lower-bound timestamp.
    ///
    /// @param uuid the UUID to extract the timestamp from
    /// @return the Unix epoch millisecond timestamp
    /// @throws IllegalArgumentException if `uuid` is not a version 1, 2, 6, or 7 UUID
    @Contract(pure = true)
    public static long getUnixTimestampMillis(UUID uuid) {
        int version = uuid.version();
        return switch (version) {
            case 1 -> unixTimestampMillisFromGregorianTimestamp(getV1Timestamp(uuid));
            case 2 -> unixTimestampMillisFromGregorianTimestamp(getV2Timestamp(uuid));
            case 6 -> unixTimestampMillisFromGregorianTimestamp(getV6Timestamp(uuid));
            case 7 -> getV7UnixTimestampMillis(uuid);
            default -> throw new IllegalArgumentException("UUID version " + version
                    + " does not contain a timestamp");
        };
    }

    /// Extracts the clock sequence from a version 1, 2, or 6 UUID.
    ///
    /// Version 1 and version 6 UUIDs carry a 14-bit clock sequence. Version 2
    /// UUIDs carry only a 6-bit clock sequence.
    ///
    /// @param uuid the UUID to extract the clock sequence from
    /// @return the clock sequence
    /// @throws IllegalArgumentException if `uuid` is not a version 1, 2, or 6 UUID
    @Contract(pure = true)
    public static int getClockSequence(UUID uuid) {
        int version = uuid.version();
        return switch (version) {
            case 1, 6 -> (int) (uuid.getLeastSignificantBits() >>> 48) & CLOCK_SEQUENCE_MASK;
            case 2 -> (int) (uuid.getLeastSignificantBits() >>> 56) & DCE_CLOCK_SEQUENCE_MASK;
            default -> throw new IllegalArgumentException("UUID version " + version
                    + " does not contain a clock sequence");
        };
    }

    /// Extracts the node field from a version 1, 2, or 6 UUID.
    ///
    /// @param uuid the UUID to extract the node from
    /// @return the 48-bit node field
    /// @throws IllegalArgumentException if `uuid` is not a version 1, 2, or 6 UUID
    @Contract(pure = true)
    public static long getNode(UUID uuid) {
        int version = uuid.version();
        if (version != 1 && version != 2 && version != 6) {
            throw new IllegalArgumentException("UUID version " + version + " does not contain a node");
        }
        return uuid.getLeastSignificantBits() & NODE_MASK;
    }

    /// Extracts the DCE local domain from a version 2 UUID.
    ///
    /// @param uuid the UUID to extract the local domain from
    /// @return the 8-bit DCE local domain
    /// @throws IllegalArgumentException if `uuid` is not a version 2 UUID
    @Contract(pure = true)
    public static int getDceLocalDomain(UUID uuid) {
        requireVersion(uuid, 2);
        return (int) (uuid.getLeastSignificantBits() >>> 48) & DCE_LOCAL_DOMAIN_MASK;
    }

    /// Extracts the DCE local identifier from a version 2 UUID.
    ///
    /// @param uuid the UUID to extract the local identifier from
    /// @return the 32-bit DCE local identifier as an unsigned `long`
    /// @throws IllegalArgumentException if `uuid` is not a version 2 UUID
    @Contract(pure = true)
    public static long getDceLocalIdentifier(UUID uuid) {
        requireVersion(uuid, 2);
        return uuid.getMostSignificantBits() >>> 32;
    }

    /// Extracts the 12-bit `rand_a` field from a version 7 UUID.
    ///
    /// @param uuid the UUID to extract `rand_a` from
    /// @return the `rand_a` field
    /// @throws IllegalArgumentException if `uuid` is not a version 7 UUID
    @Contract(pure = true)
    public static int getV7RandA(UUID uuid) {
        requireVersion(uuid, 7);
        return (int) (uuid.getMostSignificantBits() & LOW_12_BITS_MASK);
    }

    /// Extracts the 62-bit `rand_b` field from a version 7 UUID.
    ///
    /// @param uuid the UUID to extract `rand_b` from
    /// @return the `rand_b` field
    /// @throws IllegalArgumentException if `uuid` is not a version 7 UUID
    @Contract(pure = true)
    public static long getV7RandB(UUID uuid) {
        requireVersion(uuid, 7);
        return uuid.getLeastSignificantBits() & LEAST_SIG_BITS_PAYLOAD_MASK;
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
        StringBuilder out = new StringBuilder(32);
        appendHex(out, uuid.getMostSignificantBits(), 16);
        appendHex(out, uuid.getLeastSignificantBits(), 16);
        return out.toString();
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
        return new String(buf, StandardCharsets.ISO_8859_1);
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
        BYTE_ARRAY_LONG_VIEW.set(bytes, 1, uuid.getMostSignificantBits());
        BYTE_ARRAY_LONG_VIEW.set(bytes, 9, uuid.getLeastSignificantBits());
        return "2.25." + new BigInteger(bytes);
    }

    // ========================================================================
    // Byte conversion
    // ========================================================================

    /// Returns the 16-byte big-endian representation of a UUID.
    ///
    /// The first eight bytes contain [UUID#getMostSignificantBits()], followed
    /// by eight bytes containing [UUID#getLeastSignificantBits()].
    ///
    /// @param uuid the UUID to convert
    /// @return a newly allocated 16-byte array
    @Contract(pure = true)
    public static byte[] toBytes(UUID uuid) {
        byte[] bytes = new byte[16];
        toBytes(uuid, bytes, 0);
        return bytes;
    }

    /// Writes the 16-byte big-endian representation of a UUID into an
    /// existing byte array.
    ///
    /// @param uuid   the UUID to convert
    /// @param bytes  the destination byte array
    /// @param offset the offset of the first destination byte
    /// @throws IndexOutOfBoundsException if `offset` is negative or if fewer
    ///                                   than 16 bytes are available
    @Contract(mutates = "param2")
    public static void toBytes(UUID uuid, byte[] bytes, int offset) {
        Objects.checkFromIndexSize(offset, 16, bytes.length);
        BYTE_ARRAY_LONG_VIEW.set(bytes, offset, uuid.getMostSignificantBits());
        BYTE_ARRAY_LONG_VIEW.set(bytes, offset + 8, uuid.getLeastSignificantBits());
    }

    /// Creates a UUID from a 16-byte big-endian representation.
    ///
    /// @param bytes the 16-byte UUID representation
    /// @return the parsed UUID
    /// @throws IllegalArgumentException if `bytes` is not exactly 16 bytes long
    @Contract(pure = true)
    public static UUID fromBytes(byte[] bytes) {
        if (bytes.length != 16) {
            throw new IllegalArgumentException("UUID byte array must be 16 bytes");
        }
        return fromBytes(bytes, 0);
    }

    /// Creates a UUID from 16 bytes starting at `offset`.
    ///
    /// @param bytes  the byte array containing the UUID representation
    /// @param offset the offset of the first UUID byte
    /// @return the parsed UUID
    /// @throws IndexOutOfBoundsException if `offset` is negative or if fewer
    ///                                   than 16 bytes are available
    @Contract(pure = true)
    public static UUID fromBytes(byte[] bytes, int offset) {
        Objects.checkFromIndexSize(offset, 16, bytes.length);
        long msb = (long) BYTE_ARRAY_LONG_VIEW.get(bytes, offset);
        long lsb = (long) BYTE_ARRAY_LONG_VIEW.get(bytes, offset + 8);
        return new UUID(msb, lsb);
    }

    // ========================================================================
    // Comparison
    // ========================================================================

    /// Compares two UUIDs as unsigned 128-bit integers.
    ///
    /// Compares the most significant 64 bits first, then the least
    /// significant 64 bits. The resulting order is the same as canonical
    /// UUID string order and 16-byte big-endian binary order.
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
    /// The resulting order is the same as canonical UUID string order and
    /// 16-byte big-endian binary order.
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
    /// Singleton, safe for concurrent use, consistent with
    /// [#compare(UUID, UUID)], and suitable for ordered collections such as
    /// [java.util.TreeSet] and [java.util.TreeMap].
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
                | ((timestamp >>> 48) & LOW_12_BITS_MASK);
        long leastSigBits = (((long) clockSequence & CLOCK_SEQUENCE_MASK) << 48)
                | (node & NODE_MASK);
        return newWithVersion(mostSigBits, leastSigBits, 1);
    }

    /// Generates a version-1 UUID from the system clock and default random source.
    ///
    /// @return a version-1 UUID
    public static UUID generateV1() {
        return generateV1(InstantSource.system(), DefaultRandomGenerator.INSTANCE);
    }

    /// Generates a version-1 UUID from the system clock and the given random generator.
    ///
    /// @param randomGenerator the source of randomness
    /// @return a version-1 UUID
    public static UUID generateV1(RandomGenerator randomGenerator) {
        return generateV1(InstantSource.system(), randomGenerator);
    }

    /// Generates a version-1 UUID from the given instant and default random source.
    ///
    /// @param instant the timestamp instant
    /// @return a version-1 UUID
    /// @since 0.2.0
    public static UUID generateV1(Instant instant) {
        return generateV1(instant, DefaultRandomGenerator.INSTANCE);
    }

    /// Generates a version-1 UUID from the given instant and random generator.
    ///
    /// The clock sequence and node are drawn from `randomGenerator`. The node
    /// has its multicast bit set to indicate a non-IEEE random node.
    ///
    /// @param instant         the timestamp instant
    /// @param randomGenerator the source of randomness
    /// @return a version-1 UUID
    /// @since 0.2.0
    public static UUID generateV1(Instant instant, RandomGenerator randomGenerator) {
        long randomBits = randomGenerator.nextLong();
        return v1(instant, randomClockSequence(randomBits), randomNode(randomBits));
    }

    /// Generates a version-1 UUID from the given time source and default random source.
    ///
    /// @param instantSource the source of the current time
    /// @return a version-1 UUID
    public static UUID generateV1(InstantSource instantSource) {
        return generateV1(instantSource, DefaultRandomGenerator.INSTANCE);
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
        return generateV1(instantSource.instant(), randomGenerator);
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
                | ((timestamp >>> 48) & LOW_12_BITS_MASK);
        long leastSigBits = ((((long) clockSequence & DCE_CLOCK_SEQUENCE_MASK) << 8)
                | ((long) localDomain & DCE_LOCAL_DOMAIN_MASK)) << 48
                | (node & NODE_MASK);
        return newWithVersion(mostSigBits, leastSigBits, 2);
    }

    /// Generates a version-2 UUID using the system clock and default random source.
    ///
    /// @param localDomain     the DCE local domain
    /// @param localIdentifier the local identifier for that domain
    /// @return a freshly generated version-2 UUID
    public static UUID generateV2(int localDomain, long localIdentifier) {
        return generateV2(localDomain, localIdentifier, InstantSource.system(), DefaultRandomGenerator.INSTANCE);
    }

    /// Generates a version-2 UUID using the system clock and the given random generator.
    ///
    /// @param localDomain     the DCE local domain
    /// @param localIdentifier the local identifier for that domain
    /// @param randomGenerator the source of randomness
    /// @return a freshly generated version-2 UUID
    public static UUID generateV2(int localDomain, long localIdentifier, RandomGenerator randomGenerator) {
        return generateV2(localDomain, localIdentifier, InstantSource.system(), randomGenerator);
    }

    /// Generates a version-2 UUID using the given time source and default
    /// random source.
    ///
    /// @param localDomain     the DCE local domain
    /// @param localIdentifier the local identifier for that domain
    /// @param instantSource   the source of the current time
    /// @return a freshly generated version-2 UUID
    public static UUID generateV2(int localDomain, long localIdentifier, InstantSource instantSource) {
        return generateV2(localDomain, localIdentifier, instantSource, DefaultRandomGenerator.INSTANCE);
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
    /// This method expects a precomputed MD5 digest, not a name. To generate
    /// a name-based UUID from a namespace and name, use [#generateV3(UUID, byte\[\])] instead.
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
    /// RFC 9562 name-based UUIDs use a namespace UUID. Passing `null` omits
    /// the namespace bytes and is a library extension, not the standard
    /// namespace form. Passing [#NIL] uses the nil UUID's 16 bytes as the
    /// namespace and is therefore different from `null`.
    ///
    /// When `namespace` is `null`, this method is equivalent to
    /// [UUID#nameUUIDFromBytes(byte[])] with the UTF-8 bytes of `name`.
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
    /// RFC 9562 name-based UUIDs use a namespace UUID. Passing `null` omits
    /// the namespace bytes and is a library extension, not the standard
    /// namespace form. Passing [#NIL] uses the nil UUID's 16 bytes as the
    /// namespace and is therefore different from `null`.
    ///
    /// When `namespace` is `null`, this method is equivalent to
    /// [UUID#nameUUIDFromBytes(byte[])].
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
    /// RFC 9562 name-based UUIDs use a namespace UUID. Passing `null` omits
    /// the namespace bytes and is a library extension, not the standard
    /// namespace form. Passing [#NIL] uses the nil UUID's 16 bytes as the
    /// namespace and is therefore different from `null`.
    ///
    /// When `namespace` is `null`, this method is equivalent to
    /// [UUID#nameUUIDFromBytes(byte[])] applied to the consumed bytes.
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

    /// Generates a version-4 UUID using the default random source.
    ///
    /// @return a freshly generated version-4 UUID
    public static UUID generateV4() {
        return DefaultRandomGenerator.INSTANCE.nextV4();
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
    /// This method expects a precomputed SHA-1 digest, not a name. To generate
    /// a name-based UUID from a namespace and name, use [#generateV5(UUID, byte\[\])] instead.
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
    /// RFC 9562 name-based UUIDs use a namespace UUID. Passing `null` omits
    /// the namespace bytes and is a library extension, not the standard
    /// namespace form. Passing [#NIL] uses the nil UUID's 16 bytes as the
    /// namespace and is therefore different from `null`.
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
    /// RFC 9562 name-based UUIDs use a namespace UUID. Passing `null` omits
    /// the namespace bytes and is a library extension, not the standard
    /// namespace form. Passing [#NIL] uses the nil UUID's 16 bytes as the
    /// namespace and is therefore different from `null`.
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
    /// RFC 9562 name-based UUIDs use a namespace UUID. Passing `null` omits
    /// the namespace bytes and is a library extension, not the standard
    /// namespace form. Passing [#NIL] uses the nil UUID's 16 bytes as the
    /// namespace and is therefore different from `null`.
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
        long mostSigBits = ((timestamp >>> 12) << 16) | (timestamp & LOW_12_BITS_MASK);
        long leastSigBits = (((long) clockSequence & CLOCK_SEQUENCE_MASK) << 48)
                | (node & NODE_MASK);
        return newWithVersion(mostSigBits, leastSigBits, 6);
    }

    /// Generates a version-6 UUID from the system clock and default random source.
    ///
    /// @return a version-6 UUID
    public static UUID generateV6() {
        return generateV6(InstantSource.system(), DefaultRandomGenerator.INSTANCE);
    }

    /// Generates a version-6 UUID from the system clock and the given random generator.
    ///
    /// @param randomGenerator the source of randomness
    /// @return a version-6 UUID
    public static UUID generateV6(RandomGenerator randomGenerator) {
        return generateV6(InstantSource.system(), randomGenerator);
    }

    /// Generates a version-6 UUID from the given instant and default random source.
    ///
    /// @param instant the timestamp instant
    /// @return a version-6 UUID
    /// @since 0.2.0
    public static UUID generateV6(Instant instant) {
        return generateV6(instant, DefaultRandomGenerator.INSTANCE);
    }

    /// Generates a version-6 UUID from the given instant and random generator.
    ///
    /// The clock sequence and node are drawn from `randomGenerator`. The node
    /// has its multicast bit set to indicate a non-IEEE random node.
    ///
    /// @param instant         the timestamp instant
    /// @param randomGenerator the source of randomness
    /// @return a version-6 UUID
    /// @since 0.2.0
    public static UUID generateV6(Instant instant, RandomGenerator randomGenerator) {
        long randomBits = randomGenerator.nextLong();
        return v6(instant, randomClockSequence(randomBits), randomNode(randomBits));
    }

    /// Generates a version-6 UUID from the given time source and default random source.
    ///
    /// @param instantSource the source of the current time
    /// @return a version-6 UUID
    public static UUID generateV6(InstantSource instantSource) {
        return generateV6(instantSource, DefaultRandomGenerator.INSTANCE);
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
        return generateV6(instantSource.instant(), randomGenerator);
    }

    // ========================================================================
    // Version 1/6 conversion
    // ========================================================================

    /// Converts a version-1 UUID to the equivalent version-6 UUID.
    ///
    /// The Gregorian timestamp, clock sequence, and node are preserved. Only
    /// the timestamp field order and version bits change.
    ///
    /// @param uuid the source version-1 UUID
    /// @return an equivalent version-6 UUID
    /// @throws IllegalArgumentException if `uuid` is not a version-1 UUID
    @Contract(pure = true)
    public static UUID convertV1ToV6(UUID uuid) {
        if (uuid.version() != 1) {
            throw new IllegalArgumentException("Expected a version-1 UUID");
        }
        return v6(getV1Timestamp(uuid), getClockSequence(uuid), getNode(uuid));
    }

    /// Converts a version-6 UUID to the equivalent version-1 UUID.
    ///
    /// The Gregorian timestamp, clock sequence, and node are preserved. Only
    /// the timestamp field order and version bits change.
    ///
    /// @param uuid the source version-6 UUID
    /// @return an equivalent version-1 UUID
    /// @throws IllegalArgumentException if `uuid` is not a version-6 UUID
    @Contract(pure = true)
    public static UUID convertV6ToV1(UUID uuid) {
        if (uuid.version() != 6) {
            throw new IllegalArgumentException("Expected a version-6 UUID");
        }
        return v1(getV6Timestamp(uuid), getClockSequence(uuid), getNode(uuid));
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
        long mostSigBits = ((epochMilli & LOW_48_BITS_MASK) << 16)
                | ((long) randA & LOW_12_BITS_MASK);
        long leastSigBits = randB & LEAST_SIG_BITS_PAYLOAD_MASK;
        return newWithVersion(mostSigBits, leastSigBits, 7);
    }

    /// Generates a version-7 UUID from the system clock and default random source.
    ///
    /// @return a version-7 UUID
    /// @see #generateV7(Instant, RandomGenerator)
    public static UUID generateV7() {
        return generateV7(InstantSource.system(), DefaultRandomGenerator.INSTANCE);
    }

    /// Generates a version-7 UUID from the system clock and the given random generator.
    ///
    /// @param randomGenerator the source of randomness
    /// @return a version-7 UUID
    /// @see #generateV7(Instant, RandomGenerator)
    /// @since 0.2.0
    public static UUID generateV7(RandomGenerator randomGenerator) {
        return generateV7(InstantSource.system(), randomGenerator);
    }

    /// Generates a version-7 UUID from the given instant and default random source.
    ///
    /// @param instant the timestamp instant
    /// @return a version-7 UUID
    /// @see #generateV7(Instant, RandomGenerator)
    /// @since 0.2.0
    public static UUID generateV7(Instant instant) {
        return generateV7(instant, DefaultRandomGenerator.INSTANCE);
    }

    /// Generates a version-7 UUID from the given instant and random generator.
    ///
    /// The timestamp is obtained from `instant`, and the random payload is
    /// obtained from `randomGenerator`.
    ///
    /// @implNote UUID v7 allocates 48 bits for a millisecond timestamp and 74
    /// bits for randomness. The current implementation improves timestamp
    /// precision beyond the millisecond granularity specified by RFC&nbsp;9562
    /// by incorporating the [Instant]'s sub-millisecond fraction (10 bits) into
    /// the random portion. It calls [RandomGenerator::nextLong] only once per
    /// invocation, providing the remaining 64 random bits.
    ///
    /// For full sub-millisecond precision, use [Instant::now] or another source
    /// that provides nanosecond resolution. An [Instant] obtained via
    /// [Instant::ofEpochMilli] lacks sub-millisecond precision, causing those
    /// 10 bits to be zero.
    ///
    /// @param instant         the timestamp instant
    /// @param randomGenerator the source of randomness
    /// @return a version-7 UUID
    /// @since 0.2.0
    public static UUID generateV7(Instant instant, RandomGenerator randomGenerator) {
        final int nanosPerMilli = 1_000_000;
        final int subMilliFractionBits = 10;
        final int randomABits = 2;
        int nanoOfMilli = instant.getNano() % nanosPerMilli;
        int subMillisecondFraction = (int) (((long) nanoOfMilli << subMilliFractionBits)
                / nanosPerMilli);
        long randomBits = randomGenerator.nextLong();
        int randA = (subMillisecondFraction << randomABits)
                | (int) (randomBits >>> (Long.SIZE - randomABits));
        return v7(instant.toEpochMilli(), randA, randomBits);
    }

    /// Generates a version-7 UUID from the given time source and default random source.
    ///
    /// @param instantSource the source of the current time
    /// @return a version-7 UUID
    /// @see #generateV7(Instant, RandomGenerator)
    /// @since 0.2.0
    public static UUID generateV7(InstantSource instantSource) {
        return generateV7(instantSource, DefaultRandomGenerator.INSTANCE);
    }

    /// Generates a version-7 UUID from the given time source and random generator.
    ///
    /// The timestamp is obtained from `instantSource`, and the random payload
    /// is obtained from `randomGenerator`.
    ///
    /// @param instantSource   the source of the current time
    /// @param randomGenerator the source of randomness
    /// @return a version-7 UUID
    /// @see #generateV7(Instant, RandomGenerator)
    /// @since 0.2.0
    public static UUID generateV7(InstantSource instantSource, RandomGenerator randomGenerator) {
        return generateV7(instantSource.instant(), randomGenerator);
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
        leastSigBits = (leastSigBits & LEAST_SIG_BITS_PAYLOAD_MASK)
                | 0x8000_0000_0000_0000L;
        return new UUID(mostSigBits, leastSigBits);
    }

    // ========================================================================
    // Internal helpers
    // ========================================================================

    /// Gregorian epoch offset: the number of 100-nanosecond intervals between
    /// 1582-10-15T00:00:00Z and 1970-01-01T00:00:00Z.
    private static final long GREGORIAN_OFFSET = 0x01B2_1DD2_1381_4000L;

    /// The number of Gregorian 100-nanosecond ticks in one second.
    private static final long GREGORIAN_TICKS_PER_SECOND = 10_000_000L;

    /// The number of Gregorian 100-nanosecond ticks in one millisecond.
    private static final long GREGORIAN_TICKS_PER_MILLI = 10_000L;

    /// The number of nanoseconds in one Gregorian 100-nanosecond tick.
    private static final long NANOS_PER_GREGORIAN_TICK = 100L;

    /// A mask for the low 12 bits of a field.
    private static final int LOW_12_BITS_MASK = 0x0FFF;

    /// A mask for the low 48 bits of a field.
    private static final long LOW_48_BITS_MASK = 0xFFFF_FFFF_FFFFL;

    /// A mask for the 60-bit Gregorian timestamp field used by version 1, 2,
    /// and 6 UUIDs.
    private static final long GREGORIAN_TIMESTAMP_MASK = 0x0FFF_FFFF_FFFF_FFFFL;

    /// A mask for the 62 payload bits below the UUID variant field.
    private static final long LEAST_SIG_BITS_PAYLOAD_MASK = 0x3FFF_FFFF_FFFF_FFFFL;

    /// A mask for the 14-bit clock sequence field used by version 1 and
    /// version 6 UUIDs.
    private static final int CLOCK_SEQUENCE_MASK = 0x3FFF;

    /// A mask for the 6-bit clock sequence field used by version 2 UUIDs.
    private static final int DCE_CLOCK_SEQUENCE_MASK = 0x3F;

    /// A mask for the 8-bit local domain field used by version 2 UUIDs.
    private static final int DCE_LOCAL_DOMAIN_MASK = 0xFF;

    /// A mask for the 48-bit node field used by version 1, 2, and 6 UUIDs.
    private static final long NODE_MASK = LOW_48_BITS_MASK;

    /// The multicast bit in the first octet of a randomly generated node ID.
    private static final long RANDOM_NODE_MULTICAST_MASK = 1L << 40;

    /// A mask for reading an `int`-sized limb as an unsigned 32-bit value.
    private static final long UINT_MASK = 0xFFFF_FFFFL;

    /// The Base62 character set: `0-9A-Za-z`.
    private static final byte[] BASE62_CHARS =
            "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".getBytes(StandardCharsets.ISO_8859_1);

    /// Big-endian byte-array view used to read and write 64-bit UUID halves.
    private static final VarHandle BYTE_ARRAY_LONG_VIEW =
            MethodHandles.byteArrayViewVarHandle(long[].class, ByteOrder.BIG_ENDIAN);

    /// Shared lightweight generator used by default UUID generation methods.
    ///
    /// The singleton instance is seeded from [SecureRandom] when this nested
    /// record is initialized. It keeps a 128-bit SipHash key, a 64-bit output
    /// mask, and an atomic 64-bit counter. Each call hashes a distinct counter
    /// value with SipHash-2-4 and applies the output mask before returning the
    /// 64-bit result.
    ///
    /// The atomic counter makes calls thread-safe and gives concurrent callers
    /// distinct SipHash input blocks until the counter wraps. The output mask
    /// separates otherwise identical seeded streams, but it does not add UUID
    /// payload bits or change the collision space of a UUID version.
    ///
    /// This generator is intended for ordinary UUID generation with small state
    /// and no per-call [SecureRandom] cost. It is not documented as a
    /// cryptographic random source; callers that need cryptographic random
    /// guarantees should pass a [SecureRandom] to the public overloads that
    /// accept a [RandomGenerator].
    ///
    /// @param key0    First SipHash key half.
    /// @param key1    Second SipHash key half.
    /// @param xorMask Per-instance output mask applied after SipHash.
    /// @param counter Monotonic input block for SipHash.
    private record DefaultRandomGenerator(long key0, long key1, long xorMask, AtomicLong counter) implements RandomGenerator {
        /// The default random source instance.
        static final DefaultRandomGenerator INSTANCE;

        static {
            SecureRandom seedSource = new SecureRandom();
            INSTANCE = new DefaultRandomGenerator(
                    seedSource.nextLong(),
                    seedSource.nextLong(),
                    seedSource.nextLong(),
                    new AtomicLong(seedSource.nextLong()));
        }

        /// Computes SipHash-2-4 for a single 8-byte message block.
        static long sipHash24(long key0, long key1, long message) {
            long v0 = 0x736f_6d65_7073_6575L ^ key0;
            long v1 = 0x646f_7261_6e64_6f6dL ^ key1;
            long v2 = 0x6c79_6765_6e65_7261L ^ key0;
            long v3 = 0x7465_6462_7974_6573L ^ key1;

            v3 ^= message;
            for (int i = 0; i < 2; i++) {
                v0 += v1;
                v1 = Long.rotateLeft(v1, 13);
                v1 ^= v0;
                v0 = Long.rotateLeft(v0, 32);
                v2 += v3;
                v3 = Long.rotateLeft(v3, 16);
                v3 ^= v2;
                v0 += v3;
                v3 = Long.rotateLeft(v3, 21);
                v3 ^= v0;
                v2 += v1;
                v1 = Long.rotateLeft(v1, 17);
                v1 ^= v2;
                v2 = Long.rotateLeft(v2, 32);
            }
            v0 ^= message;

            long finalBlock = 8L << 56;
            v3 ^= finalBlock;
            for (int i = 0; i < 2; i++) {
                v0 += v1;
                v1 = Long.rotateLeft(v1, 13);
                v1 ^= v0;
                v0 = Long.rotateLeft(v0, 32);
                v2 += v3;
                v3 = Long.rotateLeft(v3, 16);
                v3 ^= v2;
                v0 += v3;
                v3 = Long.rotateLeft(v3, 21);
                v3 ^= v0;
                v2 += v1;
                v1 = Long.rotateLeft(v1, 17);
                v1 ^= v2;
                v2 = Long.rotateLeft(v2, 32);
            }
            v0 ^= finalBlock;

            v2 ^= 0xffL;
            for (int i = 0; i < 4; i++) {
                v0 += v1;
                v1 = Long.rotateLeft(v1, 13);
                v1 ^= v0;
                v0 = Long.rotateLeft(v0, 32);
                v2 += v3;
                v3 = Long.rotateLeft(v3, 16);
                v3 ^= v2;
                v0 += v3;
                v3 = Long.rotateLeft(v3, 21);
                v3 ^= v0;
                v2 += v1;
                v1 = Long.rotateLeft(v1, 17);
                v1 ^= v2;
                v2 = Long.rotateLeft(v2, 32);
            }
            return v0 ^ v1 ^ v2 ^ v3;
        }

        /// Returns the next 64 pseudorandom bits.
        @Override
        public long nextLong() {
            return sipHash24(key0, key1, counter.getAndIncrement()) ^ xorMask;
        }

        /// Generates a version-4 UUID by reserving two consecutive SipHash
        /// input blocks from this generator's shared counter.
        ///
        /// @return a version-4 UUID generated from this default random source
        private UUID nextV4() {
            long current = counter.getAndAdd(2);
            long msb = sipHash24(key0, key1, current) ^ xorMask;
            long lsb = sipHash24(key0, key1, current + 1) ^ xorMask;
            return v4(msb, lsb);
        }
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

    /// Extracts the 60-bit Gregorian timestamp from a version-1 UUID.
    private static long getV1Timestamp(UUID uuid) {
        long msb = uuid.getMostSignificantBits();
        // time_low (bits 0–31) | time_mid (bits 32–47) | time_hi (bits 48–59)
        long timeLow = (msb >>> 32) & UINT_MASK;
        long timeMid = (msb >>> 16) & 0xFFFFL;
        long timeHi = msb & LOW_12_BITS_MASK;
        return (timeHi << 48) | (timeMid << 32) | timeLow;
    }

    /// Extracts the available high 28 bits of the Gregorian timestamp from a
    /// version-2 UUID and returns the low 32 bits as zero.
    private static long getV2Timestamp(UUID uuid) {
        long msb = uuid.getMostSignificantBits();
        long timeMid = (msb >>> 16) & 0xFFFFL;
        long timeHi = msb & LOW_12_BITS_MASK;
        return (timeHi << 48) | (timeMid << 32);
    }

    /// Extracts the 60-bit Gregorian timestamp from a version-6 UUID.
    private static long getV6Timestamp(UUID uuid) {
        long msb = uuid.getMostSignificantBits();
        // time_high (bits 0–31) | time_mid (bits 32–47) | time_low (bits 48–59)
        long timeHighMid = (msb >>> 16) & LOW_48_BITS_MASK;
        long timeLow = msb & LOW_12_BITS_MASK;
        return (timeHighMid << 12) | timeLow;
    }

    /// Extracts the 48-bit Unix epoch millisecond timestamp from a version-7 UUID.
    private static long getV7UnixTimestampMillis(UUID uuid) {
        return uuid.getMostSignificantBits() >>> 16;
    }

    /// Converts an [Instant] to a Gregorian 100-nanosecond timestamp since
    /// 1582-10-15T00:00:00Z.
    private static long gregorianTimestamp(Instant instant) {
        long seconds = Math.multiplyExact(instant.getEpochSecond(), GREGORIAN_TICKS_PER_SECOND);
        long nanos100 = instant.getNano() / NANOS_PER_GREGORIAN_TICK;
        return Math.addExact(Math.addExact(seconds, nanos100), GREGORIAN_OFFSET);
    }

    /// Converts a 60-bit Gregorian 100-nanosecond timestamp to an [Instant].
    private static Instant instantFromGregorianTimestamp(long timestamp) {
        // Convert from Gregorian epoch (1582-10-15) to Unix epoch (1970-01-01)
        long unixNanos100 = timestamp - GREGORIAN_OFFSET;
        long seconds = Math.floorDiv(unixNanos100, GREGORIAN_TICKS_PER_SECOND);
        long nanoAdjustment = Math.floorMod(unixNanos100, GREGORIAN_TICKS_PER_SECOND)
                * NANOS_PER_GREGORIAN_TICK;
        return Instant.ofEpochSecond(seconds, nanoAdjustment);
    }

    /// Converts a Gregorian 100-nanosecond timestamp to Unix epoch milliseconds.
    private static long unixTimestampMillisFromGregorianTimestamp(long timestamp) {
        return Math.floorDiv(timestamp - GREGORIAN_OFFSET, GREGORIAN_TICKS_PER_MILLI);
    }

    /// Generates a random 14-bit clock sequence.
    private static int randomClockSequence(RandomGenerator randomGenerator) {
        return randomGenerator.nextInt() & CLOCK_SEQUENCE_MASK;
    }

    /// Extracts a random 14-bit clock sequence from the high bits of a random word.
    private static int randomClockSequence(long randomBits) {
        return (int) (randomBits >>> (Long.SIZE - 14));
    }

    /// Generates a random 6-bit DCE Security clock sequence.
    private static int randomDceClockSequence(RandomGenerator randomGenerator) {
        return randomGenerator.nextInt() & DCE_CLOCK_SEQUENCE_MASK;
    }

    /// Generates a random 48-bit node ID with the multicast bit set.
    private static long randomNode(RandomGenerator randomGenerator) {
        return (randomGenerator.nextLong() & NODE_MASK) | RANDOM_NODE_MULTICAST_MASK;
    }

    /// Extracts a random 48-bit node ID from the low bits of a random word and sets the multicast bit.
    private static long randomNode(long randomBits) {
        return (randomBits & NODE_MASK) | RANDOM_NODE_MULTICAST_MASK;
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
        byte[] bytes = new byte[16];
        BYTE_ARRAY_LONG_VIEW.set(bytes, 0, uuid.getMostSignificantBits());
        BYTE_ARRAY_LONG_VIEW.set(bytes, 8, uuid.getLeastSignificantBits());
        digest.update(bytes);
    }

    /// Appends the low bits of a value as fixed-width lowercase hexadecimal.
    private static void appendHex(StringBuilder out, long value, int digits) {
        for (int shift = (digits - 1) * 4; shift >= 0; shift -= 4) {
            out.append(Character.forDigit((int) (value >>> shift) & 0xF, 16));
        }
    }

    /// Constructs a UUID from the first 16 bytes of a hash digest.
    private static UUID uuidFromHash(byte[] hash, int version) {
        long mostSigBits = (long) BYTE_ARRAY_LONG_VIEW.get(hash, 0);
        long leastSigBits = (long) BYTE_ARRAY_LONG_VIEW.get(hash, 8);
        return newWithVersion(mostSigBits, leastSigBits, version);
    }

    /// Throws if `uuid` is not the expected version.
    private static void requireVersion(UUID uuid, int version) {
        int actual = uuid.version();
        if (actual != version) {
            throw new IllegalArgumentException("Expected a version-" + version + " UUID");
        }
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
