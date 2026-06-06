// Copyright (c) 2026 Glavo
// SPDX-License-Identifier: MPL-2.0

package org.glavo.uuid;

import org.jetbrains.annotations.NotNullByDefault;
import org.jetbrains.annotations.Nullable;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.InstantSource;
import java.util.UUID;
import java.util.random.RandomGenerator;

/// Utility class for creating [UUID] instances of various versions defined by
/// [RFC 9562](https://www.rfc-editor.org/rfc/rfc9562).
///
/// Supported UUID versions:
///
/// - **Version 3** — name-based UUID using MD5 hashing.
/// - **Version 5** — name-based UUID using SHA-1 hashing.
/// - **Version 7** — time-ordered UUID combining a Unix epoch millisecond
///   timestamp with random bits.
///
/// This class also provides the [#NIL] constant and the low-level helper
/// [#newWithVersion(long, long, int)] for stamping version and variant bits
/// onto arbitrary 128-bit values.
///
/// All methods are thread-safe and stateless.
@NotNullByDefault
public final class UUIDs {

    /// The nil UUID whose 128 bits are all zero, as defined by RFC 9562 § 5.9.
    public static final UUID NIL = new UUID(0L, 0L);

    // -- Version 3 (MD5) -----------------------------------------------------

    /// Creates a version-3 (MD5) name-based UUID from a string name.
    ///
    /// The name is encoded as UTF-8 before hashing. If `namespace` is
    /// non-null its 16-byte representation is prepended to the hash input.
    ///
    /// @param name      the name to hash
    /// @param namespace the optional namespace UUID prepended to the hash input
    /// @return a version-3 UUID
    public static UUID v3(String name, @Nullable UUID namespace) {
        return v3(name.getBytes(StandardCharsets.UTF_8), namespace);
    }

    /// Creates a version-3 (MD5) name-based UUID from a byte-array name.
    ///
    /// If `namespace` is non-null its 16-byte representation is prepended
    /// to the hash input.
    ///
    /// @param name      the name bytes to hash
    /// @param namespace the optional namespace UUID prepended to the hash input
    /// @return a version-3 UUID
    public static UUID v3(byte[] name, @Nullable UUID namespace) {
        return nameBasedUUID(name, namespace, "MD5", 3);
    }

    /// Creates a version-3 (MD5) name-based UUID from a [ByteBuffer] name.
    ///
    /// All remaining bytes in the buffer are consumed. If `namespace` is
    /// non-null its 16-byte representation is prepended to the hash input.
    ///
    /// @param name      the buffer whose remaining bytes are hashed
    /// @param namespace the optional namespace UUID prepended to the hash input
    /// @return a version-3 UUID
    public static UUID v3(ByteBuffer name, @Nullable UUID namespace) {
        return nameBasedUUID(name, namespace, "MD5", 3);
    }

    // -- Version 5 (SHA-1) ---------------------------------------------------

    /// Creates a version-5 (SHA-1) name-based UUID from a string name.
    ///
    /// The name is encoded as UTF-8 before hashing. If `namespace` is
    /// non-null its 16-byte representation is prepended to the hash input.
    ///
    /// @param name      the name to hash
    /// @param namespace the optional namespace UUID prepended to the hash input
    /// @return a version-5 UUID
    public static UUID v5(String name, @Nullable UUID namespace) {
        return v5(name.getBytes(StandardCharsets.UTF_8), namespace);
    }

    /// Creates a version-5 (SHA-1) name-based UUID from a byte-array name.
    ///
    /// If `namespace` is non-null its 16-byte representation is prepended
    /// to the hash input.
    ///
    /// @param name      the name bytes to hash
    /// @param namespace the optional namespace UUID prepended to the hash input
    /// @return a version-5 UUID
    public static UUID v5(byte[] name, @Nullable UUID namespace) {
        return nameBasedUUID(name, namespace, "SHA-1", 5);
    }

    /// Creates a version-5 (SHA-1) name-based UUID from a [ByteBuffer] name.
    ///
    /// All remaining bytes in the buffer are consumed. If `namespace` is
    /// non-null its 16-byte representation is prepended to the hash input.
    ///
    /// @param name      the buffer whose remaining bytes are hashed
    /// @param namespace the optional namespace UUID prepended to the hash input
    /// @return a version-5 UUID
    public static UUID v5(ByteBuffer name, @Nullable UUID namespace) {
        return nameBasedUUID(name, namespace, "SHA-1", 5);
    }

    // -- Version 7 (time-ordered) --------------------------------------------

    /// Creates a version-7 UUID from an [Instant] timestamp and random bits.
    ///
    /// The instant is converted to milliseconds since the Unix epoch via
    /// [Instant#toEpochMilli()].
    ///
    /// @param instant    the timestamp
    /// @param randomBits random bits filling the non-timestamp, non-version,
    ///                   non-variant positions
    /// @return a version-7 UUID
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
    public static UUID v7(long epochMilli, long randomBits) {
        // Most significant 64 bits: 48-bit timestamp | 12 random bits (version set by newWithVersion)
        long mostSigBits = ((epochMilli & 0xFFFF_FFFF_FFFFL) << 16)
                | ((randomBits >>> 52) & 0x0FFFL);
        // Least significant 64 bits: remaining random bits (variant set by newWithVersion)
        long leastSigBits = randomBits << 12 >>> 2;
        return newWithVersion(mostSigBits, leastSigBits, 7);
    }

    /// Generates a new version-7 UUID using the given time source and random
    /// generator.
    ///
    /// This is a convenience method that obtains the current millisecond
    /// timestamp from `instantSource` and random bits from
    /// `randomGenerator`, then delegates to [#v7(long, long)].
    ///
    /// @param instantSource   the source of the current time
    /// @param randomGenerator the source of randomness
    /// @return a freshly generated version-7 UUID
    public static UUID generateV7(InstantSource instantSource, RandomGenerator randomGenerator) {
        long milli = instantSource.millis();
        long randomBits = randomGenerator.nextLong();
        return v7(milli, randomBits);
    }

    // -- Low-level helper ----------------------------------------------------

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
    public static UUID newWithVersion(long mostSigBits, long leastSigBits, int version) {
        // Clear version bits (48–51) and set the requested version
        mostSigBits = (mostSigBits & 0xFFFF_FFFF_FFFF_0FFFL)
                | ((long) (version & 0xF) << 12);
        // Clear variant bits (62–63 of leastSigBits) and set variant 10
        leastSigBits = (leastSigBits & 0x3FFF_FFFF_FFFF_FFFFL)
                | 0x8000_0000_0000_0000L;
        return new UUID(mostSigBits, leastSigBits);
    }

    // -- Internal helpers ----------------------------------------------------

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
    /// exception in an [AssertionError] since MD5 and SHA-1 are always
    /// available in conforming JREs.
    private static MessageDigest getDigest(String algorithm) {
        try {
            return MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError("Missing algorithm: " + algorithm, e);
        }
    }

    /// Private constructor prevents instantiation.
    private UUIDs() {
    }
}
