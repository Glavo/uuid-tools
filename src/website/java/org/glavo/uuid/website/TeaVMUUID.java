// Copyright (c) 2026 Glavo
// SPDX-License-Identifier: MPL-2.0

package org.glavo.uuid.website;

import org.jetbrains.annotations.NotNullByDefault;

/// TeaVM replacement for `java.util.UUID` used by the demo website.
///
/// The website build maps `java.util.UUID` to this class because TeaVM 0.14
/// ships an incomplete UUID classlib implementation.
@NotNullByDefault
public final class TeaVMUUID implements Comparable<TeaVMUUID> {
    /// The UUID variant mask for the RFC 4122/RFC 9562 variant.
    private static final long RFC_VARIANT_MASK = 0x8000_0000_0000_0000L;

    /// The UUID variant bit pattern mask.
    private static final long VARIANT_PATTERN_MASK = 0xC000_0000_0000_0000L;

    /// The most significant 64 bits.
    private final long mostSigBits;

    /// The least significant 64 bits.
    private final long leastSigBits;

    /// Creates a UUID from raw 128-bit data.
    ///
    /// @param mostSigBits the most significant 64 bits
    /// @param leastSigBits the least significant 64 bits
    public TeaVMUUID(long mostSigBits, long leastSigBits) {
        this.mostSigBits = mostSigBits;
        this.leastSigBits = leastSigBits;
    }

    /// Returns the most significant 64 bits.
    ///
    /// @return the most significant 64 bits
    public long getMostSignificantBits() {
        return mostSigBits;
    }

    /// Returns the least significant 64 bits.
    ///
    /// @return the least significant 64 bits
    public long getLeastSignificantBits() {
        return leastSigBits;
    }

    /// Returns the UUID version field.
    ///
    /// @return the UUID version
    public int version() {
        return (int) ((mostSigBits >>> 12) & 0xF);
    }

    /// Returns the UUID variant field.
    ///
    /// @return the UUID variant
    public int variant() {
        if ((leastSigBits & RFC_VARIANT_MASK) == 0L) {
            return 0;
        }
        if ((leastSigBits & VARIANT_PATTERN_MASK) == RFC_VARIANT_MASK) {
            return 2;
        }
        return (int) ((leastSigBits >>> 61) & 0x7);
    }

    /// Compares UUIDs using the JDK signed two-long ordering.
    ///
    /// @param other the UUID to compare with
    /// @return the comparison result
    @Override
    public int compareTo(TeaVMUUID other) {
        int high = Long.compare(mostSigBits, other.mostSigBits);
        return high != 0 ? high : Long.compare(leastSigBits, other.leastSigBits);
    }

    /// Returns whether this UUID equals another object.
    ///
    /// @param object the object to compare with
    /// @return `true` when the object is an equal UUID
    @Override
    public boolean equals(Object object) {
        return this == object || object instanceof TeaVMUUID other
                && mostSigBits == other.mostSigBits
                && leastSigBits == other.leastSigBits;
    }

    /// Returns the UUID hash code.
    ///
    /// @return the hash code
    @Override
    public int hashCode() {
        long hilo = mostSigBits ^ leastSigBits;
        return (int) (hilo >> 32) ^ (int) hilo;
    }

    /// Formats this UUID as canonical hyphenated lowercase text.
    ///
    /// @return the canonical UUID string
    @Override
    public String toString() {
        StringBuilder out = new StringBuilder(36);
        appendHex(out, mostSigBits >>> 32, 8);
        out.append('-');
        appendHex(out, mostSigBits >>> 16, 4);
        out.append('-');
        appendHex(out, mostSigBits, 4);
        out.append('-');
        appendHex(out, leastSigBits >>> 48, 4);
        out.append('-');
        appendHex(out, leastSigBits, 12);
        return out.toString();
    }

    /// Parses a UUID from canonical hyphenated text.
    ///
    /// @param value the UUID string
    /// @return the parsed UUID
    public static TeaVMUUID fromString(String value) {
        if (value.length() != 36
                || value.charAt(8) != '-'
                || value.charAt(13) != '-'
                || value.charAt(18) != '-'
                || value.charAt(23) != '-') {
            throw new IllegalArgumentException("Invalid UUID string: " + value);
        }

        long most = parseHex(value, 0, 8);
        most = (most << 16) | parseHex(value, 9, 13);
        most = (most << 16) | parseHex(value, 14, 18);
        long least = parseHex(value, 19, 23);
        least = (least << 48) | parseHex(value, 24, 36);
        return new TeaVMUUID(most, least);
    }

    /// Appends the low bits of a value as fixed-width lowercase hexadecimal.
    ///
    /// @param out the output builder
    /// @param value the value to append
    /// @param digits the number of hexadecimal digits
    private static void appendHex(StringBuilder out, long value, int digits) {
        for (int shift = (digits - 1) * 4; shift >= 0; shift -= 4) {
            out.append(Character.forDigit((int) (value >>> shift) & 0xF, 16));
        }
    }

    /// Parses a hexadecimal substring.
    ///
    /// @param value the source string
    /// @param start the inclusive start offset
    /// @param end the exclusive end offset
    /// @return the parsed value
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

    /// Returns a hexadecimal digit value, or -1 if invalid.
    ///
    /// @param c the character
    /// @return the digit value
    private static int hexDigit(char c) {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        if (c >= 'A' && c <= 'F') {
            return c - 'A' + 10;
        }
        if (c >= 'a' && c <= 'f') {
            return c - 'a' + 10;
        }
        return -1;
    }
}
