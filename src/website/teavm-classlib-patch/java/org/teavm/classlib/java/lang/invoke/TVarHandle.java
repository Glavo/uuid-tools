// Copyright (c) 2026 Glavo
// SPDX-License-Identifier: MPL-2.0

package org.teavm.classlib.java.lang.invoke;

import org.jetbrains.annotations.NotNullByDefault;

/// TeaVM classlib supplement for `java.lang.invoke.VarHandle`.
///
/// TeaVM maps `org.teavm.classlib.java.*` classes to `java.*` classes. This
/// implementation provides the big-endian `byte[]` long view used by the demo.
@NotNullByDefault
public final class TVarHandle {
    /// Singleton big-endian `byte[]` long view.
    static final TVarHandle BIG_ENDIAN_LONG_ARRAY_VIEW = new TVarHandle();

    /// Creates the singleton view handle.
    private TVarHandle() {
    }

    /// Reads a 64-bit big-endian value from a byte array.
    ///
    /// @param bytes the source byte array
    /// @param offset the source offset
    /// @return the decoded value
    public long get(byte[] bytes, int offset) {
        return ((bytes[offset] & 0xFFL) << 56)
                | ((bytes[offset + 1] & 0xFFL) << 48)
                | ((bytes[offset + 2] & 0xFFL) << 40)
                | ((bytes[offset + 3] & 0xFFL) << 32)
                | ((bytes[offset + 4] & 0xFFL) << 24)
                | ((bytes[offset + 5] & 0xFFL) << 16)
                | ((bytes[offset + 6] & 0xFFL) << 8)
                | (bytes[offset + 7] & 0xFFL);
    }

    /// Writes a 64-bit big-endian value into a byte array.
    ///
    /// @param bytes the destination byte array
    /// @param offset the destination offset
    /// @param value the value to encode
    public void set(byte[] bytes, int offset, long value) {
        bytes[offset] = (byte) (value >>> 56);
        bytes[offset + 1] = (byte) (value >>> 48);
        bytes[offset + 2] = (byte) (value >>> 40);
        bytes[offset + 3] = (byte) (value >>> 32);
        bytes[offset + 4] = (byte) (value >>> 24);
        bytes[offset + 5] = (byte) (value >>> 16);
        bytes[offset + 6] = (byte) (value >>> 8);
        bytes[offset + 7] = (byte) value;
    }
}
