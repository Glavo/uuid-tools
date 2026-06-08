// Copyright (c) 2026 Glavo
// SPDX-License-Identifier: MPL-2.0

package org.teavm.classlib.java.lang.invoke;

import org.jetbrains.annotations.NotNullByDefault;

import java.nio.ByteOrder;

/// TeaVM classlib supplement for `java.lang.invoke.MethodHandles`.
///
/// TeaVM maps `org.teavm.classlib.java.*` classes to `java.*` classes. This
/// implementation provides the byte-array view factory used by the demo.
@NotNullByDefault
public final class TMethodHandles {
    /// Creates no instances.
    private TMethodHandles() {
    }

    /// Returns a byte-array view handle for long arrays.
    ///
    /// @param viewArrayClass the requested view array class
    /// @param byteOrder the requested byte order
    /// @return the byte-array view handle
    public static TVarHandle byteArrayViewVarHandle(Class<?> viewArrayClass, ByteOrder byteOrder) {
        if (viewArrayClass == long[].class && byteOrder == ByteOrder.BIG_ENDIAN) {
            return TVarHandle.BIG_ENDIAN_LONG_ARRAY_VIEW;
        }
        throw new UnsupportedOperationException("Unsupported byte array view: " + viewArrayClass + ", " + byteOrder);
    }
}
