// Copyright (c) 2026 Glavo
// SPDX-License-Identifier: MPL-2.0

package org.teavm.classlib.java.security;

import org.jetbrains.annotations.NotNullByDefault;
import org.jetbrains.annotations.Nullable;

/// TeaVM classlib supplement for `java.security.NoSuchAlgorithmException`.
///
/// TeaVM maps `org.teavm.classlib.java.*` classes to `java.*` classes.
@NotNullByDefault
public class TNoSuchAlgorithmException extends Exception {
    /// Creates an exception with no detail message.
    public TNoSuchAlgorithmException() {
    }

    /// Creates an exception with a detail message.
    ///
    /// @param message the detail message
    public TNoSuchAlgorithmException(@Nullable String message) {
        super(message);
    }
}
