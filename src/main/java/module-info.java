// Copyright (c) 2026 Glavo
// SPDX-License-Identifier: MPL-2.0

/// Lightweight UUID utilities for modern Java.
///
/// The module exports [org.glavo.uuid], centered on
/// [org.glavo.uuid.UUIDs]. It provides UUID generation, parsing,
/// formatting, binary conversion, field accessors, and comparison helpers
/// through static methods.
///
/// This module has no runtime dependencies. JetBrains annotations are used
/// only as static nullability metadata.
module org.glavo.uuid {
    requires static org.jetbrains.annotations;

    exports org.glavo.uuid;
}
