// Copyright (c) 2026 Glavo
// SPDX-License-Identifier: MPL-2.0

/// Lightweight UUID utilities for modern Java.
///
/// The module exports [org.glavo.uuid], centered on
/// [org.glavo.uuid.UUIDs]. It provides UUID generation, parsing,
/// formatting, binary conversion, field accessors, and comparison helpers
/// through static methods.
///
/// <h2>Choosing a UUID</h2>
///
/// If you want sortable UUIDs for database keys or distributed event
/// ordering, start with UUID version 7:
///
/// ```java
/// UUID uuid = UUIDs.generateV7();
/// ```
///
/// Use version 4 for fully random UUIDs, version 5 for deterministic
/// name-based UUIDs, and version 8 when an application-defined layout is
/// required. Versions 1, 2, 3, and 6 are mainly useful for interoperability
/// with existing UUID layouts.
///
/// <h2>Text and binary conversion</h2>
///
/// [org.glavo.uuid.UUIDs#parse(String)] accepts standard, compact,
/// Windows registry, and URN text forms. Compact encodings that can be
/// confused with other formats use explicit methods, such as
/// [org.glavo.uuid.UUIDs#parseBase62(String)].
///
/// UUIDs can also be converted to and from their 16-byte big-endian binary
/// representation with [org.glavo.uuid.UUIDs#toBytes(java.util.UUID)] and
/// [org.glavo.uuid.UUIDs#fromBytes(byte[])].
///
/// <h2>Dependencies</h2>
///
/// This module has no runtime dependencies. JetBrains annotations are used
/// only as static nullability metadata.
module org.glavo.uuid {
    requires static org.jetbrains.annotations;

    exports org.glavo.uuid;
}
