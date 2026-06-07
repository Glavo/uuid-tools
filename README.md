# uuid-tools

A lightweight Java UUID utility library for generating, parsing, formatting, and
comparing UUIDs.

## Add to Your Project

TODO

## Features

uuid-tools has a single top-level class `org.glavo.uuid.UUIDs` with all
functionality exposed through static methods and fields.

### Generating UUIDs

UUID has multiple versions. Different version numbers represent different
construction rules and purposes, and they are not necessarily interchangeable.

Java's `UUID` only provides `randomUUID()` and `nameUUIDFromBytes(byte[])` for
generating UUID v4 and v3 respectively, while uuid-tools supports generating
UUID v1/v2/v3/v4/v5/v6/v7/v8.

#### Time-based UUIDs (versions 1/2/6/7)

If you want to embed timestamps in UUIDs, prefer version 7. It contains a
48-bit timestamp (millisecond precision) and 74 random bits.

```java
// Generate a version-7 UUID from the current time and default RNG
UUID _ = UUIDs.generateV7();

// Or with a specific InstantSource and RandomGenerator
UUID _ = UUIDs.generateV7(Clock.systemUTC(), new Random());

// Or deterministically from a specific Instant and random bits
UUID _ = UUIDs.v7(Instant.now(), 114514L);
```

UUID v1/v2/v6 are also time-based and can be constructed similarly.

```java
// Generate version-1/6 UUIDs from the current time and default RNG
UUID _ = UUIDs.generateV1();
UUID _ = UUIDs.generateV6();

// Or with a specific InstantSource and RandomGenerator
UUID _ = UUIDs.generateV1(Clock.systemUTC(), new Random());
UUID _ = UUIDs.generateV6(Clock.systemUTC(), new Random());

// Or deterministically from a specific Instant and node value
UUID _ = UUIDs.v1(Instant.now(), 114514L);
UUID _ = UUIDs.v6(Instant.now(), 114514L);

// V1/v6 traditionally embed a MAC address; you can pass one directly
NetworkInterface networkInterface = java.net.NetworkInterface.networkInterfaces().findFirst().get();
UUID _ = UUIDs.v1(Instant.now(), networkInterface.getHardwareAddress());
UUID _ = UUIDs.v6(Instant.now(), networkInterface.getHardwareAddress());
```

However versions 1/2/6 each have their own drawbacks, so prefer version 7
unless you have specific requirements.

#### Random UUIDs (version 4)

Version-4 UUIDs are randomly generated. Six bits are reserved for the version
and variant fields; the remaining 122 bits are random.

```java
// Generate a version-4 UUID from the default RNG
UUID _ = UUIDs.generateV4();

// With a specific RandomGenerator
UUID _ = UUIDs.generateV4(new Random());

// Deterministically from specific random bits
UUID _ = UUIDs.v4(114515L, 1919810L);
```

#### Name-based UUIDs (versions 3/5)

Version-3/5 UUIDs are derived by hashing a namespace UUID and a name string.

Given the same namespace and name, the resulting UUID is deterministic.
Changing either the namespace or the name produces a completely different UUID
(barring hash collisions).

Version 3 uses MD5; version 5 uses SHA-1. Prefer version 5 since MD5 has known
weaknesses.

```java
// Generate version-3/5 UUIDs from a namespace and name
UUID _ = UUIDs.generateV3(UUIDs.NAMESPACE_DNS, "glavo.site");
UUID _ = UUIDs.generateV5(UUIDs.NAMESPACE_DNS, "glavo.site");

// The namespace can be any UUID — use the built-in ones or your own
UUID myNamespace = UUIDs.generateV4();
UUID _ = UUIDs.generateV3(myNamespace, "glavo.site");
UUID _ = UUIDs.generateV5(myNamespace, "glavo.site");
```

#### Custom UUIDs (version 8)

Version-8 UUIDs reserve 6 bits for version and variant; the remaining 122 bits
are application-defined.

```java
// Construct a version-8 UUID from raw bits
UUID _ = UUIDs.v8(114515L, 1919810L);
```

### Comparing UUIDs

`java.util.UUID` implements `Comparable`, but its comparison algorithm treats
the two 64-bit halves as signed integers. This is non-standard and can produce
unexpected behavior.

uuid-tools provides a straightforward method and a `Comparator` implementation
that use the conventional unsigned 128-bit ordering, making UUID sorting behave
as expected.

```java
Instant now = Instant.now();
UUID uuid1 = UUIDs.v7(now, 0L);
UUID uuid2 = UUIDs.v7(now.plusSeconds(1L), 0L);

// Compare two UUIDs
assert UUIDs.compare(uuid1, uuid2) < 0;

// Use uuid-tools' Comparator instead of the default
TreeSet<UUID> _ = new TreeSet<>(UUIDs.comparator());
```

### String Conversion

`java.util.UUID.toString()` produces the standard hyphenated form
(e.g. `2712b21a-988a-4bf7-ac0e-7007300c10c2`), and
`UUID.fromString(String)` parses it back.

In practice, UUIDs appear in many different string formats. uuid-tools provides
convenient methods for converting UUIDs to these formats and a unified
`UUIDs.parse(String)` for parsing them all.

Supported formats:

| Format           | To String Method              | Example                                         |
|------------------|-------------------------------|-------------------------------------------------|
| Standard         | `UUID.toString()`             | `550e8400-e29b-41d4-a716-446655440000`          |
| Compact          | `UUIDs.toCompactString(UUID)` | `550e8400e29b41d4a716446655440000`              |
| Windows registry | /                             | `{550e8400-e29b-41d4-a716-446655440000}`        |
| URN              | `UUIDs.toURNString(UUID)`     | `urn:uuid:550e8400-e29b-41d4-a716-446655440000` |
| Base62           | `UUIDs.toBase62String(UUID)`  | `6aGFHbkMKi3UrLaRLGaKzG`                        |

## Requirements

- Java 17 or later

## License

[MPL-2.0](https://www.mozilla.org/en-US/MPL/2.0/)
