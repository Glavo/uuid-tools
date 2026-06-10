# UUID Tools: A Lightweight, Modern Java UUID Utility Library

[![Gradle Check](https://github.com/Glavo/uuid-tools/actions/workflows/check.yml/badge.svg)](https://github.com/Glavo/uuid-tools/actions/workflows/check.yml)
[![codecov](https://codecov.io/gh/Glavo/uuid-tools/graph/badge.svg)](https://codecov.io/gh/Glavo/uuid-tools)
![Java](https://img.shields.io/badge/Java-17%2B-blue)
[![javadoc](https://javadoc.io/badge2/org.glavo/uuid-tools/javadoc.svg)](https://javadoc.io/doc/org.glavo/uuid-tools/latest/org.glavo.uuid/org/glavo/uuid/UUIDs.html)

A lightweight Java UUID utility library for generating, parsing, formatting, and
comparing UUIDs.

## Add to Your Project

[![Maven Central Version](https://img.shields.io/maven-central/v/org.glavo/uuid-tools?label=Maven%20Central)](https://central.sonatype.com/artifact/org.glavo/uuid-tools)

Gradle:

```kotlin
dependencies {
    implementation("org.glavo:uuid-tools:0.2.0")
}
```

Maven:

```xml
<dependencies>
    <dependency>
        <groupId>org.glavo</groupId>
        <artifactId>uuid-tools</artifactId>
        <version>0.2.0</version>
    </dependency>
</dependencies>
```

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
48-bit timestamp (millisecond precision) and 74 `rand_a`/`rand_b` bits.

```java
// Generate a version-7 UUID from the current time and default RNG
UUID current = UUIDs.generateV7();

// Or with a specific InstantSource and RandomGenerator
UUID customSource = UUIDs.generateV7(InstantSource.system(), new Random());

// Or deterministically from a specific Instant, rand_a, and rand_b
UUID deterministic = UUIDs.v7(Instant.now(), 0x123, 114514L);
```

UUID v1/v2/v6 are also time-based and can be constructed similarly.

```java
// Generate version-1/6 UUIDs from the current time and default RNG
UUID currentV1 = UUIDs.generateV1();
UUID currentV6 = UUIDs.generateV6();

// Or with a specific InstantSource and RandomGenerator
UUID customSourceV1 = UUIDs.generateV1(InstantSource.system(), new Random());
UUID customSourceV6 = UUIDs.generateV6(InstantSource.system(), new Random());

// Or deterministically from a specific Instant, clock sequence, and node
UUID deterministicV1 = UUIDs.v1(Instant.now(), 0x1234, 0x0123_4567_89ABL);
UUID deterministicV6 = UUIDs.v6(Instant.now(), 0x1234, 0x0123_4567_89ABL);

// The only difference between UUID v6 and v1 is the ordering of the timestamp bits, 
// so they can be losslessly converted between each other
assert UUIDs.convertV1ToV6(deterministicV1).equals(deterministicV6);
assert UUIDs.convertV6ToV1(deterministicV6).equals(deterministicV1);

// Version 2 embeds a local DCE domain and local identifier
UUID v2 = UUIDs.generateV2(UUIDs.DCE_DOMAIN_PERSON, 501);
UUID fixedTimeV2 = UUIDs.generateV2(UUIDs.DCE_DOMAIN_PERSON, 501, InstantSource.fixed(Instant.now()));
UUID customRandomV2 = UUIDs.generateV2(UUIDs.DCE_DOMAIN_PERSON, 501, new Random());
```

However versions 1/2/6 each have their own drawbacks, so prefer version 7
unless you have specific requirements.

#### Random UUIDs (version 4)

Version-4 UUIDs are randomly generated. Six bits are reserved for the version
and variant fields; the remaining 122 bits are random.

```java
// Generate a version-4 UUID from the default RNG
UUID random = UUIDs.generateV4();

// With a specific RandomGenerator
UUID fromRandomGenerator = UUIDs.generateV4(new Random());

// Deterministically from specific random bits
UUID fromBits = UUIDs.v4(114515L, 1919810L);
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
UUID dnsV3 = UUIDs.generateV3(UUIDs.NAMESPACE_DNS, "glavo.site");
UUID dnsV5 = UUIDs.generateV5(UUIDs.NAMESPACE_DNS, "glavo.site");

// The namespace can be any UUID — use the built-in ones or your own
UUID myNamespace = UUIDs.generateV4();
UUID customV3 = UUIDs.generateV3(myNamespace, "glavo.site");
UUID customV5 = UUIDs.generateV5(myNamespace, "glavo.site");
```

#### Custom UUIDs (version 8)

Version-8 UUIDs reserve 6 bits for version and variant; the remaining 122 bits
are application-defined.

```java
// Construct a version-8 UUID from raw bits
UUID uuid = UUIDs.v8(114515L, 1919810L);
```

### Random Source

`generateV1`/`V2`/`V4`/`V6`/`V7` require random numbers during generation.

The default generation methods use a shared lightweight pseudorandom source
seeded from `SecureRandom` during first use. It is designed for ordinary UUID
generation where throughput and small retained state matter.

For security tokens, credentials, keys, or values that require cryptographic
random guarantees, pass a `SecureRandom` explicitly:

```java
UUID uuidv1 = UUIDs.generateV1(new SecureRandom());
UUID uuidv4 = UUIDs.generateV4(new SecureRandom());
UUID uuidv6 = UUIDs.generateV6(new SecureRandom());
UUID uuidv7 = UUIDs.generateV7(new SecureRandom());
```

### Comparing UUIDs

`java.util.UUID` implements `Comparable`, but its comparison algorithm treats
the two 64-bit halves as signed integers. This is non-standard and can produce
unexpected behavior.

uuid-tools provides a straightforward method and a `Comparator` implementation.
They compare UUIDs as unsigned 128-bit integers, which matches the ordering of
canonical UUID strings and 16-byte big-endian UUID values.

```java
Instant now = Instant.now();
UUID uuid1 = UUIDs.v7(now, 0, 0L);
UUID uuid2 = UUIDs.v7(now.plusSeconds(1L), 0, 0L);

// Compare two UUIDs
assert UUIDs.compare(uuid1, uuid2) < 0;

// Use uuid-tools' Comparator instead of the default
TreeSet<UUID> ordered = new TreeSet<>(UUIDs.comparator());
```

### String Conversion

`java.util.UUID.toString()` produces the standard hyphenated form
(e.g. `2712b21a-988a-4bf7-ac0e-7007300c10c2`), and
`UUID.fromString(String)` parses it back.

In practice, UUIDs appear in many different string formats. uuid-tools provides
convenient methods for converting UUIDs to these formats. `UUIDs.parse(String)`
handles unambiguous UUID text forms, while compact encodings such as Base62 use
explicit parsers.

Supported formats:

| Format           | To String Method              | Parse Method               | Example                                         |
|------------------|-------------------------------|----------------------------|-------------------------------------------------|
| Standard         | `UUID.toString()`             | `UUIDs.parse(String)`      | `550e8400-e29b-41d4-a716-446655440000`          |
| Compact          | `UUIDs.toCompactString(UUID)` | `UUIDs.parse(String)`      | `550e8400e29b41d4a716446655440000`              |
| Windows registry | /                             | `UUIDs.parse(String)`      | `{550e8400-e29b-41d4-a716-446655440000}`        |
| URN              | `UUIDs.toURNString(UUID)`     | `UUIDs.parse(String)`      | `urn:uuid:550e8400-e29b-41d4-a716-446655440000` |
| Base62           | `UUIDs.toBase62String(UUID)`  | `UUIDs.parseBase62(String)` | `2aUyqjCzEIiEcYMKj7TZtw`                        |

### Binary Conversion

UUIDs can be converted to and from their 16-byte big-endian representation.

```java
UUID uuid = UUIDs.generateV7();
byte[] bytes = UUIDs.toBytes(uuid);
UUID decoded = UUIDs.fromBytes(bytes);

byte[] payload = new byte[20];
UUIDs.toBytes(uuid, payload, 2);
UUID decodedFromOffset = UUIDs.fromBytes(payload, 2);
```

## Comparison with UUID Creator

[UUID Creator](https://github.com/f4b6a3/uuid-creator) is a well-established
library in the Java ecosystem with many related features, and uuid-tools has
drawn inspiration from its design and test suite.

Compared to UUID Creator, uuid-tools is significantly lighter (JAR ~15 KiB,
roughly 1/10 the size) and offers a simpler, more modern API that is easy to
learn and use.

uuid-tools' API resembles UUID Creator's `GUID` class, but clearly separates
UUID generation from construction for better semantic clarity, and is built
for modern Java (Java 17+).

uuid-tools also allows direct construction of UUIDs from their underlying
fields, making it easy to implement custom UUID generation strategies.

## Requirements

- Java 17 or later

## Demo Website

The repository includes a static TeaVM/Wasm GC demo website for trying the core
UUID APIs in a browser.

```shell
./gradlew buildWebsite
```

The generated website is written to `build/website`. Serve that directory over
HTTP so the browser can load the WebAssembly module.

For local development, Gradle can also build and serve the website:

```shell
./gradlew serveWebsite
```

The server listens on `http://127.0.0.1:8080/` by default. Use
`-Pwebsite.port=8081` to choose another port.

## License

[MPL-2.0](https://www.mozilla.org/en-US/MPL/2.0/)
