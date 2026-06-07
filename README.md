# uuid-tools

UUID creation, parsing, formatting, and comparison utilities for Java 17+.

Implements all UUID versions defined by [RFC 9562](https://www.rfc-editor.org/rfc/rfc9562)
and the DCE Security version-2 layout, built on top of `java.util.UUID`.

## Coordinates

```
group:    org.glavo
artifact: uuid-tools
```

## Choosing a UUID Version

| Need | Version | Method |
|------|---------|--------|
| Time-ordered key | **v7** | `UUIDs.generateV7()` |
| Deterministic from a name | **v5** | `UUIDs.generateV5(namespace, name)` |
| Fully random | **v4** | `UUIDs.generateV4()` |
| Custom layout | **v8** | `UUIDs.v8(msb, lsb)` |

Versions 1, 2, 3, and 6 are available for legacy interoperability.

## Quick Start

```java
import org.glavo.uuid.UUIDs;

// Generate a time-ordered UUID (recommended for most use cases)
UUID id = UUIDs.generateV7();

// Deterministic UUID from a namespace and name
UUID dns = UUIDs.generateV5(UUIDs.NAMESPACE_DNS, "example.com");

// Parse any supported format
UUID parsed = UUIDs.parse("550e8400-e29b-41d4-a716-446655440000");

// Compact hex (no hyphens)
String compact = UUIDs.toCompactString(id);

// Base62 (22 characters)
String base62 = UUIDs.toBase62String(id);

// Extract timestamp from a time-based UUID
Instant timestamp = UUIDs.getInstant(id);

// Unsigned 128-bit comparison
int cmp = UUIDs.compare(id, parsed);
```

## Supported Parse Formats

| Format | Example |
|--------|---------|
| Standard | `550e8400-e29b-41d4-a716-446655440000` |
| Compact | `550e8400e29b41d4a716446655440000` |
| Windows registry | `{550e8400-e29b-41d4-a716-446655440000}` |
| URN | `urn:uuid:550e8400-e29b-41d4-a716-446655440000` |
| Base62 | `6aGFHbkMKi3UrLaRLGaKzG` |

## Output Formats

| Method | Example |
|--------|---------|
| `UUID.toString()` | `550e8400-e29b-41d4-a716-446655440000` |
| `toCompactString()` | `550e8400e29b41d4a716446655440000` |
| `toURNString()` | `urn:uuid:550e8400-e29b-41d4-a716-446655440000` |
| `toBase62String()` | `6aGFHbkMKi3UrLaRLGaKzG` |
| `toOIDString()` | `2.25.113059749145936325402354257176981405696` |

## Requirements

- Java 17 or later

## License

[MPL-2.0](https://www.mozilla.org/en-US/MPL/2.0/)
