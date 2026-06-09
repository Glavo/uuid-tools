# Changelog

## 0.2.0 (In development)

### New APIs

- Added `Instant` overloads for version-1, version-6, and version-7 UUID generation, and added the missing
  `generateV7(RandomGenerator)` and `generateV7(InstantSource)` overloads.

### Improvements

- Added a per-instance output mask to the default random generator.
- Updated README and Javadoc coverage for dependency usage, random source guidance, version-7 generation,
  name-based UUID digest and null-namespace behavior, and default random generator internals.

### Tests

- Expanded Base62, compatibility, boundary-state, parsing, and binary conversion coverage.

---

## 0.1.0 (2026-06-08)

Initial release.
