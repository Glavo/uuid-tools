// Copyright (c) 2026 Glavo
// SPDX-License-Identifier: MPL-2.0

package org.glavo.uuid.website;

import org.glavo.uuid.UUIDs;
import org.jetbrains.annotations.NotNullByDefault;
import org.jetbrains.annotations.Nullable;
import org.jetbrains.annotations.Unmodifiable;
import org.teavm.jso.JSBody;
import org.teavm.jso.JSFunctor;
import org.teavm.jso.JSObject;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;

/// TeaVM entry point for the interactive UUID Tools demo website.
@NotNullByDefault
public final class UUIDToolsDemo {
    /// The number of UUID bytes.
    private static final int UUID_BYTE_LENGTH = 16;

    /// Gregorian epoch offset: the number of 100-nanosecond intervals between
    /// 1582-10-15T00:00:00Z and 1970-01-01T00:00:00Z.
    private static final long GREGORIAN_OFFSET = 0x01B2_1DD2_1381_4000L;

    /// The number of Gregorian 100-nanosecond ticks in one millisecond.
    private static final long GREGORIAN_TICKS_PER_MILLI = 10_000L;

    /// A mask for the 12-bit UUID version-7 `rand_a` field.
    private static final int RAND_A_MASK = 0x0FFF;

    /// A mask for the 14-bit UUID version-1 and version-6 clock sequence field.
    private static final int CLOCK_SEQUENCE_MASK = 0x3FFF;

    /// A mask for the 6-bit UUID version-2 clock sequence field.
    private static final int DCE_CLOCK_SEQUENCE_MASK = 0x3F;

    /// A mask for the 48-bit UUID version-1, version-2, and version-6 node field.
    private static final long NODE_MASK = 0xFFFF_FFFF_FFFFL;

    /// A mask for the 62-bit UUID version-7 `rand_b` field.
    private static final long RAND_B_MASK = 0x3FFF_FFFF_FFFF_FFFFL;

    /// Characters used by the standard Base64 alphabet.
    private static final String BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /// The multicast bit used for random UUID node identifiers.
    private static final long RANDOM_NODE_MULTICAST_MASK = 1L << 40;

    /// HTML ids for controls that update the generated UUID preview.
    private static final String @Unmodifiable [] GENERATOR_CONTROL_IDS = {
            "version-select",
            "namespace-select",
            "namespace-input",
            "name-input",
            "local-domain-select",
            "local-id-input",
    };

    /// HTML ids for fields that show values derived from the active UUID.
    private static final String @Unmodifiable [] INSPECTOR_FIELD_IDS = {
            "field-standard",
            "field-base64",
            "field-oid",
            "field-bytes",
            "field-msb",
            "field-lsb",
            "field-version",
            "field-variant",
            "field-instant",
            "field-time-unix",
            "field-time-gregorian",
            "field-clock-sequence",
            "field-node",
            "field-dce-domain",
            "field-dce-local-id",
            "field-rand-a",
            "field-rand-b",
    };

    /// Display content for the selected UUID version.
    ///
    /// @param title the panel title
    /// @param kind the compact version category
    /// @param text the combined behavior and usage description
    private record VersionDetails(String title, String kind, String text) {
    }

    /// The UUID currently displayed as the active source value.
    private static @Nullable UUID currentUUID;

    /// Creates no instances.
    private UUIDToolsDemo() {
    }

    /// Starts the demo after the TeaVM WebAssembly module has loaded.
    ///
    /// @param args ignored command-line arguments supplied by the TeaVM runtime
    public static void main(String[] args) {
        for (String id : GENERATOR_CONTROL_IDS) {
            addLiveUpdateListener(id, UUIDToolsDemo::regenerate);
        }
        addLiveUpdateListener("parse-input", UUIDToolsDemo::parseInput);
        addLiveUpdateListener("parse-format-select", UUIDToolsDemo::parseInput);
        addClickListener("source-generate-button", UUIDToolsDemo::activateGenerateSource);
        addClickListener("source-parse-button", UUIDToolsDemo::activateParseSource);
        addClickListener("generate-button", UUIDToolsDemo::regenerate);
        addClickListener("copy-active-button", UUIDToolsDemo::copyActiveUUIDToClipboard);
        regenerate();
    }

    /// Activates the generator as the current UUID source.
    private static void activateGenerateSource() {
        setDocumentSource("generate");
        regenerate();
    }

    /// Activates the parser as the current UUID source.
    private static void activateParseSource() {
        setDocumentSource("parse");
        parseInput();
    }

    /// Regenerates the active UUID and updates all dependent panels.
    private static void regenerate() {
        int version = parseIntValue("version-select", "version");
        setDocumentVersion(version);
        setDocumentNamespace(readValue("namespace-select"));
        renderVersionDetails(version);
        try {
            UUID uuid = createUUID(version);
            acceptUUID(uuid, "Generated");
        } catch (RuntimeException e) {
            rejectSource("Failed", e);
        }
    }

    /// Creates a UUID for the selected version.
    ///
    /// @param version the selected UUID version
    /// @return the generated UUID
    private static UUID createUUID(int version) {
        return switch (version) {
            case 1 -> UUIDs.v1(currentGregorianTimestamp(), randomClockSequence(), randomNode());
            case 2 -> UUIDs.v2(
                    currentGregorianTimestamp(),
                    parseIntValue("local-domain-select", "local domain"),
                    parseUnsignedValue("local-id-input", 0xFFFF_FFFFL, "local identifier"),
                    randomDceClockSequence(),
                    randomNode());
            case 3 -> generateV3(readNamespace(), readNameBytes());
            case 4 -> UUIDs.v4(randomLong(), randomLong());
            case 5 -> generateV5(readNamespace(), readNameBytes());
            case 6 -> UUIDs.v6(currentGregorianTimestamp(), randomClockSequence(), randomNode());
            case 7 -> UUIDs.v7(
                    currentEpochMillis(),
                    randomInt() & RAND_A_MASK,
                    randomLong() & RAND_B_MASK);
            case 8 -> UUIDs.v8(randomLong(), randomLong());
            default -> throw new IllegalArgumentException("Unsupported UUID version: " + version);
        };
    }

    /// Renders the detailed description for the selected UUID version.
    ///
    /// @param version the selected UUID version
    private static void renderVersionDetails(int version) {
        VersionDetails details = versionDetails(version);
        setText("version-detail-title", details.title());
        setText("version-detail-kind", details.kind());
        setText("version-detail-text", details.text());
    }

    /// Returns the detailed description for a UUID version.
    ///
    /// @param version the selected UUID version
    /// @return the version details
    private static VersionDetails versionDetails(int version) {
        return switch (version) {
            case 1 -> new VersionDetails(
                    "Version 1",
                    "Time-based legacy UUID",
                    "Version 1 combines the current Gregorian timestamp with a clock sequence and a random multicast "
                            + "node identifier. "
                            + "Use when a legacy protocol expects version-1 UUIDs. Prefer version 7 for new "
                            + "time-ordered IDs.");
            case 2 -> new VersionDetails(
                    "Version 2",
                    "DCE Security UUID",
                    "Version 2 is a legacy DCE Security layout that embeds a local domain and local identifier. "
                            + "Use only for systems that explicitly require DCE person, group, or organization "
                            + "identifiers.");
            case 3 -> new VersionDetails(
                    "Version 3",
                    "MD5 name-based UUID",
                    "Version 3 hashes a namespace UUID and UTF-8 name with MD5 to produce a deterministic UUID. "
                            + "Use for compatibility with existing version-3 data. Prefer version 5 for new "
                            + "name-based IDs.");
            case 4 -> new VersionDetails(
                    "Version 4",
                    "Random UUID",
                    "Version 4 uses 122 random payload bits and does not encode time, names, or application fields. "
                            + "Use for opaque identifiers when chronological ordering is not needed.");
            case 5 -> new VersionDetails(
                    "Version 5",
                    "SHA-1 name-based UUID",
                    "Version 5 hashes a namespace UUID and UTF-8 name with SHA-1 to produce a deterministic UUID. "
                            + "Use when the same namespace and name must always produce the same UUID.");
            case 6 -> new VersionDetails(
                    "Version 6",
                    "Sortable legacy time UUID",
                    "Version 6 stores the same timestamp, clock sequence, and node data as version 1 in sortable "
                            + "order. Use for interoperability with version-6 systems. Prefer version 7 for new "
                            + "sortable IDs.");
            case 7 -> new VersionDetails(
                    "Version 7",
                    "Time-ordered UUID",
                    "Version 7 combines a Unix millisecond timestamp with random payload bits. "
                            + "Use for new database keys, event IDs, and other identifiers that benefit from "
                            + "chronological sorting.");
            case 8 -> new VersionDetails(
                    "Version 8",
                    "Custom payload UUID",
                    "Version 8 reserves the version and variant bits while leaving the remaining payload to the "
                            + "application. Use when an application has a documented custom UUID layout. This demo "
                            + "fills the payload randomly.");
            default -> throw new IllegalArgumentException("Unsupported UUID version: " + version);
        };
    }

    /// Parses the source input and renders it as the active UUID.
    private static void parseInput() {
        String input = readValue("parse-input").trim();
        if (input.isEmpty()) {
            clearActiveUUID();
            setState("source-panel", "idle");
            setText("source-status", "Waiting");
            setText("source-error", "");
            return;
        }

        try {
            UUID uuid = parseInputUUID(input);
            acceptUUID(uuid, "Parsed");
        } catch (RuntimeException e) {
            rejectSource("Rejected", e);
        }
    }

    /// Parses the parser panel input according to the selected format.
    ///
    /// @param input the input text
    /// @return the parsed UUID
    private static UUID parseInputUUID(String input) {
        String format = readValue("parse-format-select");
        return "base62".equals(format) ? UUIDs.parseBase62(input) : UUIDs.parse(input);
    }

    /// Copies the active UUID string to the system clipboard through JavaScript.
    private static void copyActiveUUIDToClipboard() {
        UUID uuid = currentUUID;
        if (uuid != null) {
            copyToClipboard(uuid.toString());
        }
    }

    /// Accepts a UUID as the active source value.
    ///
    /// @param uuid the UUID to display
    /// @param status the source status text
    private static void acceptUUID(UUID uuid, String status) {
        currentUUID = uuid;
        setState("source-panel", "ok");
        setText("source-status", status);
        setText("source-error", "");
        setText("active-standard", uuid.toString());
        renderUUID(uuid);
    }

    /// Rejects the current source value after a generation or parse failure.
    ///
    /// @param status the source status text
    /// @param exception the failure to display
    private static void rejectSource(String status, RuntimeException exception) {
        clearActiveUUID();
        setState("source-panel", "error");
        setText("source-status", status);
        setText("source-error", exception.toString());
    }

    /// Clears the active UUID and all dependent derived fields.
    private static void clearActiveUUID() {
        currentUUID = null;
        setText("active-standard", "");
        setState("inspector-panel", "idle");
        setText("inspect-status", "Waiting");
        clearFields(INSPECTOR_FIELD_IDS);
    }

    /// Renders all derived fields for the active UUID.
    ///
    /// @param uuid the UUID to inspect
    private static void renderUUID(UUID uuid) {
        setState("inspector-panel", "ok");
        setText("inspect-status", "Ready");
        setField("field-standard", uuid.toString(), "value");
        setField("field-base64", toBase64String(uuid), "value");
        setField("field-oid", toOIDString(uuid), "value");
        setField("field-bytes", bytesToHex(uuid), "value");
        setField("field-msb", "0x" + lowerHex(uuid.getMostSignificantBits(), 16), "value");
        setField("field-lsb", "0x" + lowerHex(uuid.getLeastSignificantBits(), 16), "value");
        setField("field-version", Integer.toString(uuid.version()), "value");
        setField("field-variant", Integer.toString(uuid.variant()), "value");
        renderTimeFields(uuid);
        renderClockFields(uuid);
        renderDceFields(uuid);
        renderV7Fields(uuid);
    }

    /// Renders timestamp fields when the UUID version carries a timestamp.
    ///
    /// @param uuid the UUID to inspect
    private static void renderTimeFields(UUID uuid) {
        int version = uuid.version();
        if (version == 1 || version == 2 || version == 6 || version == 7) {
            setField("field-instant", UUIDs.getInstant(uuid).toString(), "value");
            setField("field-time-unix", Long.toString(UUIDs.getUnixTimestampMillis(uuid)), "value");
            setField("field-time-gregorian", Long.toString(UUIDs.getGregorianTimestamp(uuid)), "value");
        } else {
            setUnavailableField("field-instant");
            setUnavailableField("field-time-unix");
            setUnavailableField("field-time-gregorian");
        }
    }

    /// Renders clock sequence and node fields for time-based layouts.
    ///
    /// @param uuid the UUID to inspect
    private static void renderClockFields(UUID uuid) {
        int version = uuid.version();
        if (version == 1 || version == 2 || version == 6) {
            setField("field-clock-sequence", Integer.toString(UUIDs.getClockSequence(uuid)), "value");
            setField("field-node", "0x" + lowerHex(UUIDs.getNode(uuid), 12), "value");
        } else {
            setUnavailableField("field-clock-sequence");
            setUnavailableField("field-node");
        }
    }

    /// Renders DCE Security fields for version-2 UUIDs.
    ///
    /// @param uuid the UUID to inspect
    private static void renderDceFields(UUID uuid) {
        if (uuid.version() == 2) {
            setField("field-dce-domain", Integer.toString(UUIDs.getDceLocalDomain(uuid)), "value");
            setField("field-dce-local-id", Long.toString(UUIDs.getDceLocalIdentifier(uuid)), "value");
        } else {
            setUnavailableField("field-dce-domain");
            setUnavailableField("field-dce-local-id");
        }
    }

    /// Renders UUID version-7 random payload fields.
    ///
    /// @param uuid the UUID to inspect
    private static void renderV7Fields(UUID uuid) {
        if (uuid.version() == 7) {
            setField("field-rand-a", Integer.toString(UUIDs.getV7RandA(uuid)), "value");
            setField("field-rand-b", Long.toString(UUIDs.getV7RandB(uuid)), "value");
        } else {
            setUnavailableField("field-rand-a");
            setUnavailableField("field-rand-b");
        }
    }

    /// Reads the namespace combo box value for version-3 and version-5 UUID generation.
    ///
    /// @return the namespace UUID, or `null` for no namespace
    private static @Nullable UUID readNamespace() {
        String selected = readValue("namespace-select");
        return switch (selected) {
            case "none" -> null;
            case "dns" -> UUIDs.NAMESPACE_DNS;
            case "url" -> UUIDs.NAMESPACE_URL;
            case "oid" -> UUIDs.NAMESPACE_OID;
            case "x500" -> UUIDs.NAMESPACE_X500;
            case "custom" -> UUIDs.parse(readValue("namespace-input").trim());
            default -> throw new IllegalArgumentException("Unknown namespace: " + selected);
        };
    }

    /// Reads the name input as UTF-8 bytes.
    ///
    /// @return UTF-8 encoded name bytes
    private static byte[] readNameBytes() {
        return readValue("name-input").getBytes(StandardCharsets.UTF_8);
    }

    /// Generates a version-3 UUID from a namespace and UTF-8 name bytes.
    ///
    /// @param namespace the namespace UUID, or `null` for no namespace
    /// @param name the name bytes
    /// @return the generated UUID
    private static UUID generateV3(@Nullable UUID namespace, byte[] name) {
        MessageDigest digest = getDigest("MD5");
        feedNamespace(digest, namespace);
        digest.update(name);
        return UUIDs.v3(digest.digest());
    }

    /// Generates a version-5 UUID from a namespace and UTF-8 name bytes.
    ///
    /// @param namespace the namespace UUID, or `null` for no namespace
    /// @param name the name bytes
    /// @return the generated UUID
    private static UUID generateV5(@Nullable UUID namespace, byte[] name) {
        MessageDigest digest = getDigest("SHA-1");
        feedNamespace(digest, namespace);
        digest.update(name);
        return UUIDs.v5(digest.digest());
    }

    /// Feeds namespace UUID bytes into a digest.
    ///
    /// @param digest the target digest
    /// @param namespace the namespace UUID, or `null` for no namespace
    private static void feedNamespace(MessageDigest digest, @Nullable UUID namespace) {
        if (namespace != null) {
            byte[] bytes = new byte[UUID_BYTE_LENGTH];
            writeLongBigEndian(bytes, 0, namespace.getMostSignificantBits());
            writeLongBigEndian(bytes, 8, namespace.getLeastSignificantBits());
            digest.update(bytes);
        }
    }

    /// Returns a message digest for a required algorithm.
    ///
    /// @param algorithm the digest algorithm name
    /// @return the message digest
    private static MessageDigest getDigest(String algorithm) {
        try {
            return MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new InternalError("Missing algorithm: " + algorithm, e);
        }
    }

    /// Reads a required integer form value.
    ///
    /// @param id the element id
    /// @param label the field label for error messages
    /// @return the parsed integer
    private static int parseIntValue(String id, String label) {
        try {
            return Integer.parseInt(readValue(id).trim());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid " + label + ": " + readValue(id), e);
        }
    }

    /// Reads a required unsigned integer-like value with a maximum.
    ///
    /// @param id the element id
    /// @param max the inclusive maximum value
    /// @param label the field label for error messages
    /// @return the parsed value
    private static long parseUnsignedValue(String id, long max, String label) {
        String text = readValue(id).trim();
        return parseUnsignedText(text, max, label);
    }

    /// Parses an unsigned decimal or `0x`-prefixed hexadecimal value.
    ///
    /// @param text the value text
    /// @param max the inclusive maximum value
    /// @param label the field label for error messages
    /// @return the parsed value
    private static long parseUnsignedText(String text, long max, String label) {
        if (text.isEmpty()) {
            throw new IllegalArgumentException("Missing " + label);
        }

        int radix = 10;
        int offset = 0;
        if (text.startsWith("0x") || text.startsWith("0X")) {
            radix = 16;
            offset = 2;
        }

        long value = 0;
        for (int i = offset; i < text.length(); i++) {
            int digit = Character.digit(text.charAt(i), radix);
            if (digit < 0) {
                throw new IllegalArgumentException("Invalid " + label + ": " + text);
            }
            if (value > (max - digit) / radix) {
                throw new IllegalArgumentException(label + " must be in [0, " + max + "]");
            }
            value = value * radix + digit;
        }
        return value;
    }

    /// Returns the current Unix epoch millisecond timestamp.
    ///
    /// @return the current Unix epoch millisecond timestamp
    private static long currentEpochMillis() {
        return currentTimeMillis();
    }

    /// Returns the current Gregorian 100-nanosecond timestamp.
    ///
    /// @return the current Gregorian timestamp
    private static long currentGregorianTimestamp() {
        return GREGORIAN_OFFSET + currentEpochMillis() * GREGORIAN_TICKS_PER_MILLI;
    }

    /// Generates a random 14-bit clock sequence.
    ///
    /// @return the clock sequence
    private static int randomClockSequence() {
        return randomInt() & CLOCK_SEQUENCE_MASK;
    }

    /// Generates a random 6-bit DCE Security clock sequence.
    ///
    /// @return the DCE Security clock sequence
    private static int randomDceClockSequence() {
        return randomInt() & DCE_CLOCK_SEQUENCE_MASK;
    }

    /// Generates a random multicast node identifier.
    ///
    /// @return the node identifier
    private static long randomNode() {
        return (randomLong() & NODE_MASK) | RANDOM_NODE_MULTICAST_MASK;
    }

    /// Generates a random 64-bit value from the browser JavaScript engine.
    ///
    /// @return the random value
    private static long randomLong() {
        return ((long) randomInt() << 32) ^ (randomInt() & 0xFFFF_FFFFL);
    }

    /// Formats the UUID as sixteen big-endian bytes.
    ///
    /// @param uuid the UUID to format
    /// @return the lowercase hexadecimal byte sequence
    private static String bytesToHex(UUID uuid) {
        StringBuilder out = new StringBuilder(UUID_BYTE_LENGTH * 3 - 1);
        appendLongBytes(out, uuid.getMostSignificantBits());
        appendLongBytes(out, uuid.getLeastSignificantBits());
        return out.toString();
    }

    /// Formats a UUID as an OID under the `2.25` arc.
    ///
    /// @param uuid the UUID to format
    /// @return the OID string
    private static String toOIDString(UUID uuid) {
        byte[] bytes = new byte[UUID_BYTE_LENGTH + 1];
        writeLongBigEndian(bytes, 1, uuid.getMostSignificantBits());
        writeLongBigEndian(bytes, 9, uuid.getLeastSignificantBits());
        return "2.25." + new BigInteger(bytes);
    }

    /// Formats a UUID as standard Base64 over the sixteen UUID bytes.
    ///
    /// @param uuid the UUID to format
    /// @return the Base64 string
    private static String toBase64String(UUID uuid) {
        byte[] bytes = new byte[UUID_BYTE_LENGTH];
        writeLongBigEndian(bytes, 0, uuid.getMostSignificantBits());
        writeLongBigEndian(bytes, 8, uuid.getLeastSignificantBits());

        StringBuilder out = new StringBuilder(24);
        for (int offset = 0; offset < UUID_BYTE_LENGTH - 1; offset += 3) {
            appendBase64Triple(out, bytes[offset] & 0xFF, bytes[offset + 1] & 0xFF, bytes[offset + 2] & 0xFF);
        }

        int last = bytes[UUID_BYTE_LENGTH - 1] & 0xFF;
        out.append(BASE64_CHARS.charAt(last >>> 2));
        out.append(BASE64_CHARS.charAt((last & 0x03) << 4));
        out.append("==");
        return out.toString();
    }

    /// Appends a three-byte Base64 group.
    ///
    /// @param out the output builder
    /// @param first the first unsigned byte
    /// @param second the second unsigned byte
    /// @param third the third unsigned byte
    private static void appendBase64Triple(StringBuilder out, int first, int second, int third) {
        out.append(BASE64_CHARS.charAt(first >>> 2));
        out.append(BASE64_CHARS.charAt(((first & 0x03) << 4) | (second >>> 4)));
        out.append(BASE64_CHARS.charAt(((second & 0x0F) << 2) | (third >>> 6)));
        out.append(BASE64_CHARS.charAt(third & 0x3F));
    }

    /// Writes a long value as eight big-endian bytes.
    ///
    /// @param bytes the destination bytes
    /// @param offset the destination offset
    /// @param value the value to write
    private static void writeLongBigEndian(byte[] bytes, int offset, long value) {
        for (int i = 7; i >= 0; i--) {
            bytes[offset + i] = (byte) value;
            value >>>= Byte.SIZE;
        }
    }

    /// Appends a long value as eight big-endian bytes.
    ///
    /// @param out the output builder
    /// @param value the value to append
    private static void appendLongBytes(StringBuilder out, long value) {
        for (int shift = 56; shift >= 0; shift -= 8) {
            if (out.length() > 0) {
                out.append(' ');
            }
            appendHexByte(out, (int) (value >>> shift));
        }
    }

    /// Appends the low byte of an integer as two lowercase hexadecimal digits.
    ///
    /// @param out the output builder
    /// @param value the byte value
    private static void appendHexByte(StringBuilder out, int value) {
        out.append(Character.forDigit((value >>> 4) & 0xF, 16));
        out.append(Character.forDigit(value & 0xF, 16));
    }

    /// Formats the low bits of a value as fixed-width lowercase hexadecimal.
    ///
    /// @param value the value to format
    /// @param digits the number of hexadecimal digits
    /// @return the fixed-width hexadecimal text
    private static String lowerHex(long value, int digits) {
        String hex = Long.toHexString(value);
        if (hex.length() >= digits) {
            return hex.substring(hex.length() - digits);
        }

        StringBuilder out = new StringBuilder(digits);
        for (int i = hex.length(); i < digits; i++) {
            out.append('0');
        }
        out.append(hex);
        return out.toString();
    }

    /// Hides a field that is unavailable for the active UUID version.
    ///
    /// @param id the field element id
    private static void setUnavailableField(String id) {
        setField(id, "", "hidden");
    }

    /// Clears a list of result fields.
    ///
    /// @param fieldIds the HTML ids to clear
    private static void clearFields(String @Unmodifiable [] fieldIds) {
        for (String fieldId : fieldIds) {
            clearField(fieldId);
        }
    }

    /// Reads an input, select, or textarea value from the page.
    ///
    /// @param id the element id
    /// @return the element value, or the empty string when the element is missing
    @JSBody(params = {"id"}, script = "var e = document.getElementById(id); return e ? e.value : '';")
    private static native String readValue(String id);

    /// Sets an element's text content.
    ///
    /// @param id the element id
    /// @param value the text value
    @JSBody(params = {"id", "value"}, script = "window.UUIDToolsDemo.setText(id, value);")
    private static native void setText(String id, String value);

    /// Sets a field value and semantic state.
    ///
    /// @param id the element id
    /// @param value the display value
    /// @param state the field state
    @JSBody(params = {"id", "value", "state"}, script = "window.UUIDToolsDemo.setField(id, value, state);")
    private static native void setField(String id, String value, String state);

    /// Clears a field value and state.
    ///
    /// @param id the element id
    @JSBody(params = {"id"}, script = "window.UUIDToolsDemo.clearField(id);")
    private static native void clearField(String id);

    /// Sets an element state attribute used by CSS.
    ///
    /// @param id the element id
    /// @param state the state value
    @JSBody(params = {"id", "state"}, script = "window.UUIDToolsDemo.setState(id, state);")
    private static native void setState(String id, String state);

    /// Sets the selected UUID version on the document root.
    ///
    /// @param version the selected UUID version
    @JSBody(params = {"version"}, script = "document.documentElement.dataset.version = String(version);")
    private static native void setDocumentVersion(int version);

    /// Sets the selected namespace mode on the document root.
    ///
    /// @param namespace the selected namespace mode
    @JSBody(params = {"namespace"}, script = "document.documentElement.dataset.namespace = String(namespace);")
    private static native void setDocumentNamespace(String namespace);

    /// Sets the active source mode on the document root.
    ///
    /// @param source the active source mode
    @JSBody(params = {"source"}, script = "window.UUIDToolsDemo.setSourceMode(source);")
    private static native void setDocumentSource(String source);

    /// Copies text to the system clipboard when the browser allows it.
    ///
    /// @param text the text to copy
    @JSBody(params = {"text"}, script = "window.UUIDToolsDemo.copyToClipboard(text);")
    private static native void copyToClipboard(String text);

    /// Returns the current Unix epoch millisecond timestamp from JavaScript.
    ///
    /// @return the current Unix epoch millisecond timestamp
    @JSBody(script = "return BigInt(Date.now());")
    private static native long currentTimeMillis();

    /// Returns a random signed 32-bit value from JavaScript.
    ///
    /// @return the random value
    @JSBody(script = "return (Math.random() * 0x100000000) | 0;")
    private static native int randomInt();

    /// Registers live update listeners on a form control.
    ///
    /// @param id the element id
    /// @param listener the listener to call after the control changes
    @JSBody(params = {"id", "listener"}, script = ""
            + "var e = document.getElementById(id);"
            + "if (e) {"
            + "  e.addEventListener('input', function () { listener(); });"
            + "  e.addEventListener('change', function () { listener(); });"
            + "}")
    private static native void addLiveUpdateListener(String id, UpdateListener listener);

    /// Registers a click listener on a button.
    ///
    /// @param id the element id
    /// @param listener the listener to call after the button is clicked
    @JSBody(params = {"id", "listener"}, script = ""
            + "var e = document.getElementById(id);"
            + "if (e) {"
            + "  e.addEventListener('click', function () { listener(); });"
            + "}")
    private static native void addClickListener(String id, UpdateListener listener);

    /// Java function type passed to JavaScript as an event callback.
    @JSFunctor
    @NotNullByDefault
    private interface UpdateListener extends JSObject {
        /// Handles a browser event.
        void handle();
    }
}
