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

import java.nio.charset.StandardCharsets;
import java.util.UUID;

/// TeaVM entry point for the interactive uuid-tools demo website.
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
            "rand-a-input",
            "rand-b-input",
    };

    /// HTML ids for fields that show values derived from the active UUID.
    private static final String @Unmodifiable [] INSPECTOR_FIELD_IDS = {
            "field-standard",
            "field-compact",
            "field-urn",
            "field-base62",
            "field-oid",
            "field-bytes",
            "field-msb",
            "field-lsb",
            "field-version",
            "field-variant",
            "field-time-unix",
            "field-time-gregorian",
            "field-clock-sequence",
            "field-node",
            "field-dce-domain",
            "field-dce-local-id",
            "field-rand-a",
            "field-rand-b",
    };

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
            case 3 -> UUIDs.generateV3(readNamespace(), readNameBytes());
            case 4 -> UUIDs.v4(randomLong(), randomLong());
            case 5 -> UUIDs.generateV5(readNamespace(), readValue("name-input"));
            case 6 -> UUIDs.v6(currentGregorianTimestamp(), randomClockSequence(), randomNode());
            case 7 -> UUIDs.v7(
                    currentEpochMillis(),
                    readOptionalRandA(),
                    readOptionalRandB());
            case 8 -> UUIDs.v8(randomLong(), randomLong());
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
        setField("field-compact", UUIDs.toCompactString(uuid), "value");
        setField("field-urn", UUIDs.toURNString(uuid), "value");
        setField("field-base62", UUIDs.toBase62String(uuid), "value");
        setField("field-oid", UUIDs.toOIDString(uuid), "value");
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
            setField("field-time-unix", Long.toString(UUIDs.getUnixTimestampMillis(uuid)), "value");
            setField("field-time-gregorian", Long.toString(UUIDs.getGregorianTimestamp(uuid)), "value");
        } else {
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

    /// Reads the selected namespace for version-3 and version-5 UUID generation.
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

    /// Reads an optional version-7 `rand_a` value.
    ///
    /// @return the selected or generated `rand_a` value
    private static int readOptionalRandA() {
        String text = readValue("rand-a-input").trim();
        if (text.isEmpty()) {
            return randomInt() & RAND_A_MASK;
        }
        return (int) parseUnsignedText(text, RAND_A_MASK, "rand_a");
    }

    /// Reads an optional version-7 `rand_b` value.
    ///
    /// @return the selected or generated `rand_b` value
    private static long readOptionalRandB() {
        String text = readValue("rand-b-input").trim();
        if (text.isEmpty()) {
            return randomLong() & RAND_B_MASK;
        }
        return parseUnsignedText(text, RAND_B_MASK, "rand_b");
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

    /// Marks a field as unavailable for the active UUID version.
    ///
    /// @param id the field element id
    private static void setUnavailableField(String id) {
        setField(id, "n/a", "empty");
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
