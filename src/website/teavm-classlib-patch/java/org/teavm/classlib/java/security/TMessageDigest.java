// Copyright (c) 2026 Glavo
// SPDX-License-Identifier: MPL-2.0

package org.teavm.classlib.java.security;

import org.jetbrains.annotations.NotNullByDefault;

import java.nio.ByteBuffer;

/// TeaVM classlib supplement for `java.security.MessageDigest`.
///
/// TeaVM maps `org.teavm.classlib.java.*` classes to `java.*` classes. This
/// implementation provides the MD5 and SHA-1 operations used by uuid-tools
/// name-based UUID generation.
@NotNullByDefault
public final class TMessageDigest {
    /// Internal algorithm id for MD5.
    private static final int ALGORITHM_MD5 = 1;

    /// Internal algorithm id for SHA-1.
    private static final int ALGORITHM_SHA1 = 2;

    /// MD5 initial value A.
    private static final int MD5_A = 0x67452301;

    /// MD5 initial value B.
    private static final int MD5_B = 0xEFCDAB89;

    /// MD5 initial value C.
    private static final int MD5_C = 0x98BADCFE;

    /// MD5 initial value D.
    private static final int MD5_D = 0x10325476;

    /// SHA-1 initial value H0.
    private static final int SHA1_H0 = 0x67452301;

    /// SHA-1 initial value H1.
    private static final int SHA1_H1 = 0xEFCDAB89;

    /// SHA-1 initial value H2.
    private static final int SHA1_H2 = 0x98BADCFE;

    /// SHA-1 initial value H3.
    private static final int SHA1_H3 = 0x10325476;

    /// SHA-1 initial value H4.
    private static final int SHA1_H4 = 0xC3D2E1F0;

    /// The selected algorithm id.
    private final int algorithm;

    /// Accumulated input bytes.
    private byte[] data = new byte[128];

    /// The number of accumulated bytes.
    private int size;

    /// Creates a message digest for an internal algorithm id.
    ///
    /// @param algorithm the internal algorithm id
    private TMessageDigest(int algorithm) {
        this.algorithm = algorithm;
    }

    /// Returns a message digest implementation for the requested algorithm.
    ///
    /// @param algorithm the algorithm name
    /// @return the message digest
    /// @throws TNoSuchAlgorithmException if the algorithm is not MD5 or SHA-1
    public static TMessageDigest getInstance(String algorithm) throws TNoSuchAlgorithmException {
        if ("MD5".equalsIgnoreCase(algorithm)) {
            return new TMessageDigest(ALGORITHM_MD5);
        }
        if ("SHA-1".equalsIgnoreCase(algorithm) || "SHA1".equalsIgnoreCase(algorithm)) {
            return new TMessageDigest(ALGORITHM_SHA1);
        }
        throw new TNoSuchAlgorithmException(algorithm);
    }

    /// Updates the digest with all bytes from an array.
    ///
    /// @param input the input bytes
    public void update(byte[] input) {
        update(input, 0, input.length);
    }

    /// Updates the digest with a byte-array range.
    ///
    /// @param input the input bytes
    /// @param offset the start offset
    /// @param length the number of bytes
    public void update(byte[] input, int offset, int length) {
        if (offset < 0 || length < 0 || offset > input.length - length) {
            throw new IndexOutOfBoundsException();
        }
        ensureCapacity(size + length);
        System.arraycopy(input, offset, data, size, length);
        size += length;
    }

    /// Updates the digest with all remaining bytes from a buffer.
    ///
    /// @param input the input buffer
    public void update(ByteBuffer input) {
        int length = input.remaining();
        ensureCapacity(size + length);
        while (input.hasRemaining()) {
            data[size++] = input.get();
        }
    }

    /// Completes the digest and resets this object.
    ///
    /// @return the digest bytes
    public byte[] digest() {
        byte[] input = copyInput();
        size = 0;
        return algorithm == ALGORITHM_MD5 ? md5(input) : sha1(input);
    }

    /// Ensures that the accumulation buffer can store the requested number of bytes.
    ///
    /// @param capacity the requested capacity
    private void ensureCapacity(int capacity) {
        if (capacity <= data.length) {
            return;
        }

        int newLength = data.length;
        while (newLength < capacity) {
            newLength *= 2;
        }

        byte[] newData = new byte[newLength];
        System.arraycopy(data, 0, newData, 0, size);
        data = newData;
    }

    /// Returns a copy of the accumulated input bytes.
    ///
    /// @return the copied input bytes
    private byte[] copyInput() {
        byte[] input = new byte[size];
        System.arraycopy(data, 0, input, 0, size);
        return input;
    }

    /// Computes an MD5 digest.
    ///
    /// @param input the input bytes
    /// @return the 16-byte digest
    private static byte[] md5(byte[] input) {
        byte[] padded = md5Padded(input);
        int a0 = MD5_A;
        int b0 = MD5_B;
        int c0 = MD5_C;
        int d0 = MD5_D;
        int[] words = new int[16];

        for (int offset = 0; offset < padded.length; offset += 64) {
            for (int i = 0; i < words.length; i++) {
                words[i] = littleEndianInt(padded, offset + i * 4);
            }

            int a = a0;
            int b = b0;
            int c = c0;
            int d = d0;

            for (int i = 0; i < 64; i++) {
                int f;
                int g;
                if (i < 16) {
                    f = (b & c) | (~b & d);
                    g = i;
                } else if (i < 32) {
                    f = (d & b) | (~d & c);
                    g = (5 * i + 1) & 15;
                } else if (i < 48) {
                    f = b ^ c ^ d;
                    g = (3 * i + 5) & 15;
                } else {
                    f = c ^ (b | ~d);
                    g = (7 * i) & 15;
                }

                int oldD = d;
                d = c;
                c = b;
                b += Integer.rotateLeft(a + f + md5Constant(i) + words[g], md5Shift(i));
                a = oldD;
            }

            a0 += a;
            b0 += b;
            c0 += c;
            d0 += d;
        }

        byte[] digest = new byte[16];
        writeLittleEndianInt(digest, 0, a0);
        writeLittleEndianInt(digest, 4, b0);
        writeLittleEndianInt(digest, 8, c0);
        writeLittleEndianInt(digest, 12, d0);
        return digest;
    }

    /// Returns MD5-padded input.
    ///
    /// @param input the input bytes
    /// @return the padded input
    private static byte[] md5Padded(byte[] input) {
        byte[] padded = paddedInput(input);
        long bitLength = (long) input.length << 3;
        for (int i = 0; i < 8; i++) {
            padded[padded.length - 8 + i] = (byte) (bitLength >>> (i * 8));
        }
        return padded;
    }

    /// Returns the MD5 round shift amount.
    ///
    /// @param index the operation index
    /// @return the shift amount
    private static int md5Shift(int index) {
        return switch (index >>> 4) {
            case 0 -> switch (index & 3) {
                case 0 -> 7;
                case 1 -> 12;
                case 2 -> 17;
                default -> 22;
            };
            case 1 -> switch (index & 3) {
                case 0 -> 5;
                case 1 -> 9;
                case 2 -> 14;
                default -> 20;
            };
            case 2 -> switch (index & 3) {
                case 0 -> 4;
                case 1 -> 11;
                case 2 -> 16;
                default -> 23;
            };
            default -> switch (index & 3) {
                case 0 -> 6;
                case 1 -> 10;
                case 2 -> 15;
                default -> 21;
            };
        };
    }

    /// Returns the MD5 sine-derived additive constant.
    ///
    /// @param index the operation index
    /// @return the additive constant
    private static int md5Constant(int index) {
        double value = Math.abs(Math.sin(index + 1)) * 4_294_967_296.0;
        return (int) (long) Math.floor(value);
    }

    /// Computes a SHA-1 digest.
    ///
    /// @param input the input bytes
    /// @return the 20-byte digest
    private static byte[] sha1(byte[] input) {
        byte[] padded = sha1Padded(input);
        int h0 = SHA1_H0;
        int h1 = SHA1_H1;
        int h2 = SHA1_H2;
        int h3 = SHA1_H3;
        int h4 = SHA1_H4;
        int[] words = new int[80];

        for (int offset = 0; offset < padded.length; offset += 64) {
            for (int i = 0; i < 16; i++) {
                words[i] = bigEndianInt(padded, offset + i * 4);
            }
            for (int i = 16; i < words.length; i++) {
                words[i] = Integer.rotateLeft(words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16], 1);
            }

            int a = h0;
            int b = h1;
            int c = h2;
            int d = h3;
            int e = h4;

            for (int i = 0; i < words.length; i++) {
                int f;
                int k;
                if (i < 20) {
                    f = (b & c) | (~b & d);
                    k = 0x5A827999;
                } else if (i < 40) {
                    f = b ^ c ^ d;
                    k = 0x6ED9EBA1;
                } else if (i < 60) {
                    f = (b & c) | (b & d) | (c & d);
                    k = 0x8F1BBCDC;
                } else {
                    f = b ^ c ^ d;
                    k = 0xCA62C1D6;
                }

                int temp = Integer.rotateLeft(a, 5) + f + e + k + words[i];
                e = d;
                d = c;
                c = Integer.rotateLeft(b, 30);
                b = a;
                a = temp;
            }

            h0 += a;
            h1 += b;
            h2 += c;
            h3 += d;
            h4 += e;
        }

        byte[] digest = new byte[20];
        writeBigEndianInt(digest, 0, h0);
        writeBigEndianInt(digest, 4, h1);
        writeBigEndianInt(digest, 8, h2);
        writeBigEndianInt(digest, 12, h3);
        writeBigEndianInt(digest, 16, h4);
        return digest;
    }

    /// Returns SHA-1-padded input.
    ///
    /// @param input the input bytes
    /// @return the padded input
    private static byte[] sha1Padded(byte[] input) {
        byte[] padded = paddedInput(input);
        long bitLength = (long) input.length << 3;
        for (int i = 0; i < 8; i++) {
            padded[padded.length - 1 - i] = (byte) (bitLength >>> (i * 8));
        }
        return padded;
    }

    /// Creates a padded input buffer with the one-bit delimiter.
    ///
    /// @param input the input bytes
    /// @return the padded input
    private static byte[] paddedInput(byte[] input) {
        int paddedLength = ((input.length + 8) / 64 + 1) * 64;
        byte[] padded = new byte[paddedLength];
        System.arraycopy(input, 0, padded, 0, input.length);
        padded[input.length] = (byte) 0x80;
        return padded;
    }

    /// Reads a little-endian 32-bit word.
    ///
    /// @param input the source bytes
    /// @param offset the start offset
    /// @return the word
    private static int littleEndianInt(byte[] input, int offset) {
        return (input[offset] & 0xFF)
                | ((input[offset + 1] & 0xFF) << 8)
                | ((input[offset + 2] & 0xFF) << 16)
                | ((input[offset + 3] & 0xFF) << 24);
    }

    /// Reads a big-endian 32-bit word.
    ///
    /// @param input the source bytes
    /// @param offset the start offset
    /// @return the word
    private static int bigEndianInt(byte[] input, int offset) {
        return ((input[offset] & 0xFF) << 24)
                | ((input[offset + 1] & 0xFF) << 16)
                | ((input[offset + 2] & 0xFF) << 8)
                | (input[offset + 3] & 0xFF);
    }

    /// Writes a little-endian 32-bit word.
    ///
    /// @param output the destination bytes
    /// @param offset the start offset
    /// @param value the word
    private static void writeLittleEndianInt(byte[] output, int offset, int value) {
        output[offset] = (byte) value;
        output[offset + 1] = (byte) (value >>> 8);
        output[offset + 2] = (byte) (value >>> 16);
        output[offset + 3] = (byte) (value >>> 24);
    }

    /// Writes a big-endian 32-bit word.
    ///
    /// @param output the destination bytes
    /// @param offset the start offset
    /// @param value the word
    private static void writeBigEndianInt(byte[] output, int offset, int value) {
        output[offset] = (byte) (value >>> 24);
        output[offset + 1] = (byte) (value >>> 16);
        output[offset + 2] = (byte) (value >>> 8);
        output[offset + 3] = (byte) value;
    }
}
