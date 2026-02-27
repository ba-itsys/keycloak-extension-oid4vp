/*
 * Copyright 2026 Bundesagentur für Arbeit
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.arbeitsagentur.keycloak.oid4vp;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import java.io.ByteArrayOutputStream;
import java.util.Base64;
import java.util.Map;

public class Oid4vpQrCodeService {

    public String generateQrCode(String content, int width, int height) {
        try {
            QRCodeWriter writer = new QRCodeWriter();
            BitMatrix matrix =
                    writer.encode(content, BarcodeFormat.QR_CODE, width, height, Map.of(EncodeHintType.MARGIN, 1));

            ByteArrayOutputStream pngOut = new ByteArrayOutputStream();
            writePng(pngOut, matrix);
            return Base64.getEncoder().encodeToString(pngOut.toByteArray());
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate QR code", e);
        }
    }

    private void writePng(ByteArrayOutputStream out, BitMatrix matrix) throws Exception {
        int width = matrix.getWidth();
        int height = matrix.getHeight();

        // Minimal PNG writer to avoid javax.imageio dependency (not available in Keycloak)
        int rowBytes = 1 + width; // filter byte + 1 byte per pixel (grayscale)
        byte[] rawData = new byte[height * rowBytes];
        for (int y = 0; y < height; y++) {
            int offset = y * rowBytes;
            rawData[offset] = 0; // filter: none
            for (int x = 0; x < width; x++) {
                rawData[offset + 1 + x] = matrix.get(x, y) ? (byte) 0 : (byte) 255;
            }
        }

        byte[] compressed = deflate(rawData);

        // PNG signature
        out.write(new byte[] {(byte) 137, 80, 78, 71, 13, 10, 26, 10});

        // IHDR
        writeChunk(
                out,
                "IHDR",
                concat(
                        intToBytes(width), intToBytes(height), new byte[] {8, 0, 0, 0, 0} // 8-bit grayscale
                        ));

        // IDAT
        writeChunk(out, "IDAT", compressed);

        // IEND
        writeChunk(out, "IEND", new byte[0]);
    }

    private byte[] deflate(byte[] data) throws Exception {
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        java.util.zip.DeflaterOutputStream deflater = new java.util.zip.DeflaterOutputStream(bout);
        deflater.write(data);
        deflater.finish();
        deflater.close();
        return bout.toByteArray();
    }

    private void writeChunk(ByteArrayOutputStream out, String type, byte[] data) throws Exception {
        byte[] typeBytes = type.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        out.write(intToBytes(data.length));
        byte[] typeAndData = concat(typeBytes, data);
        out.write(typeAndData);
        java.util.zip.CRC32 crc = new java.util.zip.CRC32();
        crc.update(typeAndData);
        out.write(intToBytes((int) crc.getValue()));
    }

    private byte[] intToBytes(int value) {
        return new byte[] {(byte) (value >> 24), (byte) (value >> 16), (byte) (value >> 8), (byte) value};
    }

    private byte[] concat(byte[]... arrays) {
        int total = 0;
        for (byte[] a : arrays) total += a.length;
        byte[] result = new byte[total];
        int pos = 0;
        for (byte[] a : arrays) {
            System.arraycopy(a, 0, result, pos, a.length);
            pos += a.length;
        }
        return result;
    }
}
