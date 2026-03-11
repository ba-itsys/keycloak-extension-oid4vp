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
package de.arbeitsagentur.keycloak.oid4vp.util;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import java.io.ByteArrayOutputStream;
import java.util.Base64;
import java.util.Map;

/**
 * Generates QR codes for the OID4VP cross-device flow.
 *
 * <p>In the cross-device flow, the verifier displays a QR code containing the wallet authorization
 * URL ({@code openid4vp://...}). The user scans the QR code with their wallet app on another device.
 *
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5">OID4VP 1.0 §5 — Authorization Request</a>
 */
public class Oid4vpQrCodeService {

    private static final int QR_CODE_MARGIN = 1;

    /** Generates a Base64-encoded PNG QR code image for the given content string. */
    public String generateQrCode(String content, int width, int height) {
        try {
            QRCodeWriter writer = new QRCodeWriter();
            BitMatrix matrix = writer.encode(
                    content, BarcodeFormat.QR_CODE, width, height, Map.of(EncodeHintType.MARGIN, QR_CODE_MARGIN));

            ByteArrayOutputStream pngOut = new ByteArrayOutputStream();
            MatrixToImageWriter.writeToStream(matrix, "png", pngOut);
            return Base64.getEncoder().encodeToString(pngOut.toByteArray());
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate QR code", e);
        }
    }
}
