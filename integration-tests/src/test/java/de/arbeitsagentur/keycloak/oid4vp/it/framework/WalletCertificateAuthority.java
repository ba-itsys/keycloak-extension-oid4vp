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
package de.arbeitsagentur.keycloak.oid4vp.it.framework;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.EnumSet;

/**
 * Certificate authority shared by all test wallets. A wallet loads its CA from
 * {@code ~/.eudi-dev/wallet-ca-key.pem} and {@code wallet-ca-cert.pem} when those files are
 * present, so seeding them gives every container the same CA and the trust the Keycloak test server
 * puts in it via {@code truststore-paths} survives wallet restarts.
 */
final class WalletCertificateAuthority {

    private static final WalletCertificateAuthority INSTANCE = new WalletCertificateAuthority();

    private final String caKeyPem;
    private final String caCertPem;
    private final Path caCertPemFile;

    private WalletCertificateAuthority() {
        try {
            KeyPair caKeyPair = TestCertificates.generateEcKeyPair();
            X509Certificate caCert = TestCertificates.generateCaCert(caKeyPair);
            caKeyPem =
                    TestCertificates.toPem("PRIVATE KEY", caKeyPair.getPrivate().getEncoded()) + "\n";
            caCertPem = TestCertificates.toPem("CERTIFICATE", caCert.getEncoded()) + "\n";

            caCertPemFile = Files.createTempFile("oid4vp-wallet-ca-", ".pem");
            Files.writeString(caCertPemFile, caCertPem);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to create wallet certificate authority", e);
        }
    }

    static WalletCertificateAuthority instance() {
        return INSTANCE;
    }

    Path caCertPemPath() {
        return caCertPemFile;
    }

    Path createSeededWalletStateDir() {
        try {
            Path stateDir = Files.createTempDirectory("oid4vp-wallet-state-");
            // The wallet container runs as a non-root user and writes its store into this directory.
            setPermissions(stateDir, EnumSet.allOf(PosixFilePermission.class));
            Path keyFile = Files.writeString(stateDir.resolve("wallet-ca-key.pem"), caKeyPem);
            Path certFile = Files.writeString(stateDir.resolve("wallet-ca-cert.pem"), caCertPem);
            EnumSet<PosixFilePermission> filePermissions = EnumSet.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE,
                    PosixFilePermission.GROUP_READ,
                    PosixFilePermission.OTHERS_READ);
            setPermissions(keyFile, filePermissions);
            setPermissions(certFile, filePermissions);
            return stateDir;
        } catch (IOException e) {
            throw new IllegalStateException("Failed to create seeded wallet state directory", e);
        }
    }

    private static void setPermissions(Path path, EnumSet<PosixFilePermission> permissions) {
        try {
            Files.setPosixFilePermissions(path, permissions);
        } catch (UnsupportedOperationException | IOException ignored) {
            // Non-POSIX filesystems do not support chmod here.
        }
    }
}
