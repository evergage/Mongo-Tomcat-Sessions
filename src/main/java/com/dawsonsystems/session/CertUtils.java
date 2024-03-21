/*
 * Copyright (C) 2010-2023 Evergage, Inc.
 * All rights reserved.
 */

package com.dawsonsystems.session;

import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import static org.bouncycastle.util.encoders.Hex.toHexString;
import static com.google.common.base.Preconditions.checkArgument;

/**
 * Utility class for misc certificate/key operations
 */
public class CertUtils {

    // Compares the SHA-1 over the modulus within the public and private key. The modulus should be unique for each pair
    public static boolean checkClientCertAndPrivateKeyMatch(X509Certificate cert, PrivateKey privateKey) {
        checkArgument(cert != null, "Certificate cannot be null");
        checkArgument(privateKey != null, "Private key cannot be null");

        try {
            final PublicKey publicKey = cert.getPublicKey();
            if (!(publicKey instanceof RSAPublicKey)) {
                throw new IllegalArgumentException("Certificate file does not contain an RSA public key but a " + publicKey.getClass().getName());
            }
            final RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
            final byte[] certModulusData = rsaPublicKey.getModulus().toByteArray();

            final MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            final byte[] certID = sha1.digest(certModulusData);
            final String certIDinHex = toHexString(certID);

            if (!(privateKey instanceof RSAPrivateKey)) {
                throw new IllegalArgumentException("Key file does not contain an X509 encoded private key");
            }

            final RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) privateKey;
            final byte[] keyModulusData = rsaPrivateKey.getModulus().toByteArray();
            final byte[] keyID = sha1.digest(keyModulusData);
            final String keyIDinHex = toHexString(keyID);

            return certIDinHex.equalsIgnoreCase(keyIDinHex);
        } catch (Exception e) {
            throw new RuntimeException("Failed to compare client private key and certificate", e);
        }
    }

}
