package com.dawsonsystems.session;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


/**
 * SSLContext that uses certificates from PEM-based CA bundles and client private keys from PEM bundles.
 */
class ClientSSLFromPEMsUtility {

    /**
     * Create an SSL context suitable for client authentication and using a specific trust store.
     *
     * @param serverTrustStorePem   path to a bundle of certificate PEMs, which will be trusted by this context
     * @param combinedCertAndKeyPem path to a combined PEM file, containing client private key (unencrypted) and certs
     */
    public static SSLContext sslContextFromPEMs(File serverTrustStorePem, File combinedCertAndKeyPem) {
        if (!serverTrustStorePem.canRead()) {
            throw new IllegalArgumentException("Unable to read server trust store PEM: " + serverTrustStorePem);
        }

        if (!combinedCertAndKeyPem.canRead()) {
            throw new IllegalArgumentException("Unable to read combined cert and key PEM: " + combinedCertAndKeyPem);
        }

        try {
            KeyStore trustStore = createTrustStoreFromPEMBundle(serverTrustStorePem);
            TrustManagerFactory trustManagerFactory =
                    TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);

            // Default to using PEM filename for cert key
            String keyAlias = combinedCertAndKeyPem.getName();

            KeyStore keystore = createKeyStoreFromCombinedPEM(combinedCertAndKeyPem, keyAlias);
            KeyManagerFactory keyManagerFactory =
                    KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keystore, "".toCharArray());

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);
            return sslContext;
        } catch (GeneralSecurityException | IOException e) {
            throw new IllegalArgumentException(
                    "Failed to read certificates from combined cert and key PEM " + combinedCertAndKeyPem, e);
        }
    }

    private static KeyStore createKeyStoreFromCombinedPEM(File combinedCertAndKeyPem, String alias)
            throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException,
            InvalidKeySpecException {
        X509Certificate[] clientCertificateChain = parseX509CertificatesFromPEMBundle(combinedCertAndKeyPem);
        PrivateKey clientKey = parsePrivateKeyFromPEM(combinedCertAndKeyPem);

        KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(null);

        keystore.setKeyEntry(alias, clientKey, "".toCharArray(), clientCertificateChain);
        return keystore;
    }

    private static KeyStore createTrustStoreFromPEMBundle(File serverTrustStorePem)
            throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null, null);

        X509Certificate[] certsFromStore = parseX509CertificatesFromPEMBundle(serverTrustStorePem);
        for (int i = 0; i < certsFromStore.length; i++) {
            X509Certificate x509Certificate = certsFromStore[i];
            trustStore.setCertificateEntry("trusted_cert_" + i, x509Certificate);
        }
        return trustStore;
    }

    private static PrivateKey parsePrivateKeyFromPEM(File privateKeyPem)
            throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        String privateKeyPemText = new String(Files.readAllBytes(privateKeyPem.toPath()));

        Matcher keyMatcher = Pattern.compile(".*BEGIN PRIVATE KEY-+\n(.+?)\n-+END PRIVATE KEY.*", Pattern.DOTALL)
                .matcher(privateKeyPemText);

        if (!keyMatcher.matches()) {
            throw new IllegalArgumentException("Failed to find private key in source PEM " + privateKeyPem);
        }

        byte[] bytes = Base64.getMimeDecoder().decode(keyMatcher.group(1));
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(bytes));
    }


    private static X509Certificate[] parseX509CertificatesFromPEMBundle(File certificatePem) throws IOException,
            CertificateException {
        String certificatePemText = new String(Files.readAllBytes(certificatePem.toPath()));

        Matcher certMatcher = Pattern.compile("BEGIN CERTIFICATE-+\n(.+?)\n-+END CERTIFICATE", Pattern.DOTALL)
                .matcher(certificatePemText);

        List<X509Certificate> results = new ArrayList<>();

        while (certMatcher.find()) {
            String certBase64 = certMatcher.group(1);
            byte[] bytes = Base64.getMimeDecoder().decode(certBase64);
            results.add((X509Certificate)
                                CertificateFactory.getInstance("X.509")
                                        .generateCertificate(new ByteArrayInputStream(bytes)));
        }

        return results.toArray(new X509Certificate[0]);
    }

}


