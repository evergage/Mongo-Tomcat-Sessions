package com.dawsonsystems.session;

import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.mongodb.lang.Nullable;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jcajce.provider.asymmetric.util.KeyUtil;

import org.apache.commons.io.FileUtils;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.WeakHashMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


/**
 * SSLContext that uses certificates from PEM-based CA bundles and client private keys from PEM bundles.
 */
class ClientSSLUtils {

    public static final int DEFAULT_IDENTITY_CERT_RELOAD_INTERVAL_SECONDS = (int) TimeUnit.HOURS.toSeconds(6);

    private static Logger log = Logger.getLogger("ClientSSLUtils");
    private static Map<String, Map<InstantSwappableX509ExtendedKeyManager, Void>> swappableKeyManagersByIdentityPath = new ConcurrentHashMap<>();
    private static ScheduledExecutorService certReloadScheduledExecutorService;
    static {
        certReloadScheduledExecutorService = Executors.newSingleThreadScheduledExecutor(
                NameThreadFactory.daemon("identityCertRefreshExecutor")
        );
    }

//    /**
//     * Create an SSL context suitable for client authentication and using a specific trust store.
//     *
//     * @param serverTrustStorePem   path to a bundle of certificate PEMs, which will be trusted by this context
//     * @param combinedCertAndKeyPem path to a combined PEM file, containing client private key (unencrypted) and certs
//     */
//    public static SSLContext sslContextFromPEMs(File serverTrustStorePem, File combinedCertAndKeyPem) {
//        if (!serverTrustStorePem.canRead()) {
//            throw new IllegalArgumentException("Unable to read server trust store PEM: " + serverTrustStorePem);
//        }
//
//        if (!combinedCertAndKeyPem.canRead()) {
//            throw new IllegalArgumentException("Unable to read combined cert and key PEM: " + combinedCertAndKeyPem);
//        }
//
//        try {
//            KeyStore trustStore = createTrustStoreFromPEMBundle(serverTrustStorePem);
//            TrustManagerFactory trustManagerFactory =
//                    TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
//            trustManagerFactory.init(trustStore);
//
//            // Default to using PEM filename for cert key
//            String keyAlias = combinedCertAndKeyPem.getName();
//
//            KeyStore keystore = createKeyStoreFromCombinedPEM(combinedCertAndKeyPem, keyAlias);
//            KeyManagerFactory keyManagerFactory =
//                    KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
//            keyManagerFactory.init(keystore, "".toCharArray());
//
//            SSLContext sslContext = SSLContext.getInstance("TLS");
//            sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);
//            return sslContext;
//        } catch (GeneralSecurityException | IOException e) {
//            throw new IllegalArgumentException(
//                    "Failed to read certificates from combined cert and key PEM " + combinedCertAndKeyPem, e);
//        }
//    }

    protected static String createUniqueIdentityPath(String identityCertsPath, String privateKeyPemPath) {
        return identityCertsPath + "," + privateKeyPemPath;
    }

    public static boolean isIndividualClientAndPrivateKeyPEMFilesPresent() {
        String privateKeyPEMPath = fetchIdentityKeyPEMPath();
        String certPEMPath = fetchIdentityCertsPEMPath();
        if (!Strings.isNullOrEmpty(privateKeyPEMPath) &&
                !Strings.isNullOrEmpty(certPEMPath)) {
            if (!Files.isReadable(Paths.get(certPEMPath))) {
                throw new RuntimeException("Cert PEM not readable at path: " + certPEMPath);
            }
            if (!Files.isReadable(Paths.get(privateKeyPEMPath))) {
                throw new RuntimeException("Private Key PEM not readable at path: " + privateKeyPEMPath);
            }
            return true;
        }
        return false;
    }

    // TODO Either hardcode the paths here for the identity key/cert and truststore or get them from Sys properties?
    protected static String fetchIdentityKeyPEMPath() {
        return System.getProperty("keyPath");
    }

    protected static String fetchIdentityCertsPEMPath() {
        return System.getProperty("certsPath");
    }

    protected static String fetchTrustStorePath() {
        return System.getProperty("truststorePath");
    }

    // Directly looks up client private key and cert PEM files instead of the combined PEM file
    public static SSLContext createClientSSLContextFromIndividualPEMs(File certPem,
                                                                      File privateKeyPem,
                                                                      File serverTrustStorePem) throws IOException {
            String uniqueIdentityPath = createUniqueIdentityPath(certPem.getPath(), privateKeyPem.getPath());
            return createClientSSLContextFromIndividualPEMs(uniqueIdentityPath,
                                                            createByteArraySupplier(certPem),
                                                            createByteArraySupplier(privateKeyPem),
                                                            serverTrustStorePem);
    }

    /**
     * A scheduled executor swaps the KeyManager every CERT_RELOAD_INTERVAL to ensure the latest cert is loaded into
     * the KeyStore.
     *
     * If an HTTP client gets created repeatedly, we should prevent accumulation of scheduled refresh tasks.
     * To do so, we keep a map of unique file paths (concatenation of client cert and private key file names) to a
     * WeakReference map of InstantSwappableX509ExtendedKeyManager. Only KeyManagers existing in this map are periodically
     * swapped by the scheduled executor. When an SSLContext gets garbage collected, the swappable key manager that it
     * references will get garbage collected and the WeakHashMap will lose the entry for that key
     */
    private static SSLContext createClientSSLContextFromIndividualPEMs(
            String name,
            @Nullable ByteArraySupplier certPem,
            @Nullable ByteArraySupplier privateKeyPem,
            File serverTrustStorePem) {
        try {
            KeyManager[] keyManagers = null;
            KeyStore trustStore = createTrustStoreFromPEMBundle(serverTrustStorePem);
            TrustManagerFactory trustManagerFactory =
                    TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);
            SSLContext sslContext = SSLContext.getInstance("TLS");

            if (certPem != null && privateKeyPem != null) {
                Supplier<X509ExtendedKeyManager> x509ExtendedKeyManagerSupplier = () -> {
                    KeyManagerFactory keyManagerFactory;
                    try {
                        byte[] certPEMBytes = certPem.get();
                        byte[] privateKeyPEMBytes = privateKeyPem.get();
                        keyManagerFactory = createKeyStoreManagerFactoryFromIndividualPEMs(name, certPEMBytes, privateKeyPEMBytes);
                    } catch (NoSuchAlgorithmException | InvalidKeySpecException | CertificateException | IOException |
                             KeyStoreException | UnrecoverableKeyException e) {
                        throw new RuntimeException("Failed to load key store", e);
                    }
                    KeyManager keyManager = keyManagerFactory.getKeyManagers()[0];
                    Preconditions.checkState(keyManager instanceof X509ExtendedKeyManager, "Unexpected key manager type");
                    return (X509ExtendedKeyManager) keyManager;
                };

                InstantSwappableX509ExtendedKeyManager instantSwappableX509ExtendedKeyManager =
                        new InstantSwappableX509ExtendedKeyManager(x509ExtendedKeyManagerSupplier.get());

                Map<InstantSwappableX509ExtendedKeyManager, Void> keyManagersForIdentity =
                        swappableKeyManagersByIdentityPath.computeIfAbsent(name, uniqueIdentityPath -> {
                            certReloadScheduledExecutorService.scheduleAtFixedRate(() -> {
                                Map<InstantSwappableX509ExtendedKeyManager, Void> keyManagersForIdentityPath =
                                        swappableKeyManagersByIdentityPath.get(uniqueIdentityPath);
                                if (keyManagersForIdentityPath.isEmpty()) {
                                    return;
                                }
                                for (Entry<InstantSwappableX509ExtendedKeyManager, Void> entry : keyManagersForIdentityPath.entrySet()) {
                                    try {
                                        X509ExtendedKeyManager newX509ExtendedKeyManager = x509ExtendedKeyManagerSupplier.get();
                                        entry.getKey().setDelegate(newX509ExtendedKeyManager);
                                    } catch (RuntimeException e) {
                                        log.warning("Failed to dynamically refresh key manager for " + uniqueIdentityPath);
                                    }
                                }
                            }, DEFAULT_IDENTITY_CERT_RELOAD_INTERVAL_SECONDS, DEFAULT_IDENTITY_CERT_RELOAD_INTERVAL_SECONDS, TimeUnit.SECONDS);
                            log.info(String.format("Scheduled identity certificate refresh at every %s seconds for %s", DEFAULT_IDENTITY_CERT_RELOAD_INTERVAL_SECONDS, name));
                            return Collections.synchronizedMap(new WeakHashMap<>());
                        });
                keyManagersForIdentity.put(instantSwappableX509ExtendedKeyManager, null);
                keyManagers = new KeyManager[] {instantSwappableX509ExtendedKeyManager};
            }
            sslContext.init(keyManagers, trustManagerFactory.getTrustManagers(), null);
            return sslContext;
        } catch (GeneralSecurityException | IOException e) {
            throw new IllegalArgumentException(
                    String.format("Failed to create client SSL context: certPem=[%s], privateKeyPem=[%s], serverTrustStorePem=[%s].",
                                  certPem, privateKeyPem, serverTrustStorePem), e);
        }
    }

    private static KeyManagerFactory createKeyStoreManagerFactoryFromIndividualPEMs(String name, byte[] certPem, byte[] privateKey)
            throws NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException,
            InvalidKeySpecException, UnrecoverableKeyException {
        KeyStore keystore = createKeyStoreFromIndividualPEMs(name, certPem, privateKey);

        KeyManagerFactory factory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        factory.init(keystore, "".toCharArray());
        return factory;
    }

    private static KeyStore createKeyStoreFromIndividualPEMs(String name, byte[] certPem, byte[] privateKeyPem)
            throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        String certPemText = new String(certPem, StandardCharsets.UTF_8);
        X509Certificate[] clientCertificateChain = parseX509CertificatesFromPEMBundle(name, certPemText);
        X509Certificate endEntityCert = clientCertificateChain[0];

        // Ensure cert is not forward dated and not expired
        endEntityCert.checkValidity();

        String privateKeyPemText = new String(privateKeyPem, StandardCharsets.UTF_8);
        PrivateKey clientKey = parsePrivateKeyFromPEM(name, privateKeyPemText);

        if (!CertUtils.checkClientCertAndPrivateKeyMatch(endEntityCert, clientKey)) {
            throw new CertMismatchException("Client certificate and client identity key do not match");
        }

        KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(null);
        keystore.setKeyEntry(name, clientKey, "".toCharArray(), clientCertificateChain);
        return keystore;
    }

    public static class CertMismatchException extends RuntimeException {
        private CertMismatchException(String message) {
            super(message);
        }
    }

    private static ByteArraySupplier createByteArraySupplier(File pemFile) throws IOException {
        log.info(String.format("Reading input PEM file: %s, size: %s bytes",
                               pemFile.getAbsolutePath(),
                               FileUtils.sizeOf(pemFile)));
        return () -> {
            try (var fileInputStream = new FileInputStream(pemFile)) {
                return fileInputStream.readAllBytes();
            } catch (IOException e) {
                throw new RuntimeException("Failed to read file [" + pemFile + "]", e);
            }
        };
    }

    private interface ByteArraySupplier extends Supplier<byte[]> {

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

    private static PrivateKey parsePrivateKeyFromPEM(String name, String pemText) {
        Matcher keyMatcherPKCS8 =
                Pattern.compile(".*BEGIN PRIVATE KEY-+\n(.+?)\n-+END PRIVATE KEY.*", Pattern.DOTALL).
                        matcher(pemText);

        Matcher keyMatcherPKCS1 =
                Pattern.compile(".*BEGIN RSA PRIVATE KEY-+\n(.+?)\n-+END RSA PRIVATE KEY.*", Pattern.DOTALL).
                        matcher(pemText);

        if (keyMatcherPKCS8.matches()) {
            return parsePrivateKeyPKCS8(keyMatcherPKCS8.group(1), name);
        } else if (keyMatcherPKCS1.matches()) {
            return parsePrivateKeyPKCS1(keyMatcherPKCS1.group(1), name);
        } else {
            throw new IllegalArgumentException("Failed to find private key in PEM [" + name + "].");
        }
    }

    private static RSAPrivateKey parsePrivateKeyPKCS8(String key, String name) {
        try {
            byte[] keyBytes = decodeBase64(key);
            return (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse PKCS8 private key from PEM [" + name + "].", e);
        }
    }

    private static RSAPrivateKey parsePrivateKeyPKCS1(String key, String name) {
        try {
            byte[] keyBytes = decodeBase64(key);
            org.bouncycastle.asn1.pkcs.RSAPrivateKey rsaPrivateKey =
                    org.bouncycastle.asn1.pkcs.RSAPrivateKey.getInstance(keyBytes);
            byte[] privateKeyInfoBytes = KeyUtil.getEncodedPrivateKeyInfo(
                    new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE), rsaPrivateKey);
            return (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(privateKeyInfoBytes));
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse PKCS1 private key from PEM [" + name + "].", e);
        }
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

    public static X509Certificate[] parseX509CertificatesFromPEMBundle(String name, String pemText) {
        Matcher certificateMatcher =
                Pattern.
                        compile("BEGIN CERTIFICATE-+\n(.+?)\n-+END CERTIFICATE", Pattern.DOTALL).
                        matcher(pemText);

        List<X509Certificate> results = new ArrayList<>();

        while (certificateMatcher.find()) {
            String certBase64 = certificateMatcher.group(1);
            X509Certificate cert;
            try {
                byte[] bytes = decodeBase64(certBase64);
                cert = parseDERCertificate(bytes);
            } catch (CertificateException e) {
                throw new RuntimeException("Failed to parse X509 certificate from PEM [" + name + "].", e);
            }
            results.add(cert);
        }

        return results.toArray(new X509Certificate[0]);
    }

    private static byte[] decodeBase64(String str) {
        // Use MIME decoder, as it skips newline chars
        return Base64.getMimeDecoder().decode(str);
    }

    private static X509Certificate parseDERCertificate(byte[] certBytes) throws CertificateException {
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(certBytes));
    }

}


