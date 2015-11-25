/************************************************************************
 * Copyright (c) Crater Dog Technologies(TM).  All Rights Reserved.     *
 ************************************************************************
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.        *
 *                                                                      *
 * This code is free software; you can redistribute it and/or modify it *
 * under the terms of The MIT License (MIT), as published by the Open   *
 * Source Initiative. (See http://opensource.org/licenses/MIT)          *
 ************************************************************************/
package craterdog.security;

import craterdog.utils.Base64Utils;
import craterdog.utils.RandomUtils;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import org.slf4j.ext.XLogger;
import org.slf4j.ext.XLoggerFactory;


/**
 * This class provides methods that hide the complexities of the Java security API in dealing
 * with certificate management.
 *
 * @author Derk Norton
 */
public abstract class CertificateManager {

    static final XLogger logger = XLoggerFactory.getXLogger(CertificateManager.class);

    static private final String KEY_STORE_FORMAT = "PKCS12";

    /**
     * This method returns the asymmetric key type string.
     *
     * @return The asymmetric key type string.
     */
    public abstract String getAsymmetricKeyType();


    /**
     * This method returns the asymmetric key size.
     *
     * @return The asymmetric key size.
     */
    public abstract int getAsymmetricalKeySize();


    /**
     * This method returns the hash algorithm.
     *
     * @return The hash algorithm.
     */
    public abstract String getHashAlgorithm();


    /**
     * This method returns the asymmetric signature algorithm.
     *
     * @return The asymmetric signature algorithm.
     */
    public abstract String getAsymmetricSignatureAlgorithm();


    /**
     * This method generates a new public/private key pair.
     *
     * @return The new key pair.
     */
    public abstract KeyPair generateKeyPair();


    /**
     * This method saves a PKCS12 format key store out to an output stream.
     *
     * @param output The output stream to be written to.
     * @param keyStore The PKCS12 format key store.
     * @param password The password that should be used to encrypt the file.
     * @throws java.io.IOException Unable to save the key store to the specified output stream.
     */
    public final void saveKeyStore(OutputStream output, KeyStore keyStore, char[] password) throws IOException {
        logger.entry();
        try {
            keyStore.store(output, password);
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
            RuntimeException exception = new RuntimeException("An unexpected exception occurred while attempting to save a keystore.", e);
            logger.error(exception.toString());
            throw exception;
        }
        logger.exit();
    }


    /**
     * This method retrieves a PKCS12 format key store from an input stream.
     *
     * @param input The input stream from which to read the key store.
     * @param password The password that was used to encrypt the file.
     * @return The PKCS12 format key store.
     * @throws java.io.IOException Unable to retrieve the key store from the specified input stream.
     */
    public final KeyStore retrieveKeyStore(InputStream input, char[] password) throws IOException {
        logger.entry();
        try {
            KeyStore keyStore = KeyStore.getInstance(KEY_STORE_FORMAT);
            keyStore.load(input, password);
            logger.exit();
            return keyStore;
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
            RuntimeException exception = new RuntimeException("An unexpected exception occurred while attempting to retrieve a keystore.", e);
            logger.error(exception.toString());
            throw exception;
        }
    }


    /**
     * This method retrieves a public certificate from a key store.
     *
     * @param keyStore The key store containing the certificate.
     * @param certificateName The name (alias) of the certificate.
     * @return The X509 format public certificate.
     */
    public final X509Certificate retrieveCertificate(KeyStore keyStore, String certificateName) {
        try {
            logger.entry();
            X509Certificate certificate = (X509Certificate) keyStore.getCertificate(certificateName);
            logger.exit();
            return certificate;
        } catch (KeyStoreException e) {
            RuntimeException exception = new RuntimeException("An unexpected exception occurred while attempting to retrieve a certificate.", e);
            logger.error(exception.toString());
            throw exception;
        }
    }


    /**
     * This method retrieves a private key from a key store.
     *
     * @param keyStore The key store containing the private key.
     * @param keyName The name (alias) of the private key.
     * @param password The password used to encrypt the private key.
     * @return The decrypted private key.
     */
    public final PrivateKey retrievePrivateKey(KeyStore keyStore, String keyName, char[] password) {
        try {
            logger.entry();
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyName, password);
            logger.exit();
            return privateKey;
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            RuntimeException exception = new RuntimeException("An unexpected exception occurred while attempting to retrieve a private key.", e);
            logger.error(exception.toString());
            throw exception;
        }
    }


    public final String[] splitPrivateKey(PrivateKey key) {
        String[] result = new String[2];
        byte[] keyBytes = key.getEncoded();
        int numberOfBytes = keyBytes.length;
        byte[] randomBytes = RandomUtils.generateRandomBytes(numberOfBytes);
        byte[] xorBytes = xorByteArrays(keyBytes, randomBytes);
        result[0] = Base64Utils.encode(randomBytes);
        result[1] = Base64Utils.encode(xorBytes);
        return result;
    }


    public final PrivateKey mergePrivateKey(String[] encodedByteArrays) {
        try {
            byte[] randomBytes = Base64Utils.decode(encodedByteArrays[0]);
            byte[] xorBytes = Base64Utils.decode(encodedByteArrays[1]);
            byte[] keyBytes = xorByteArrays(randomBytes, xorBytes);
            KeyFactory factory = KeyFactory.getInstance(getAsymmetricKeyType());
            PrivateKey privateKey = factory.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
            return privateKey;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            RuntimeException exception = new RuntimeException("Attempted to merge invalid key shards");
            logger.error(exception.toString());
            throw exception;
        }
    }


    private byte[] xorByteArrays(byte[] firstArray, byte[] secondArray) {
        int numberOfBytes = firstArray.length;
        byte[] xorBytes = new byte[numberOfBytes];
        for (int i = 0; i < numberOfBytes; i++) {
            xorBytes[i] =  (byte) (0xFF & (firstArray[i] ^ secondArray[i]));
        }
        return xorBytes;
    }


    /**
     * This method creates a new self-signed X509 certificate for a new certificate authority (CA).
     *
     * @param privateKey The private key for the new certificate.
     * @param publicKey The public key that the new certificate is encoding.
     * @param subject The distinguished name for the certificate (e.g. CN=Derk Norton, O=Crater Dog Technologies).
     * @param serialNumber The unique serial number for the new certificate.
     * @param lifetime The number of milliseconds before the certificate should expire.
     * @return The new signed certificate.
     */
    public abstract X509Certificate createCertificateAuthority(PrivateKey privateKey, PublicKey publicKey,
            String subject, BigInteger serialNumber, long lifetime);


    /**
     * This method creates a new X509 certificate that is signed by a certificate authority (CA).
     *
     * @param caPrivateKey The private key for the certificate authority.
     * @param caCertificate The public certificate for the certificate authority.
     * @param publicKey The public key that the new certificate is encoding.
     * @param subject The distinguished name for the certificate (e.g. CN=Derk Norton, O=Crater Dog Technologies).
     * @param serialNumber The unique serial number for the new certificate.
     * @param lifetime The number of milliseconds before the certificate should expire.
     * @return The new signed certificate.
     */
    public abstract X509Certificate createCertificate(PrivateKey caPrivateKey, X509Certificate caCertificate,
            PublicKey publicKey, String subject, BigInteger serialNumber, long lifetime);


    /**
     * This method creates a new PKCS12 format key store containing a named private key and public certificate.
     *
     * @param keyName The name of the private key and public certificate.
     * @param password The password used to encrypt the private key.
     * @param privateKey The private key.
     * @param certificate The X509 format public certificate.
     * @return The new PKCS12 format key store.
     */
    public final KeyStore createPkcs12KeyStore(String keyName, char[] password, PrivateKey privateKey, X509Certificate certificate) {
        logger.entry();
        List<X509Certificate> certificates = new ArrayList<>();
        certificates.add(certificate);
        KeyStore keyStore = createPkcs12KeyStore(keyName, password, privateKey, certificates);
        logger.exit();
        return keyStore;
    }


    /**
     * This method creates a new PKCS12 format key store containing a named private key and public certificate chain.
     *
     * @param keyName The name of the private key and public certificate.
     * @param password The password used to encrypt the private key.
     * @param privateKey The private key.
     * @param certificates The chain of X509 format public certificates.
     * @return The new PKCS12 format key store.
     */
    public final KeyStore createPkcs12KeyStore(String keyName, char[] password, PrivateKey privateKey, List<X509Certificate> certificates) {
        try {
            logger.entry();
            X509Certificate[] chain = new X509Certificate[certificates.size()];
            chain = certificates.toArray(chain);
            KeyStore keyStore = KeyStore.getInstance(KEY_STORE_FORMAT);
            keyStore.load(null, null);
            keyStore.setKeyEntry(keyName, privateKey, password, chain);
            logger.exit();
            return keyStore;
        } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
            RuntimeException exception = new RuntimeException("An unexpected exception occurred while attempting to create a new keystore.", e);
            logger.error(exception.toString());
            throw exception;
        }
    }


    /**
     * This method encodes a public key into a PEM string.
     *
     * @param key The public key.
     * @return The corresponding PEM string.
     */
    public abstract String encodePublicKey(PublicKey key);


    /**
     * This method decodes public key from a PEM string.
     *
     * @param pem The PEM string for the public key.
     * @return The corresponding key.
     */
    public abstract PublicKey decodePublicKey(String pem);


    /**
     * This method encodes a private key into a PEM string.
     *
     * @param key The private key.
     * @param password The password to be used to encrypt the private key.
     * @return The corresponding PEM string.
     */
    public abstract String encodePrivateKey(PrivateKey key, char[] password);


    /**
     * This method decodes private key from a PEM string.
     *
     * @param pem The PEM string for the private key.
     * @param password The password to be used to decrypt the private key.
     * @return The corresponding key.
     */
    public abstract PrivateKey decodePrivateKey(String pem, char[] password);


    /**
     * This method encodes an X509 format certificate into a PEM string.
     *
     * @param certificate The X509 format certificate.
     * @return The corresponding PEM string.
     */
    public abstract String encodeCertificate(X509Certificate certificate);


    /**
     * This method decodes an X509 format certificate from a PEM string.
     *
     * @param pem The PEM string for the certificate.
     * @return The corresponding X509 format certificate.
     */
    public abstract X509Certificate decodeCertificate(String pem);


    /**
     * This method encodes a PKCS12 format key store into a base 64 string format.
     *
     * @param keyStore The PKCS12 format key store to be encoded.
     * @param password The password to be used to encrypt the byte stream.
     * @return The base 64 encoded string.
     */
    public final String encodeKeyStore(KeyStore keyStore, char[] password) {
        logger.entry();
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            keyStore.store(out, password);
            out.flush();
            byte[] bytes = out.toByteArray();
            String encodedKeyStore = Base64Utils.encode(bytes);
            logger.exit();
            return encodedKeyStore;
        } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
            RuntimeException exception = new RuntimeException("An unexpected exception occurred while attempting to encode a keystore.", e);
            logger.error(exception.toString());
            throw exception;
        }
    }


    /**
     * This method decodes a PKCS12 format key store from its encrypted byte stream.
     *
     * @param base64String The base 64 encoded, password encrypted PKCS12 byte stream.
     * @param password The password that was used to encrypt the byte stream.
     * @return The PKCS12 format key store.
     */
    public final KeyStore decodeKeyStore(String base64String, char[] password) {
        logger.entry();
        byte[] bytes = Base64Utils.decode(base64String);
        try (ByteArrayInputStream in = new ByteArrayInputStream(bytes)) {
            KeyStore keyStore = KeyStore.getInstance(KEY_STORE_FORMAT);
            keyStore.load(in, password);
            logger.exit();
            return keyStore;
        } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
            RuntimeException exception = new RuntimeException("An unexpected exception occurred while attempting to decode a keystore.", e);
            logger.error(exception.toString());
            throw exception;
        }
    }

}
