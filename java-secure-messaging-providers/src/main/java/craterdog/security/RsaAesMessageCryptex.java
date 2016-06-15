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
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;


/**
 * This class implements the interfaces needed to do message level symmetric key encryption and
 * decryption when the sender and receiver have already exchanged their asymmetric public keys.
 * The public/private key pair are RSA based, and the symmetric key type is AES.
 *
 * @author Derk Norton
 */
public final class RsaAesMessageCryptex extends MessageCryptex {

    static private final String HASH_ALGORITHM = "SHA-256";
    static private final String PASSWORD_ENCODING_TYPE = "PBEWithSHA1AndDESede";

    static private final String SYMMETRIC_KEY_TYPE = "AES";
    static private final int SYMMETRIC_KEY_SIZE = 128;
    static private final AlgorithmParameterSpec SYMMETRIC_IV_PARAMETER = new IvParameterSpec(new byte[16]);  // all zeros
    static private final String SYMMETRIC_ENCRYPTION_ALGORITHM = SYMMETRIC_KEY_TYPE + "/CBC/PKCS5Padding";
    // NOTE: Java's PKCS5Padding implementation is actually PKCS7Padding which is a superset
    // of PKCS5Padding, but the PKCS7Padding string is not recognized by the default Java cipher
    // implementation so we have to specify PKCS5Padding above.

    static private final String ASYMMETRIC_KEY_TYPE = "RSA";
    static private final int ASYMMETRIC_KEY_SIZE = 2048;
    static private final String ASYMMETRIC_SIGNATURE_ALGORITHM = "SHA256with" + ASYMMETRIC_KEY_TYPE;
    static private final String ASYMMETRIC_ENCRYPTION_ALGORITHM = ASYMMETRIC_KEY_TYPE + "/ECB/OAEPWithSHA-256AndMGF1Padding";
    // NOTE: The mode is not used for non-block ciphers so the ECB specified above is ignored.
    // Unfortunately, Java does not support a mode value of NONE even though that would be more
    // accurately named.


    @Override
    public String getHashAlgorithm() {
        return HASH_ALGORITHM;
    }


    @Override
    public String hashString(String string) {
        try {
            logger.entry();
            byte[] bytes = (string).getBytes();
            MessageDigest hasher = MessageDigest.getInstance(HASH_ALGORITHM);
            byte[] hash = hasher.digest(bytes);
            String hashString = Base64Utils.encode(hash);
            logger.exit();
            return hashString;
        } catch (NoSuchAlgorithmException e) {
            String message = "An unexpected exception occurred while attempting to hash a string.";
            RuntimeException exception = new RuntimeException(message, e);
            logger.error(message, exception);
            throw exception;
        }
    }


    @Override
    public String getPasswordEncodingType() {
        return PASSWORD_ENCODING_TYPE;
    }


    @Override
    public String getSymmetricKeyType() {
        return SYMMETRIC_KEY_TYPE;
    }


    @Override
    public int getSymmetricKeySize() {
        return SYMMETRIC_KEY_SIZE;
    }


    @Override
    public String getSymmetricEncryptionAlgorithm() {
        return SYMMETRIC_ENCRYPTION_ALGORITHM;
    }


    @Override
    public SecretKey generateSharedKey() {
        try {
            logger.entry();
            KeyGenerator keyGenerator = KeyGenerator.getInstance(SYMMETRIC_KEY_TYPE);
            keyGenerator.init(SYMMETRIC_KEY_SIZE, RandomUtils.generator);
            SecretKey sharedKey = keyGenerator.generateKey();
            logger.exit();
            return sharedKey;
        } catch (GeneralSecurityException e) {
            String message = "An exception occured while trying to generate a shared key.";
            RuntimeException exception = new RuntimeException(message, e);
            logger.error(message, exception);
            throw exception;
        }
    }


    @Override
    public CipherOutputStream encryptionOutputStream(SecretKey sharedKey, OutputStream output)
            throws IOException {
        try {
            logger.entry();

            logger.debug("Creating and initializing the encryption engine...");
            Cipher cipher = Cipher.getInstance(SYMMETRIC_ENCRYPTION_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, sharedKey, SYMMETRIC_IV_PARAMETER);

            logger.debug("Creating a special output stream to do the work...");
            CipherOutputStream cipherOutputStream = new CipherOutputStream(output, cipher);

            logger.exit();
            return cipherOutputStream;
        } catch (GeneralSecurityException e) {
            String message = "An exception occured while trying to encrypt a stream.";
            RuntimeException exception = new RuntimeException(message, e);
            logger.error(message, exception);
            throw exception;
        }
    }


    @Override
    public CipherInputStream decryptionInputStream(SecretKey sharedKey, InputStream input)
            throws IOException {
        try {
            logger.entry();

            logger.debug("Creating and initializing the decryption engine...");
            Cipher cipher = Cipher.getInstance(SYMMETRIC_ENCRYPTION_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, sharedKey, SYMMETRIC_IV_PARAMETER);

            logger.debug("Creating a special input stream to do the work...");
            CipherInputStream cipherInputStream = new CipherInputStream(input, cipher);

            logger.exit();
            return cipherInputStream;
        } catch (GeneralSecurityException e) {
            String message = "An exception occured while trying to decrypt a stream.";
            RuntimeException exception = new RuntimeException(message, e);
            logger.error(message, exception);
            throw exception;
        }
    }


    @Override
    public String getAsymmetricKeyType() {
        return ASYMMETRIC_KEY_TYPE;
    }


    @Override
    public int getAsymmetricKeySize() {
        return ASYMMETRIC_KEY_SIZE;
    }


    @Override
    public String getAsymmetricSignatureAlgorithm() {
        return ASYMMETRIC_SIGNATURE_ALGORITHM;
    }


    @Override
    public String getAsymmetricEncryptionAlgorithm() {
        return ASYMMETRIC_ENCRYPTION_ALGORITHM;
    }


    @Override
    public KeyPair generateKeyPair() {
        try {
            logger.entry();
            KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance(ASYMMETRIC_KEY_TYPE);
            keyGenerator.initialize(ASYMMETRIC_KEY_SIZE, RandomUtils.generator);
            KeyPair keyPair = keyGenerator.generateKeyPair();
            logger.exit();
            return keyPair;
        } catch (GeneralSecurityException e) {
            String message = "An unexpected exception occurred while attempting to generate a new key pair.";
            RuntimeException exception = new RuntimeException(message, e);
            logger.error(message, exception);
            throw exception;
        }
    }


    @Override
    public String encodePublicKey(PublicKey key) {
        logger.entry();
        try {
            StringBuilder buffer = new StringBuilder();
            buffer.append("-----BEGIN PUBLIC KEY-----\n");
            buffer.append(Base64Utils.encode(key.getEncoded()));
            buffer.append("\n-----END PUBLIC KEY-----");
            String result = buffer.toString();

            logger.exit();
            return result;

        } catch (Exception e) {
            String message = "An unexpected exception occurred while attempting to encode a public key.";
            RuntimeException exception = new RuntimeException(message, e);
            logger.error(message, exception);
            throw exception;
        }
    }


    @Override
    public PublicKey decodePublicKey(String pem) {
        logger.entry();
        try {
            logger.debug("Unwrapping the PEM encoding...");
            String base64Encoded = pem
                    .replace("-----BEGIN PUBLIC KEY-----\n", "")
                    .replace("\n-----END PUBLIC KEY-----", "");
            byte[] keyBytes = Base64Utils.decode(base64Encoded);

            logger.debug("Decoding the public key...");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            KeyFactory factory = KeyFactory.getInstance(ASYMMETRIC_KEY_TYPE);
            PublicKey result = factory.generatePublic(keySpec);

            logger.exit();
            return result;

        } catch (GeneralSecurityException e) {
            String message = "An unexpected exception occurred while attempting to decode a public key.";
            RuntimeException exception = new RuntimeException(message, e);
            logger.error(message, exception);
            throw exception;
        }
    }


    @Override
    public String encodePrivateKey(PrivateKey key, char[] password) {
        logger.entry();
        try {
            logger.debug("Transforming the password into a secret key...");
            SecretKeyFactory passwordFactory = SecretKeyFactory.getInstance(PASSWORD_ENCODING_TYPE);
            PBEKeySpec passwordSpec = new PBEKeySpec(password);
            SecretKey passwordKey = passwordFactory.generateSecret(passwordSpec);

            logger.debug("Encrypting the private key using the secret key...");
            Cipher cipher = Cipher.getInstance(PASSWORD_ENCODING_TYPE);
            cipher.init(Cipher.ENCRYPT_MODE, passwordKey);
            byte[] encryptedBytes = cipher.doFinal(key.getEncoded());

            logger.debug("Encoding the encrypted bytes in PKCS8 format...");
            AlgorithmParameters params = cipher.getParameters();
	        EncryptedPrivateKeyInfo encryptedKeyInfo = new EncryptedPrivateKeyInfo(params, encryptedBytes) ;

            logger.debug("Wrapping the encrypted bytes in PEM encoding...");
            StringBuilder buffer = new StringBuilder();
            buffer.append("-----BEGIN ENCRYPTED PRIVATE KEY-----\n");
            buffer.append(Base64Utils.encode(encryptedKeyInfo.getEncoded()));
            buffer.append("\n-----END ENCRYPTED PRIVATE KEY-----");
            String result = buffer.toString();

            logger.exit();
            return result;

        } catch (IOException | GeneralSecurityException e) {
            String message = "An unexpected exception occurred while attempting to encode a private key.";
            RuntimeException exception = new RuntimeException(message, e);
            logger.error(message, exception);
            throw exception;
        }
    }


    @Override
    public PrivateKey decodePrivateKey(String pem, char[] password) {
        logger.entry();
        try {
            logger.debug("Unwrapping the PEM encoding...");
            String base64Encoded = pem
                    .replace("-----BEGIN ENCRYPTED PRIVATE KEY-----\n", "")
                    .replace("\n-----END ENCRYPTED PRIVATE KEY-----", "");
            byte[] encryptedBytes = Base64Utils.decode(base64Encoded);
	        EncryptedPrivateKeyInfo encryptedKeyInfo = new EncryptedPrivateKeyInfo(encryptedBytes) ;

            logger.debug("Transforming the password into a secret key...");
            SecretKeyFactory passwordFactory = SecretKeyFactory.getInstance(PASSWORD_ENCODING_TYPE);
            PBEKeySpec passwordSpec = new PBEKeySpec(password);
            SecretKey passwordKey = passwordFactory.generateSecret(passwordSpec);

            logger.debug("Decrypting the encrypted bytes from PKCS8 format...");
            PKCS8EncodedKeySpec pkcs8KeySpec = encryptedKeyInfo.getKeySpec(passwordKey) ;
            KeyFactory keyFactory = KeyFactory.getInstance(ASYMMETRIC_KEY_TYPE);
	        PrivateKey result = keyFactory.generatePrivate(pkcs8KeySpec);

            logger.exit();
            return result;

        } catch (IOException | GeneralSecurityException e) {
            String message = "An unexpected exception occurred while attempting to decode a private key.";
            RuntimeException exception = new RuntimeException(message, e);
            logger.error(message, exception);
            throw exception;
        }
    }


    @Override
    public byte[] signBytes(PrivateKey privateKey, byte[] bytes) {
        try {
            logger.entry();
            Signature signer = Signature.getInstance(ASYMMETRIC_SIGNATURE_ALGORITHM);
            signer.initSign(privateKey);
            signer.update(bytes);
            byte[] signature = signer.sign();
            logger.exit();
            return signature;
        } catch (GeneralSecurityException e) {
            String message = "An exception occured while trying to sign bytes.";
            RuntimeException exception = new RuntimeException(message, e);
            logger.error(message, exception);
            throw exception;
        }
    }


    @Override
    public boolean bytesAreValid(PublicKey certificate, byte[] bytes, byte[] signature) {
        try {
            logger.entry();
            Signature signer = Signature.getInstance(ASYMMETRIC_SIGNATURE_ALGORITHM);
            signer.initVerify(certificate);
            signer.update(bytes);
            boolean isValid = signer.verify(signature);
            logger.exit();
            return isValid;
        } catch (GeneralSecurityException e) {
            String message = "An exception occured while trying to validate signed bytes.";
            RuntimeException exception = new RuntimeException(message, e);
            logger.error(message, exception);
            throw exception;
        }
    }


    @Override
    public byte[] encryptSharedKey(PublicKey publicKey, SecretKey sharedKey) {
        try {
            logger.entry();
            Cipher cipher = Cipher.getInstance(ASYMMETRIC_ENCRYPTION_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedKey = cipher.doFinal(sharedKey.getEncoded());
            logger.exit();
            return encryptedKey;
        } catch (GeneralSecurityException e) {
            String message = "An exception occured while trying to encrypt a shared key.";
            RuntimeException exception = new RuntimeException(message, e);
            logger.error(message, exception);
            throw exception;
        }
    }


    @Override
    public SecretKey decryptSharedKey(PrivateKey privateKey, byte[] encryptedKey) {
        try {
            logger.entry();
            byte[] decryptedKey;
            Cipher cipher = Cipher.getInstance(ASYMMETRIC_ENCRYPTION_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            decryptedKey = cipher.doFinal(encryptedKey);
            SecretKey sharedKey = new SecretKeySpec(decryptedKey, SYMMETRIC_KEY_TYPE);
            logger.exit();
            return sharedKey;
        } catch (GeneralSecurityException e) {
            String message = "An exception occured while trying to decrypt a shared key.";
            RuntimeException exception = new RuntimeException(message, e);
            logger.error(message, exception);
            throw exception;
        }
    }

}
