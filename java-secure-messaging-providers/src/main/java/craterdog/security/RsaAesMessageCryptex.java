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
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


/**
 * This class implements the interfaces needed to do message level symmetric key encryption and
 * decryption when the sender and receiver have already exchanged their asymmetric public keys.
 * The public/private key pair are RSA based, and the symmetric key type is AES.
 *
 * @author Derk Norton
 */
public final class RsaAesMessageCryptex extends MessageCryptex {

    static private final String ENCODING_TYPE = "AES-128-CBC-PKCS7";
    static private final String ASYMMETRIC_KEY_TYPE = "RSA";
    static private final String HASH_ALGORITHM = "SHA256";
    static private final String ASYMMETRIC_SIGNATURE_ALGORITHM = "SHA1with" + ASYMMETRIC_KEY_TYPE;
    static private final String ASYMMETRIC_ENCRYPTION_ALGORITHM = ASYMMETRIC_KEY_TYPE + "/NONE/OAEPWithSHA256AndMGF1Padding";
    static private final String SYMMETRIC_KEY_TYPE = "AES";
    static private final int SYMMETRIC_KEY_SIZE = 128;
    static private final String SYMMETRIC_ENCRYPTION_ALGORITHM = SYMMETRIC_KEY_TYPE + "/CBC/PKCS7Padding";
    static private final String PROVIDER_NAME = BouncyCastleProvider.PROVIDER_NAME;


    /**
     * This default constructor creates the cryptex and initializes the security provider.
     */
    public RsaAesMessageCryptex() {
        logger.entry();
        Security.addProvider(new BouncyCastleProvider());
        logger.exit();
    }


    @Override
    public String getEncodingType() {
        return ENCODING_TYPE;
    }


    @Override
    public String getAsymmetricSignatureAlgorithm() {
        return ASYMMETRIC_SIGNATURE_ALGORITHM;
    }


    @Override
    public String getAsymmetricEncryptionAlgorithm() {
        // this should be changed to the preferred algorithm after August, 2014
        return ASYMMETRIC_ENCRYPTION_ALGORITHM;
    }


    @Override
    public String getSymmetricEncryptionAlgorithm() {
        return SYMMETRIC_ENCRYPTION_ALGORITHM;
    }


    @Override
    public int getSymmetricKeySize() {
        return SYMMETRIC_KEY_SIZE;
    }


    @Override
    public String getHashAlgorithm() {
        return HASH_ALGORITHM;
    }


    @Override
    public byte[] signBytes(PrivateKey privateKey, byte[] bytes) {
        try {
            logger.entry();
            Signature signer = Signature.getInstance(ASYMMETRIC_SIGNATURE_ALGORITHM, PROVIDER_NAME);
            signer.initSign(privateKey);
            signer.update(bytes);
            byte[] signature = signer.sign();
            logger.exit();
            return signature;
        } catch (GeneralSecurityException e) {
            logger.catching(e);
            RuntimeException exception =
                    new RuntimeException("An exception occured while trying to sign bytes.", e);
            throw exception;
        }
    }


    @Override
    public boolean bytesAreValid(PublicKey certificate, byte[] bytes, byte[] signature) {
        try {
            logger.entry();
            Signature signer = Signature.getInstance(ASYMMETRIC_SIGNATURE_ALGORITHM, PROVIDER_NAME);
            signer.initVerify(certificate);
            signer.update(bytes);
            boolean isValid = signer.verify(signature);
            logger.exit();
            return isValid;
        } catch (GeneralSecurityException e) {
            logger.catching(e);
            RuntimeException exception =
                    new RuntimeException("An exception occured while trying to validate signed bytes.", e);
            throw exception;
        }
    }


    @Override
    public SecretKey generateSharedKey() {
        try {
            logger.entry();
            KeyGenerator keyGenerator = KeyGenerator.getInstance(SYMMETRIC_KEY_TYPE, PROVIDER_NAME);
            SecureRandom randomGenerator = new SecureRandom();
            keyGenerator.init(SYMMETRIC_KEY_SIZE, randomGenerator);
            SecretKey sharedKey = keyGenerator.generateKey();
            logger.exit();
            return sharedKey;
        } catch (GeneralSecurityException e) {
            logger.catching(e);
            RuntimeException exception =
                    new RuntimeException("An exception occured while trying to generate a shared key.", e);
            throw exception;
        }
    }


    @Override
    public byte[] encryptSharedKey(PublicKey publicKey, SecretKey sharedKey) {
        try {
            logger.entry();
            // this should change to the real algorithm (with OAEP padding) after August, 2014
            Cipher cipher = Cipher.getInstance(ASYMMETRIC_ENCRYPTION_ALGORITHM, PROVIDER_NAME);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedKey = cipher.doFinal(sharedKey.getEncoded());
            logger.exit();
            return encryptedKey;
        } catch (GeneralSecurityException e) {
            logger.catching(e);
            RuntimeException exception =
                    new RuntimeException("An exception occured while trying to encrypt a shared key.", e);
            throw exception;
        }
    }


    @Override
    public SecretKey decryptSharedKey(PrivateKey privateKey, byte[] encryptedKey) {
        try {
            logger.entry();
            byte[] decryptedKey;
            Cipher cipher = Cipher.getInstance(ASYMMETRIC_ENCRYPTION_ALGORITHM, PROVIDER_NAME);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            decryptedKey = cipher.doFinal(encryptedKey);
            SecretKey sharedKey = new SecretKeySpec(decryptedKey, SYMMETRIC_ENCRYPTION_ALGORITHM);
            logger.exit();
            return sharedKey;
        } catch (GeneralSecurityException e) {
            logger.catching(e);
            RuntimeException exception =
                    new RuntimeException("An exception occured while trying to decrypt a shared key.", e);
            throw exception;
        }
    }


    @Override
    public CipherOutputStream encryptionOutputStream(SecretKey sharedKey, OutputStream output)
            throws IOException {
        try {
            logger.entry();

            logger.info("Creating and initializing the encryption engine...");
            Cipher cipher = Cipher.getInstance(SYMMETRIC_ENCRYPTION_ALGORITHM, PROVIDER_NAME);
            byte[] fixedIV = new byte[16];  // all zeros
            AlgorithmParameterSpec ivSpec = new IvParameterSpec(fixedIV);
            cipher.init(Cipher.ENCRYPT_MODE, sharedKey, ivSpec);

            logger.info("Creating a special output stream to do the work...");
            CipherOutputStream cipherOutputStream = new CipherOutputStream(output, cipher);

            logger.exit();
            return cipherOutputStream;
        } catch (GeneralSecurityException e) {
            logger.catching(e);
            RuntimeException exception =
                    new RuntimeException("An exception occured while trying to encrypt a stream.", e);
            throw exception;
        }
    }


    @Override
    public CipherInputStream decryptionInputStream(SecretKey sharedKey, InputStream input)
            throws IOException {
        try {
            logger.entry();

            logger.info("Creating and initializing the decryption engine...");
            Cipher cipher = Cipher.getInstance(SYMMETRIC_ENCRYPTION_ALGORITHM, PROVIDER_NAME);
            byte[] fixedIV = new byte[16];  // all zeros
            AlgorithmParameterSpec ivSpec = new IvParameterSpec(fixedIV);
            cipher.init(Cipher.DECRYPT_MODE, sharedKey, ivSpec);

            logger.info("Creating a special input stream to do the work...");
            CipherInputStream cipherInputStream = new CipherInputStream(input, cipher);

            logger.exit();
            return cipherInputStream;
        } catch (GeneralSecurityException e) {
            logger.catching(e);
            RuntimeException exception =
                    new RuntimeException("An exception occured while trying to decrypt a stream.", e);
            throw exception;
        }
    }


    // The salt is added to the string being hashed to prevent dictionary attacks on the hash value.
    static private final String SALT = "M4QGNTG3SD5JD0RMSTNMZHTXBQBYXCMT";

    @Override
    public String hashString(String string) {
        try {
            logger.entry();
            byte[] bytes = (string + SALT).getBytes();
            MessageDigest hasher = MessageDigest.getInstance(HASH_ALGORITHM);
            byte[] hash = hasher.digest(bytes);
            String hashString = Base64Utils.encode(hash);
            logger.exit();
            return hashString;
        } catch (NoSuchAlgorithmException e) {
            RuntimeException exception = new RuntimeException("An unexpected exception occurred while attempting to hash a string.", e);
            logger.throwing(exception);
            throw exception;
        }
    }

}