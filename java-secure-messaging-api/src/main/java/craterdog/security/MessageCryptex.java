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
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import javax.crypto.*;
import org.apache.commons.io.IOUtils;
import org.slf4j.ext.XLogger;
import org.slf4j.ext.XLoggerFactory;


/**
 * This abstract class defines constants and implements invariant methods that are needed
 * by all concrete classes that implement key and message encryption and decryption.
 *
 * @author Derk Norton
 */
public abstract class MessageCryptex {

    static XLogger logger = XLoggerFactory.getXLogger(MessageCryptex.class);

    // Byte Encoding

    /**
     * This method encodes a byte array into a base 64 string.
     *
     * @param bytes The byte array to be encoded.
     * @return The base 64 encoded string for those bytes.
     */
    public final String encodeBytes(byte[] bytes) {
        logger.entry();
        String base64String = Base64Utils.encode(bytes);
        logger.exit();
        return base64String;
    }


    /**
     * This method decodes a base 64 string into its original bytes.
     *
     * @param base64String The base 64 encoded string.
     * @return The corresponding decoded bytes.
     */
    public final byte[] decodeString(String base64String) {
        logger.entry();
        byte[] decodedBytes = Base64Utils.decode(base64String);
        logger.exit();
        return decodedBytes;
    }


    // Cryptographic Hashing

    /**
     * This method returns the hash algorithm.
     *
     * @return The hash algorithm.
     */
    public abstract String getHashAlgorithm();


    /**
     * This method returns a base 64 encoded SHA256 one-way hash of the specified string.
     *
     * @param string The string to be hashed.
     * @return A base 64 encoded one-way hash of the string.
     */
    public abstract String hashString(String string);


    // Symmetric (Shared) Key Cryptography

    /**
     * This method returns the password encoding type used for password based encryption (PBE)
     * used by this cryptex.
     *
     * @return The type of the password encoding.
     */
    public abstract String getPasswordEncodingType();


    /**
     * This method returns the symmetric key type used by this cryptex.
     *
     * @return The type of the symmetric keys.
     */
    public abstract String getSymmetricKeyType();


    /**
     * This method returns the symmetric key size used by this cryptex.
     *
     * @return The size of the symmetric keys.
     */
    public abstract int getSymmetricKeySize();


    /**
     * This method returns the symmetric encryption algorithm used by this cryptex.
     *
     * @return The name of the algorithm.
     */
    public abstract String getSymmetricEncryptionAlgorithm();


    /**
     * This method generates a shared (secret) key to be used for encrypting
     * large amounts of data.
     *
     * @return The new shared (secret) key.
     */
    public abstract SecretKey generateSharedKey();


    /**
     * This method encrypts a string using a shared key.
     *
     * @param sharedKey The shared key used for the encryption.
     * @param string The string to be encrypted.
     * @return The encrypted string.
     */
    public final byte[] encryptString(SecretKey sharedKey, String string) {
        logger.entry();
        try (ByteArrayInputStream input = new ByteArrayInputStream(string.getBytes("UTF-8"));
                ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            encryptStream(sharedKey, input, output);
            output.flush();
            byte[] encryptedString = output.toByteArray();
            logger.exit();
            return encryptedString;
        } catch (IOException e) {
            // should never happen!
            RuntimeException exception = new RuntimeException("An unexpected exception occured while trying to encrypt a string.", e);
            logger.error(exception.toString());
            throw exception;
        }
    }


    /**
     * This method decrypts a string using a shared key.
     *
     * @param sharedKey The shared key used for the encryption.
     * @param encryptedString The encrypted string.
     * @return The decrypted string.
     */
    public final String decryptString(SecretKey sharedKey, byte[] encryptedString) {
        logger.entry();
        try (ByteArrayInputStream input = new ByteArrayInputStream(encryptedString);
                ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            decryptStream(sharedKey, input, output);
            output.flush();
            String string = output.toString("UTF-8");
            logger.exit();
            return string;
        } catch (IOException e) {
            // should never happen!
            RuntimeException exception = new RuntimeException("An unexpected exception occured while trying to decrypt a string.", e);
            logger.error(exception.toString());
            throw exception;
        }
    }


    /**
     * This method encrypts a byte stream using a shared key.
     *
     * @param sharedKey The shared key used for the encryption.
     * @param input The byte stream to be encrypted.
     * @param output The encrypted output stream.
     * @throws java.io.IOException Unable to encrypt the stream.
     */
    public final void encryptStream(SecretKey sharedKey, InputStream input, OutputStream output) throws IOException {
        logger.entry();
        CipherOutputStream cipherOutput = null;
        byte[] buffer = new byte[2048];
        try {
            logger.debug("Creating a special output stream to do the work...");
            cipherOutput = encryptionOutputStream(sharedKey, output);

            logger.debug("Reading from the input and writing to the encrypting output stream...");
            // Can't use IOUtils.copy(input, cipherOutput) here because need to purge buffer later...
            int bytesRead;
            while ((bytesRead = input.read(buffer)) != -1) {
                cipherOutput.write(buffer, 0, bytesRead);
            }
            cipherOutput.flush();
        } finally {
            logger.debug("Purging any plaintext hanging around in memory...");
            Arrays.fill(buffer, (byte) 0);

            if (cipherOutput != null) cipherOutput.close();
        }
        logger.exit();
    }


    /**
     * This method decrypts a byte stream from an encrypted byte stream.
     *
     * @param sharedKey The shared key used for the encryption.
     * @param input The encrypted byte stream.
     * @param output The decrypted byte stream.
     * @throws java.io.IOException Unable to decrypt the stream.
     */
    public final void decryptStream(SecretKey sharedKey, InputStream input, OutputStream output) throws IOException {
        logger.entry();
        CipherInputStream cipherInput = null;
        try {
            logger.debug("Creating a special input stream to do the work...");
            cipherInput = decryptionInputStream(sharedKey, input);

            logger.debug("Reading bytes, decrypting them, and writing them out...");
            IOUtils.copy(cipherInput, output);
            output.flush();
        } finally {
            if (cipherInput != null) cipherInput.close();
        }
        logger.exit();
    }


    /**
     * This method generates an output stream that performs encryption on another output stream.
     *
     * @param sharedKey The shared key used for the encryption.
     * @param output The output stream to be encrypted.
     * @return The encrypting output stream.
     * @throws java.io.IOException Unable to create an encryption output stream.
     */
    public abstract CipherOutputStream encryptionOutputStream(SecretKey sharedKey, OutputStream output) throws IOException;


    /**
     * This method generates an input stream that performs decryption on another input stream.
     *
     * @param sharedKey The shared key used for the encryption.
     * @param input The input stream to be decrypted.
     * @return The decrypting input stream.
     * @throws java.io.IOException Unable to create a decryption input stream.
     */
    public abstract CipherInputStream decryptionInputStream(SecretKey sharedKey, InputStream input) throws IOException;


    // Asymmetric (Public-Private) Key Cryptography

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
    public abstract int getAsymmetricKeySize();


    /**
     * This method returns the asymmetric signature algorithm used by this cryptex.
     *
     * @return The name of the algorithm.
     */
    public abstract String getAsymmetricSignatureAlgorithm();


    /**
     * This method returns the asymmetric encryption algorithm used by this cryptex.
     *
     * @return The name of the algorithm.
     */
    public abstract String getAsymmetricEncryptionAlgorithm();


    /**
     * This method generates a new public/private key pair.
     *
     * @return The new key pair.
     */
    public abstract KeyPair generateKeyPair();


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
     * This method signs a byte array.
     *
     * @param privateKey The private key used for signing.
     * @param bytes The byte array to be signed.
     * @return The resulting signature.
     */
    public abstract byte[] signBytes(PrivateKey privateKey, byte[] bytes);


    /**
     * This method checks to see if the signature for a signed byte array is valid.
     *
     * @param certificate The certificate containing the matching public key for the private key that signed the bytes.
     * @param bytes The byte array to be signed.
     * @param signature The signature to be validated.
     * @return Whether or not the signature matches the byte array.
     */
    public abstract boolean bytesAreValid(PublicKey certificate, byte[] bytes, byte[] signature);


    /**
     * This method encrypts a shared key using the public certificate of the destination for a data stream that will
     * be encrypted using the shared key.  Shared key-based encryption is much faster than public/private key pair-based
     * encryption.  But the shared key must be passed to the destination for this to work so the shared key is first
     * encrypted using public/private key encryption.
     *
     * @param certificate The public certificate of the destination.
     * @param sharedKey The shared key to be encrypted.
     * @return The encrypted shared key.
     */
    public abstract byte[] encryptSharedKey(PublicKey certificate, SecretKey sharedKey);


    /**
     * This method decrypts a shared key using the private key that is paired with the public certificate that was
     * used to encrypt it at the source.  The public certificate and private key belong to the destination of the
     * communication.
     *
     * @param privateKey The private key of the destination.
     * @param encryptedKey The encrypted shared key.
     * @return The decrypted shared key.
     */
    public abstract SecretKey decryptSharedKey(PrivateKey privateKey, byte[] encryptedKey);

}