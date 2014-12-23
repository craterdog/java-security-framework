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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.*;


/**
 * This interface defines the methods needed to do message level symmetric key encryption when
 * the sender and receiver have already exchanged their asymmetric public keys.
 *
 * @author Derk Norton
 */
public interface MessageEncryption {

    /**
     * This method returns the encoding type supported by this cryptex.
     *
     * @return The HTTP encoding type.
     */
    public String getEncodingType();

    /**
     * This method returns the hash algorithm.
     *
     * @return The hash algorithm.
     */
    public abstract String getHashAlgorithm();


    /**
     * This method returns the asymmetric signature algorithm used by this cryptex.
     *
     * @return The name of the algorithm.
     */
    public String getAsymmetricSignatureAlgorithm();

    /**
     * This method returns the asymmetric encryption algorithm used by this cryptex.
     *
     * @return The name of the algorithm.
     */
    public String getAsymmetricEncryptionAlgorithm();

    /**
     * This method returns the symmetric encryption algorithm used by this cryptex.
     *
     * @return The name of the algorithm.
     */
    public String getSymmetricEncryptionAlgorithm();

    /**
     * This method returns the symmetric key size used by this cryptex.
     *
     * @return The size of the symmetric keys.
     */
    public int getSymmetricKeySize();

    /**
     * This method encodes a byte array into a base 64 string.
     *
     * @param bytes The byte array to be encoded.
     * @return The base 64 encoded string for those bytes.
     */
    public String encodeBytes(byte[] bytes);

    /**
     * This method signs a byte array.
     *
     * @param privateKey The private key used for signing.
     * @param bytes The byte array to be signed.
     * @return The resulting signature.
     */
    public byte[] signBytes(PrivateKey privateKey, byte[] bytes);

    /**
     * This method generates a shared (secret) key to be used for encrypting
     * large amounts of data.
     *
     * @return The new shared (secret) key.
     */
    public SecretKey generateSharedKey();

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
    public byte[] encryptSharedKey(PublicKey certificate, SecretKey sharedKey);

    /**
     * This method encrypts a string using a shared key.
     *
     * @param sharedKey The shared key used for the encryption.
     * @param string The string to be encrypted.
     * @return The encrypted string.
     */
    public byte[] encryptString(SecretKey sharedKey, String string);

    /**
     * This method encrypts a byte stream using a shared key.
     *
     * @param sharedKey The shared key used for the encryption.
     * @param input The byte stream to be encrypted.
     * @param output The encrypted output stream.
     * @throws java.io.IOException Unable to encrypt the stream.
     */
    public void encryptStream(SecretKey sharedKey, InputStream input, OutputStream output) throws IOException;

    /**
     * This method generates an output stream that performs encryption on another output stream.
     *
     * @param sharedKey The shared key used for the encryption.
     * @param output The output stream to be encrypted.
     * @return The encrypting output stream.
     * @throws java.io.IOException Unable to create an encryption output stream.
     */
    public CipherOutputStream encryptionOutputStream(SecretKey sharedKey, OutputStream output) throws IOException;

    /**
     * This method returns a one-way hash of the specified string.
     *
     * @param string The string to be hashed.
     * @return A base 64 encoded one-way hash of the string.
     */
    public abstract String hashString(String string);

}
