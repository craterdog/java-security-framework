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
 * This interface defines the methods needed to do message level symmetric key decryption when
 * the sender and receiver have already exchanged their asymmetric public keys.
 *
 * @author Derk Norton
 */
public interface MessageDecryption {

    /**
     * This method decodes a base 64 string into its original bytes.
     *
     * @param base64String The base 64 encoded string.
     * @return The corresponding decoded bytes.
     */
    public byte[] decodeString(String base64String);

    /**
     * This method decrypts a string using a shared key.
     *
     * @param sharedKey The shared key used for the encryption.
     * @param encryptedString The encrypted string.
     * @return The decrypted string.
     */
    public String decryptString(SecretKey sharedKey, byte[] encryptedString);

    /**
     * This method decrypts a byte stream from an encrypted byte stream.
     *
     * @param sharedKey The shared key used for the encryption.
     * @param input The encrypted byte stream.
     * @param output The decrypted byte stream.
     * @throws java.io.IOException Unable to decrypt the stream.
     */
    public void decryptStream(SecretKey sharedKey, InputStream input, OutputStream output) throws IOException;

    /**
     * This method generates an input stream that performs decryption on another input stream.
     *
     * @param sharedKey The shared key used for the encryption.
     * @param input The input stream to be decrypted.
     * @return The decrypting input stream.
     * @throws java.io.IOException Unable to create a decryption input stream.
     */
    public CipherInputStream decryptionInputStream(SecretKey sharedKey, InputStream input) throws IOException;


    /**
     * This method checks to see if the signature for a signed byte array is valid.
     *
     * @param certificate The certificate containing the matching public key for the private key that signed the bytes.
     * @param bytes The byte array to be signed.
     * @param signature The signature to be validated.
     * @return Whether or not the signature matches the byte array.
     */
    public boolean bytesAreValid(PublicKey certificate, byte[] bytes, byte[] signature);

    /**
     * This method decrypts a shared key using the private key that is paired with the public certificate that was
     * used to encrypt it at the source.  The public certificate and private key belong to the destination of the
     * communication.
     *
     * @param privateKey The private key of the destination.
     * @param encryptedKey The encrypted shared key.
     * @return The decrypted shared key.
     */
    public SecretKey decryptSharedKey(PrivateKey privateKey, byte[] encryptedKey);

}