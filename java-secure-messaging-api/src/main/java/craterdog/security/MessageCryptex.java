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
import java.util.Arrays;
import javax.crypto.*;
import org.apache.commons.io.IOUtils;
import org.slf4j.ext.XLogger;
import org.slf4j.ext.XLoggerFactory;


/**
 * This abstract class defines constants and implements invariant methods that are needed
 * by all concrete classes that implement message encryption and decryption.
 *
 * @author Derk Norton
 */
public abstract class MessageCryptex implements MessageEncryption, MessageDecryption {

    static XLogger logger = XLoggerFactory.getXLogger(MessageCryptex.class);

    @Override
    public final String encodeBytes(byte[] bytes) {
        logger.entry();
        String base64String = Base64Utils.encode(bytes);
        logger.exit();
        return base64String;
    }


    @Override
    public final byte[] decodeString(String base64String) {
        logger.entry();
        byte[] decodedBytes = Base64Utils.decode(base64String);
        logger.exit();
        return decodedBytes;
    }


    @Override
    public void encryptStream(SecretKey sharedKey, InputStream input, OutputStream output) throws IOException {
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


    @Override
    public void decryptStream(SecretKey sharedKey, InputStream input, OutputStream output) throws IOException {
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


    @Override
    public byte[] encryptString(SecretKey sharedKey, String string) {
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


    @Override
    public String decryptString(SecretKey sharedKey, byte[] encryptedString) {
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

}
