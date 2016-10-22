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

import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.SecretKey;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.ext.XLogger;
import org.slf4j.ext.XLoggerFactory;


/**
 * This class provides unit tests for all methods in the MessageCryptex class.
 *
 * @author Derk Norton
 */
public class ExampleCodeTest {

    static XLogger logger = XLoggerFactory.getXLogger(ExampleCodeTest.class);

    /**
     * Log a message at the beginning of the tests.
     */
    @BeforeClass
    public static void setUpClass() {
        logger.info("Running Example Code Unit Tests...\n");
    }


    /**
     * Log a message at the end of the tests.
     */
    @AfterClass
    public static void tearDownClass() {
        logger.info("Example Code Unit Tests Completed.\n");
    }


    /**
     * This test method performs a round-trip session key generation, encryption, signing,
     * encoding, decoding, signature verification, and decryption tests using the MessageCryptex
     * class.
     *
     * @throws IOException
     */
    @Test
    public void testMessageRoundTrip() throws IOException {
        logger.info("Testing round trip message encryption...");
        MessageCryptex cryptex = new RsaAesMessageCryptex();

        logger.info("  Generating the public/private key pairs...");
        KeyPair senderPair = cryptex.generateKeyPair();
        PrivateKey senderPrivateKey = senderPair.getPrivate();
        PublicKey senderPublicKey = senderPair.getPublic();
        KeyPair receiverPair = cryptex.generateKeyPair();
        PrivateKey receiverPrivateKey = receiverPair.getPrivate();
        PublicKey receiverPublicKey = receiverPair.getPublic();

        logger.info("  Encoding the public key.");
        String pem = cryptex.encodePublicKey(senderPublicKey, "      ");
        logger.info("    publicKey:\n" + pem + "\n");

        logger.info("  Encoding the private key with password.");
        char[] password = { 's', 'e', 'c', 'r', 'e', 't' };
        pem = cryptex.encodePrivateKey(senderPrivateKey, password, "      ");
        logger.info("    privateKey:\n" + pem + "\n");

        logger.info("  Sender generating shared session key...");
        SecretKey sessionKey = cryptex.generateSharedKey();

        logger.info("  Sender encrypting session key...");
        byte[] encryptedSessionKey = cryptex.encryptSharedKey(receiverPublicKey, sessionKey);

        logger.info("  Sender signing the encrypted session key...");
        byte[] signature = cryptex.signBytes(senderPrivateKey, encryptedSessionKey);

        logger.info("  Sender base 64 encoding the encrypted key and signature...");
        String encodedSessionKey = cryptex.encodeBytes(encryptedSessionKey, "      ");
        logger.info("    EncodedSessionKey:\n" + encodedSessionKey + "\n");
        String encodedSignature = cryptex.encodeBytes(signature, "      ");
        logger.info("    EncodedSignature:\n" + encodedSignature + "\n");

        logger.info("  Sender encrypting the request using session key...");
        String request = "This is a request...";
        InputStream clearInput = new ByteArrayInputStream(request.getBytes("UTF-8"));
        ByteArrayOutputStream encryptedOutput = new ByteArrayOutputStream();
        cryptex.encryptStream(sessionKey, clearInput, encryptedOutput);

        logger.info("  Sending the encrypted request to the receiver...");
        InputStream encryptedInput = new ByteArrayInputStream(encryptedOutput.toByteArray());

        logger.info("  Receiver decoding the encrypted session key and its signature...");
        signature = cryptex.decodeString(encodedSignature);
        encryptedSessionKey = cryptex.decodeString(encodedSessionKey);

        logger.info("  Receiver validating the signature of the encrypted session key...");
        if (! cryptex.bytesAreValid(senderPublicKey, encryptedSessionKey, signature)) {
            fail("The session key signature was invalid.");
        }

        logger.info("  Receiver decrypting the session key...");
        sessionKey = cryptex.decryptSharedKey(receiverPrivateKey, encryptedSessionKey);

        logger.info("  Receiver decrypting the request using the session key...");
        ByteArrayOutputStream decryptedOutput = new ByteArrayOutputStream();
        cryptex.decryptStream(sessionKey, encryptedInput, decryptedOutput);
        logger.info("    The decrypted request is: \"{}\"\n", new String(decryptedOutput.toByteArray()));

        logger.info("  Receiver handling the request and preparing the response...");
        String response = "This is the response...";

        logger.info("  Receiver encrypting the response using the session key...");
        clearInput = new ByteArrayInputStream(response.getBytes("UTF-8"));
        encryptedOutput = new ByteArrayOutputStream();
        cryptex.encryptStream(sessionKey, clearInput, encryptedOutput);

        logger.info("  Sending the encrypted response back to the sender...");
        encryptedInput = new ByteArrayInputStream(encryptedOutput.toByteArray());

        logger.info("  Sender decrypting the response using the session key...");
        decryptedOutput = new ByteArrayOutputStream();
        cryptex.decryptStream(sessionKey, encryptedInput, decryptedOutput);
        logger.info("    The decrypted response is: \"{}\"\n", new String(decryptedOutput.toByteArray()));


        logger.info("Round trip message encryption test completed.\n");

    }

}
