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

import static org.junit.Assert.assertEquals;
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
import org.junit.runner.RunWith;
import org.slf4j.ext.XLogger;
import org.slf4j.ext.XLoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;


/**
 * This class provides unit tests for all methods in the MessageCryptex class.
 *
 * @author Derk Norton
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = {"classpath:META-INF/spring/craterdog-secure-messaging-providers.xml"})
public class RsaAesMessageCryptexTest {

    static XLogger logger = XLoggerFactory.getXLogger(RsaAesMessageCryptexTest.class);

    /**
     * Log a message at the beginning of the tests.
     */
    @BeforeClass
    public static void setUpClass() {
        logger.info("Running RsaAesMessageCrytex Unit Tests...");
    }


    /**
     * Log a message at the end of the tests.
     */
    @AfterClass
    public static void tearDownClass() {
        logger.info("RsaAesMessageCrytex Unit Tests Completed.");
    }


    @Autowired
    private MessageCryptex cryptex;


    /**
     * This test encrypts a test string and then decrypts it and compares the two to make sure
     * that they are the same.
     */
    @Test
    public void testStringRoundTrip() {
        logger.info("Testing round trip string encryption...");

        logger.info("Generating a shared key...");
        SecretKey sharedKey = cryptex.generateSharedKey();

        logger.info("Encrypting a test string with the shared key...");
        String string = "This is a test string.";
        byte[] encryptedString = cryptex.encryptString(sharedKey, string);

        logger.info("Decrypting the encrypted string with the shared key...");
        String decryptedString = cryptex.decryptString(sharedKey, encryptedString);

        logger.info("Comparing the two strings...");
        assertEquals("The decrypted string was different from the original string",
                string, decryptedString);

        logger.info("Round trip string encryption test completed.");
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

        logger.info("Generating the public/private key pairs...");
        RsaCertificateManager manager = new RsaCertificateManager();
        KeyPair senderPair = manager.generateKeyPair();
        PrivateKey senderPrivateKey = senderPair.getPrivate();
        PublicKey senderPublicKey = senderPair.getPublic();
        KeyPair receiverPair = manager.generateKeyPair();
        PrivateKey receiverPrivateKey = receiverPair.getPrivate();
        PublicKey receiverPublicKey = receiverPair.getPublic();

        logger.info("Sender generating shared session key...");
        SecretKey sessionKey = cryptex.generateSharedKey();

        logger.info("Sender encrypting session key...");
        byte[] encryptedSessionKey = cryptex.encryptSharedKey(receiverPublicKey, sessionKey);

        logger.info("Sender signing the encrypted session key...");
        byte[] signature = cryptex.signBytes(senderPrivateKey, encryptedSessionKey);

        logger.info("Sender base 64 encoding the encrypted key and signature...");
        String encodedSessionKey = cryptex.encodeBytes(encryptedSessionKey);
        logger.info("  EncodedSessionKey: " + encodedSessionKey);
        String encodedSignature = cryptex.encodeBytes(signature);
        logger.info("  EncodedSignature: " + encodedSignature);

        logger.info("Sender encrypting the request using session key...");
        String request = "This is a JSON request...";
        InputStream requestStream = new ByteArrayInputStream(request.getBytes("UTF-8"));
        ByteArrayOutputStream encryptedRequestStream = new ByteArrayOutputStream();
        cryptex.encryptStream(sessionKey, requestStream, encryptedRequestStream);

        logger.info("Sender sending the encrypted request to the receiver...");
        requestStream = new ByteArrayInputStream(encryptedRequestStream.toByteArray());

        logger.info("Receiver decoding the encrypted session key and its signature...");
        signature = cryptex.decodeString(encodedSignature);
        encryptedSessionKey = cryptex.decodeString(encodedSessionKey);

        logger.info("Receiver validating the signature of the encrypted session key...");
        if (! cryptex.bytesAreValid(senderPublicKey, encryptedSessionKey, signature)) {
            fail("The session key signature was invalid.");
        }

        logger.info("Receiver decrypting the session key...");
        sessionKey = cryptex.decryptSharedKey(receiverPrivateKey, encryptedSessionKey);

        logger.info("Receiver decrypting the request using the session key...");
        ByteArrayOutputStream decryptedRequestStream = new ByteArrayOutputStream();
        cryptex.decryptStream(sessionKey, requestStream, decryptedRequestStream);
        assertEquals("The decrypted request was different from the original request",
                request, new String(decryptedRequestStream.toByteArray()));

        logger.info("Receiver handling the request and preparing the response...");
        String response = "This is the JSON response...";

        logger.info("Receiver encrypting the response using the session key...");
        ByteArrayInputStream responseStream = new ByteArrayInputStream(response.getBytes("UTF-8"));
        ByteArrayOutputStream encryptedResponseStream = new ByteArrayOutputStream();
        cryptex.encryptStream(sessionKey, responseStream, encryptedResponseStream);

        logger.info("Receiver sending the encrypted response to the sender...");
        responseStream = new ByteArrayInputStream(encryptedResponseStream.toByteArray());

        logger.info("Sender decrypting the response using the session key...");
        ByteArrayOutputStream decryptedResponseStream = new ByteArrayOutputStream();
        cryptex.decryptStream(sessionKey, responseStream, decryptedResponseStream);
        assertEquals("The decrypted response was different from the original response",
                response, new String(decryptedResponseStream.toByteArray()));

        logger.info("Round trip message encryption test completed.");
    }

}
