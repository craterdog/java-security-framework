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
import static org.junit.Assert.assertNotEquals;
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
public class RsaAesMessageCryptexTest {

    static XLogger logger = XLoggerFactory.getXLogger(RsaAesMessageCryptexTest.class);

    /**
     * Log a message at the beginning of the tests.
     */
    @BeforeClass
    public static void setUpClass() {
        logger.info("Running RsaAesMessageCrytex Unit Tests...\n");
    }


    /**
     * Log a message at the end of the tests.
     */
    @AfterClass
    public static void tearDownClass() {
        logger.info("RsaAesMessageCrytex Unit Tests Completed.\n");
    }


    static private final MessageCryptex cryptex = new RsaAesMessageCryptex();


    /**
     * This test encrypts a test string and then decrypts it and compares the two to make sure
     * that they are the same.
     */
    @Test
    public void testStringRoundTrip() {
        logger.info("Testing round trip string encryption...");

        logger.info("  Generating a shared key...");
        SecretKey sharedKey = cryptex.generateSharedKey();

        logger.info("  Encrypting a test string with the shared key...");
        String string = "This is a test string.";
        byte[] encryptedString = cryptex.encryptString(sharedKey, string);

        logger.info("  Decrypting the encrypted string with the shared key...");
        String decryptedString = cryptex.decryptString(sharedKey, encryptedString);

        logger.info("  Comparing the two strings...");
        assertEquals("The decrypted string was different from the original string",
                string, decryptedString);

        logger.info("Round trip string encryption test completed.\n");
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

        logger.info("  Generating the public/private key pairs...");
        KeyPair senderPair = cryptex.generateKeyPair();
        PrivateKey senderPrivateKey = senderPair.getPrivate();
        PublicKey senderPublicKey = senderPair.getPublic();
        KeyPair receiverPair = cryptex.generateKeyPair();
        PrivateKey receiverPrivateKey = receiverPair.getPrivate();
        PublicKey receiverPublicKey = receiverPair.getPublic();

        logger.info("  Encoding and decoding the public key.");
        String pem = cryptex.encodePublicKey(senderPublicKey);
        PublicKey publicKey = cryptex.decodePublicKey(pem);
        String pem2 = cryptex.encodePublicKey(publicKey);
        assertEquals("  The encoded and decoded public keys don't match.", pem, pem2);

        logger.info("  Encoding and decoding the private key with password.");
        String passphrase = "secret";  // DON'T DO IT THIS WAY!
        char[] password = passphrase.toCharArray();
        SecretKey passwordKey = cryptex.generatePasswordKey(password);
        pem = cryptex.encodePrivateKey(senderPrivateKey, passwordKey);
        password = passphrase.toCharArray();
        passwordKey = cryptex.generatePasswordKey(password);
        PrivateKey privateKey = cryptex.decodePrivateKey(pem, passwordKey);
        password = passphrase.toCharArray();
        passwordKey = cryptex.generatePasswordKey(password);
        pem2 = cryptex.encodePrivateKey(privateKey, passwordKey);
        password = passphrase.toCharArray();
        passwordKey = cryptex.generatePasswordKey(password);
        PrivateKey privateKey2 = cryptex.decodePrivateKey(pem2, passwordKey);
        assertEquals("  The encoded and decoded private keys don't match.", privateKey, privateKey2);

        logger.info("  Sender generating shared session key...");
        SecretKey sessionKey = cryptex.generateSharedKey();

        logger.info("  Sender encrypting session key...");
        byte[] encryptedSessionKey = cryptex.encryptSharedKey(receiverPublicKey, sessionKey);

        logger.info("  Sender signing the encrypted session key...");
        byte[] signature = cryptex.signBytes(senderPrivateKey, encryptedSessionKey);

        logger.info("  Sender base 64 encoding the encrypted key and signature...");
        String encodedSessionKey = cryptex.encodeBytes(encryptedSessionKey);
        String encodedSignature = cryptex.encodeBytes(signature);

        logger.info("  Sender encrypting the request using session key...");
        String request = "This is a request...";
        InputStream clearInput = new ByteArrayInputStream(request.getBytes("UTF-8"));
        ByteArrayOutputStream encryptedOutput = new ByteArrayOutputStream();
        cryptex.encryptStream(sessionKey, clearInput, encryptedOutput);

        logger.info("  Sender sending the encrypted request to the receiver...");
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
        assertEquals("The decrypted request was different from the original request",
                request, new String(decryptedOutput.toByteArray()));

        logger.info("  Receiver handling the request and preparing the response...");
        String response = "This is the response...";

        logger.info("  Receiver encrypting the response using the session key...");
        clearInput = new ByteArrayInputStream(response.getBytes("UTF-8"));
        encryptedOutput = new ByteArrayOutputStream();
        cryptex.encryptStream(sessionKey, clearInput, encryptedOutput);

        logger.info("  Receiver sending the encrypted response to the sender...");
        encryptedInput = new ByteArrayInputStream(encryptedOutput.toByteArray());

        logger.info("  Sender decrypting the response using the session key...");
        decryptedOutput = new ByteArrayOutputStream();
        cryptex.decryptStream(sessionKey, encryptedInput, decryptedOutput);
        assertEquals("The decrypted response was different from the original response",
                response, new String(decryptedOutput.toByteArray()));

        logger.info("  Decoding keys generated by openssl...");
        password = passphrase.toCharArray();
        passwordKey = cryptex.generatePasswordKey(password);
        cryptex.decodePrivateKey(openSslPrivatePem, passwordKey);
        cryptex.decodePublicKey(openSslPublicPem);

        logger.info("Round trip message encryption test completed.\n");
    }


    /**
     * This test method compares the hash values of two different strings and makes sure that
     * they are different.
     *
     * @throws IOException
     */
    @Test
    public void testMessageHashing() throws IOException {
        logger.info("Testing message hashing...");

        String hash1 = cryptex.hashString("This is a string to be hashed.");
        String hash2 = cryptex.hashString("This is a different string to be hashed.");
        assertNotEquals(hash1, hash2);

        logger.info("Message hashing test completed.\n");
    }


    /*
    This public-private key pair was generated using the following ssl commands:
        openssl genrsa -des3 -out private.pem 2048
        openssl rsa -in private.pem -outform PEM -pubout -out public.pem
        openssl pkcs8 -topk8 -inform PEM -outform PEM -in private.pem -out pkcs8.pem
        passphrase: "secret"
    */
    static private final String openSslPublicPem = "-----BEGIN PUBLIC KEY-----\n" +
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArHVMYJnHrYNwQTuwIWjD\n" +
        "LgVYjaCJeBjo1YB5FfSiaz2VJp9G5pWJ+4LRmhfyjJzrVaPs5WVPAijU1GF85hX+\n" +
        "Ey+Kyg/OxbJdcuC31xD5yUWXgsyNKnl7TddIXwNAhbWTA6PoNsbW/hZIdaU+ReI9\n" +
        "l/P8fQoJ6DqGN6XnM6N+Sl65D2W3s1i5T5L6ndjg7JpRaWIYB/5XAY0h0+IHkDnW\n" +
        "W5QHVUYL1NNC1TjLyGHZ6g+8Sme4g8WfksVS/m8CbN7/uGFGpApx9ISKF27+8AYg\n" +
        "dS9zPoJi7OBrUPpRyTia9rMJR/awhd3VBlaJ1YVjuBKajrkvxBO/d1JvOkwwEjo7\n" +
        "0wIDAQAB\n" +
        "-----END PUBLIC KEY-----";

    static private final String openSslPrivatePem = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n" +
        "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\n" +
        "pAPPdpZS/7Ob4kfzgg==\n" +
        "-----END ENCRYPTED PRIVATE KEY-----";

}
