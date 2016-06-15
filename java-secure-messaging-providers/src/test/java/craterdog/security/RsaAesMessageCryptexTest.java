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
        char[] password = { 's', 'e', 'c', 'r', 'e', 't' };
        pem = cryptex.encodePrivateKey(senderPrivateKey, password);
        PrivateKey privateKey = cryptex.decodePrivateKey(pem, password);
        pem2 = cryptex.encodePrivateKey(privateKey, password);
        PrivateKey privateKey2 = cryptex.decodePrivateKey(pem2, password);
        assertEquals("  The encoded and decoded private keys don't match.", privateKey, privateKey2);

        logger.info("  Sender generating shared session key...");
        SecretKey sessionKey = cryptex.generateSharedKey();

        logger.info("  Sender encrypting session key...");
        byte[] encryptedSessionKey = cryptex.encryptSharedKey(receiverPublicKey, sessionKey);

        logger.info("  Sender signing the encrypted session key...");
        byte[] signature = cryptex.signBytes(senderPrivateKey, encryptedSessionKey);

        logger.info("  Sender base 64 encoding the encrypted key and signature...");
        String encodedSessionKey = cryptex.encodeBytes(encryptedSessionKey);
        logger.info("    EncodedSessionKey: " + encodedSessionKey);
        String encodedSignature = cryptex.encodeBytes(signature);
        logger.info("    EncodedSignature: " + encodedSignature);

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
        cryptex.decodePrivateKey(openSslPrivatePem, password);
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


    static private final String openSslPublicPem = "-----BEGIN PUBLIC KEY-----\n" +
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoNx32/dZl7r+NmmYPiqh\n" +
        "wzeXmOaIfmBndO+dKTAYSUbtSf/XI95Pkxiv9G/YQnJXsnCxoKXGHvl2gQm3e3pU\n" +
        "+zLfBDI7aD0/45X5pFX/rLFn9gytdVCSOE/AfOCV2SXcVkoCWbOxAuy2ooc2B0j+\n" +
        "HdJgMZg4sT6kA9RZEt4PH5yysOu1oXBjMb9K+z2IlYRDXRuN9cYLT2g96l2qz18b\n" +
        "vsy7ZnRcAlJc3L5tvZnwrAL+yjE4MxcEVVrrSjOFixkrsheu4VuBywn5PoUx2u23\n" +
        "oQlvlhhBVHdv0qrqxmHgEhthR9knCm0RITP93weM2a+WSoIxtwCzJgvVZj22XdOk\n" +
        "2wIDAQAB" +
        "-----END PUBLIC KEY-----";

    static private final String openSslPrivatePem = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n" +
        "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\n" +
        "0JZE9aZUg07U5gXVnA==\n" +
        "-----END ENCRYPTED PRIVATE KEY-----";

}
