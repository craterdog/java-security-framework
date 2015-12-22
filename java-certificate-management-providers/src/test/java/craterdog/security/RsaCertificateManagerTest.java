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

import craterdog.primitives.Tag;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.AfterClass;
import static org.junit.Assert.*;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.ext.XLogger;
import org.slf4j.ext.XLoggerFactory;


/**
 * This unit test tests the <code>RsaCertificateManager</code> class.
 *
 * @author Derk Norton
 */
public class RsaCertificateManagerTest {

    static XLogger logger = XLoggerFactory.getXLogger(RsaCertificateManagerTest.class);


    /**
     * Log a message at the beginning of the tests.
     */
    @BeforeClass
    public static void setUpClass() {
        logger.info("Running RsaCertificateManager Unit Tests...\n");
    }


    /**
     * Log a message at the end of the tests.
     */
    @AfterClass
    public static void tearDownClass() {
        logger.info("RsaCertificateManager Unit Tests Completed.\n");
    }



    /**
     * Round trip tests of all the methods.
     * @throws java.lang.Exception
     */
    @Test
    public void testRoundTrips() throws Exception {
        logger.info("Testing RSA certificate manager round trip...");
        MessageCryptex cryptex = new RsaAesMessageCryptex();
        RsaCertificateManager manager = new RsaCertificateManager();

        logger.info("  Generating a new key pair for the CA.");
        KeyPair caKeyPair = cryptex.generateKeyPair();
        PublicKey caPublicKey = caKeyPair.getPublic();
        PrivateKey caPrivateKey = caKeyPair.getPrivate();

        logger.info("  Encoding and decoding the public key.");
        String pem = manager.encodePublicKey(caPublicKey);
        PublicKey publicKey = manager.decodePublicKey(pem);
        String pem2 = manager.encodePublicKey(publicKey);
        assertEquals("  The encoded and decoded public keys don't match.", pem, pem2);

        logger.info("  Encoding and decoding the private key with password.");
        char[] caPassword = new Tag().toString().toCharArray();
        pem = manager.encodePrivateKey(caPrivateKey, caPassword);
        PrivateKey privateKey = manager.decodePrivateKey(pem, caPassword);
        pem2 = manager.encodePrivateKey(privateKey, caPassword);
        PrivateKey privateKey2 = manager.decodePrivateKey(pem2, caPassword);
        assertEquals("  The encoded and decoded private keys don't match.", privateKey, privateKey2);

        logger.info("  Generating a self-signed CA certificate.");
        String caSubject = "CN=Crater Dog Technologies Private Certificate Authority, O=Crater Dog Technologies, C=US";
        BigInteger caSerialNumber = new BigInteger("633667679794240096984750112005585982774");
        long lifetime = 30L /*years*/ * 365L /*days*/ * 24L /*hours*/ * 60L /*minutes*/ * 60L /*seconds*/ * 1000L /*milliseconds*/;
        X509Certificate caCertificate = manager.createCertificateAuthority(caPrivateKey, caPublicKey, caSubject, caSerialNumber, lifetime);
        caCertificate.verify(caPublicKey);

        logger.info("  Creating the CA key store.");
        String caKeyName = "Signer";
        KeyStore caKeyStore = manager.createPkcs12KeyStore(caKeyName, caPassword, caPrivateKey, caCertificate);

        logger.info("  Writing out the key store and password to a files and reading them back in.");
        try (FileWriter pwWriter = new FileWriter("src/test/java/craterdog/security/ca.pw");
                FileOutputStream caOutput = new FileOutputStream("src/test/java/craterdog/security/ca.p12")) {
            pwWriter.write(caPassword);
            manager.saveKeyStore(caOutput, caKeyStore, caPassword);
        }
        try (FileReader pwReader = new FileReader("src/test/java/craterdog/security/ca.pw");
                FileInputStream caInput = new FileInputStream("src/test/java/craterdog/security/ca.p12")) {
            pwReader.read(caPassword);
            caKeyStore = manager.retrieveKeyStore(caInput, caPassword);
        }
        caCertificate = manager.retrieveCertificate(caKeyStore, caKeyName);
        caPrivateKey = manager.retrievePrivateKey(caKeyStore, caKeyName, caPassword);

        logger.info("  Generating a new key pair for the client.");
        KeyPair clientKeyPair = cryptex.generateKeyPair();
        PublicKey clientPublicKey = clientKeyPair.getPublic();
        PrivateKey clientPrivateKey = clientKeyPair.getPrivate();

        logger.info("  Generating a CA-signed client certificate.");
        String clientSubject = "CN=Derk Norton, O=Crater Dog Technologies, OU=Engineering";
        BigInteger clientSerialNumber = new BigInteger("421589557931194050198712193612390239378");
        X509Certificate clientCertificate = manager.createCertificate(caPrivateKey, caCertificate, clientPublicKey, clientSubject, clientSerialNumber, lifetime);
        clientCertificate.verify(caCertificate.getPublicKey());

        logger.info("  Encoding and decoding the public certificate.");
        pem = manager.encodeCertificate(clientCertificate);
        clientCertificate = manager.decodeCertificate(pem);
        pem2 = manager.encodeCertificate(clientCertificate);
        assertEquals("Encoded Certificate", pem, pem2);

        logger.info("  Creating the client key store.");
        String clientKeyName = "Client";
        char[] clientPassword = "kindasecret".toCharArray();
        List<X509Certificate> certificates = new ArrayList<>();
        certificates.add(clientCertificate);
        certificates.add(caCertificate);
        KeyStore clientKeyStore = manager.createPkcs12KeyStore(clientKeyName, clientPassword, clientPrivateKey, certificates);
        X509Certificate clientCertificate2 = manager.retrieveCertificate(clientKeyStore, clientKeyName);
        assertEquals("Client Certificate", clientCertificate, clientCertificate2);

        logger.info("  Encoding and decoding the private key.");
        String encodedKey = manager.encodeKeyStore(clientKeyStore, clientPassword);
        KeyStore clientKeyStore2 = manager.decodeKeyStore(encodedKey, clientPassword);
        X509Certificate clientCertificate3 = manager.retrieveCertificate(clientKeyStore2, clientKeyName);
        assertEquals("Client Certificate", clientCertificate2, clientCertificate3);

        logger.info("  Creating a new certificate signing request...");
        KeyPair keyPair = cryptex.generateKeyPair();
        privateKey = keyPair.getPrivate();
        publicKey = keyPair.getPublic();
        String subject = "CN=craterdog.com, O=Crater Dog Technologies™, OU=Engineering, ST=Colorado, C=USA";
        PKCS10CertificationRequest csr = manager.createSigningRequest(privateKey, publicKey, subject);

        logger.info("  Encoding and decoding the certificate signing request...");
        String encodedCsr = manager.encodeSigningRequest(csr);
        PKCS10CertificationRequest csr2 = manager.decodeSigningRequest(encodedCsr);
        assertEquals("Certificate Signing Request", csr, csr2);

        logger.info("  Signing the certificate...");
        BigInteger serialNumber = new BigInteger("483496575641745816855721203115343299496");
        X509Certificate certificate = manager.signCertificateRequest(caPrivateKey, caCertificate, csr, serialNumber, lifetime);
        certificate.verify(caPublicKey);

        logger.info("RSA certificate manager round trip testing completed.\n");
    }

}
