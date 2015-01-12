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

import craterdog.utils.RandomUtils;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.junit.Test;
import org.slf4j.ext.XLogger;
import org.slf4j.ext.XLoggerFactory;


/**
 * This unit test tests the <code>RsaCertificateManager</code> class.
 *
 * @author Derk Norton
 */
public class ExampleCodeTest {

    static XLogger logger = XLoggerFactory.getXLogger(ExampleCodeTest.class);


    /**
     * Round trip tests of all the methods.
     * @throws java.lang.Exception
     */
    @Test
    public void testRoundTrips() throws Exception {
        logger.entry();
        RsaCertificateManager manager = new RsaCertificateManager();

        logger.info("Generating a new key pair for the CA.");
        KeyPair caKeyPair = manager.generateKeyPair();
        PublicKey caPublicKey = caKeyPair.getPublic();
        PrivateKey caPrivateKey = caKeyPair.getPrivate();

        logger.info("Generating a self-signed private CA certificate.");
        String caSubject = "CN=Crater Dog Technologies™ Private Certificate Authority, O=Crater Dog Technologies™, C=US";
        BigInteger caSerialNumber = new BigInteger(RandomUtils.generateRandomBytes(16));
        long lifetime = 30L /*years*/ * 365L /*days*/ * 24L /*hours*/ * 60L /*minutes*/ * 60L /*seconds*/ * 1000L /*milliseconds*/;
        X509Certificate caCertificate = manager.createCertificateAuthority(caPrivateKey, caPublicKey, caSubject, caSerialNumber, lifetime);
        caCertificate.verify(caPublicKey);

        logger.info("Creating the CA key store.");
        String caKeyName = "Signer";
        char[] caPassword = "verysecret".toCharArray();
        KeyStore caKeyStore = manager.createPkcs12KeyStore(caKeyName, caPassword, caPrivateKey, caCertificate);

        logger.info("Generating a new key pair for the client.");
        KeyPair clientKeyPair = manager.generateKeyPair();
        PublicKey clientPublicKey = clientKeyPair.getPublic();
        PrivateKey clientPrivateKey = clientKeyPair.getPrivate();

        logger.info("Generating a private CA-signed client certificate.");
        String clientSubject = "CN=Derk Norton, O=Crater Dog Technologies™, OU=Engineering";
        BigInteger clientSerialNumber = new BigInteger(RandomUtils.generateRandomBytes(16));
        X509Certificate clientCertificate = manager.createCertificate(caPrivateKey, caCertificate, clientPublicKey, clientSubject, clientSerialNumber, lifetime);
        clientCertificate.verify(caCertificate.getPublicKey());

        logger.info("Creating the client key store.");
        String clientKeyName = "Client";
        char[] clientPassword = "kindasecret".toCharArray();
        List<X509Certificate> certificates = new ArrayList<>();
        certificates.add(clientCertificate);
        certificates.add(caCertificate);
        KeyStore clientKeyStore = manager.createPkcs12KeyStore(clientKeyName, clientPassword, clientPrivateKey, certificates);

        logger.info("Creating a new certificate signing request...");
        KeyPair keyPair = manager.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        String subject = "CN=craterdog.com, O=Crater Dog Technologies™, OU=Engineering, ST=Colorado, C=USA";
        PKCS10CertificationRequest csr = manager.createSigningRequest(privateKey, publicKey, subject);

        logger.info("Signing the certificate...");
        BigInteger serialNumber = new BigInteger(RandomUtils.generateRandomBytes(16));
        X509Certificate certificate = manager.signCertificateRequest(caPrivateKey, caCertificate, csr, serialNumber, lifetime);
        certificate.verify(caPublicKey);

        logger.exit();
    }

}
