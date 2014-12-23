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
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import org.slf4j.ext.XLogger;
import org.slf4j.ext.XLoggerFactory;


/**
 * This class provides a tool for generating new private certificate authorities.
 *
 * @author Derk Norton
 */
public class CertificateAuthorityGenerator {

    static XLogger logger = XLoggerFactory.getXLogger(CertificateAuthorityGenerator.class);

    static private final String CA_ALIAS = "Signer";

    /**
     * The main method for this application.  It expects the following arguments:
     * 1) The name of the target environment (e.g. Sandbox, PreProd, Production, etc.).
     *
     * @param args The arguments that were passed into this program.
     */
    static public void main(String[] args) {
        String environment = args[0];
        String filePrefix = environment + "-CA";

        try (FileOutputStream output = new FileOutputStream(filePrefix + ".p12");
                FileWriter pwFile = new FileWriter(filePrefix + ".pw")) {
            logger.info("Generating a new key pair for the CA...");
            RsaCertificateManager manager = new RsaCertificateManager();
            KeyPair caKeyPair = manager.generateKeyPair();
            PublicKey caPublicKey = caKeyPair.getPublic();
            PrivateKey caPrivateKey = caKeyPair.getPrivate();

            logger.info("Generating a self-signed CA certificate...");
            String caSubject = "CN=Crater Dog Technologies " + environment + " Private Certificate Authority, O=Crater Dog Technologies, C=US";
            BigInteger caSerialNumber = new BigInteger(new Tag().toBytes());
            long lifetime = 30L /*years*/ * 365L /*days*/ * 24L /*hours*/ * 60L /*minutes*/ * 60L /*seconds*/ * 1000L /*milliseconds*/;
            X509Certificate caCertificate = manager.createCertificateAuthority(caPrivateKey, caPublicKey, caSubject, caSerialNumber, lifetime);
            caCertificate.verify(caPublicKey);

            logger.info("Creating the CA key store...");
            char[] caPassword = new Tag().toString().toCharArray();
            KeyStore caKeyStore = manager.createPkcs12KeyStore(CA_ALIAS, caPassword, caPrivateKey, caCertificate);

            logger.info("Writing out the key store and password to files...");
            manager.saveKeyStore(output, caKeyStore, caPassword);
            pwFile.write(caPassword);

        } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException |
                NoSuchProviderException | SignatureException | IOException e) {
            logger.info("An error occurred while attempting to generate the certificate authority:", e);
            System.exit(1);
        }
        System.exit(0);
    }

}
