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
import craterdog.utils.RandomUtils;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
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
import java.util.ArrayList;
import java.util.List;
import org.slf4j.ext.XLogger;
import org.slf4j.ext.XLoggerFactory;


/**
 * This class provides a tool for generating and signing new client certificates using a
 * private certificate authority.
 *
 * @author Derk Norton
 */
public class ClientCertificateGenerator {

    static XLogger logger = XLoggerFactory.getXLogger(ClientCertificateGenerator.class);

    static private final String CA_ALIAS = "Signer";
    static private final String CLIENT_ALIAS = "Client";

    /**
     * The main method for this application.  It expects the following arguments:
     * <ol>
     * <li>The name of the target environment (e.g. Sandbox, PreProd, Production, etc.).</li>
     * <li>The name of the client.</li>
     * <li>The path to the directory that contains the private certificate authorities and passwords.</li>
     * <li>The subject string containing the CN, O, OU, C, etc. values.</li>
     * </ol>
     *
     * @param args The arguments that were passed into this program.
     */
    static public void main(String[] args) {
        String environment = args[0];
        String clientKeyStorePrefix = args[1] + "-" + environment;
        String caKeyStorePrefix = args[2] + File.separator + environment + "-CA";
        String subject = args[3];

        try (
                FileReader pwReader = new FileReader(caKeyStorePrefix + ".pw");
                FileInputStream caInput = new FileInputStream(caKeyStorePrefix + ".p12");
                FileWriter pwWriter = new FileWriter(clientKeyStorePrefix + ".pw");
                FileOutputStream clientOutput = new FileOutputStream(clientKeyStorePrefix + ".p12")
                ) {
            logger.info("Loading the private certificate authority keys...");
            int size = new Tag(16).toString().length();
            char[] caPassword = new char[size];
            pwReader.read(caPassword);
            MessageCryptex cryptex = new RsaAesMessageCryptex();
            RsaCertificateManager manager = new RsaCertificateManager();
            KeyStore caKeyStore = manager.retrieveKeyStore(caInput, caPassword);
            PrivateKey caPrivateKey = manager.retrievePrivateKey(caKeyStore, CA_ALIAS, caPassword);
            X509Certificate caCertificate = manager.retrieveCertificate(caKeyStore, CA_ALIAS);

            logger.info("Generating a new key pair for the client certificate...");
            KeyPair clientKeyPair = cryptex.generateKeyPair();
            PublicKey clientPublicKey = clientKeyPair.getPublic();
            PrivateKey clientPrivateKey = clientKeyPair.getPrivate();

            logger.info("Generating and signing a new client certificate...");
            long lifetime = 30L /*years*/ * 365L /*days*/ * 24L /*hours*/ * 60L /*minutes*/
                    * 60L /*seconds*/ * 1000L /*milliseconds*/;
            BigInteger serialNumber = new BigInteger(RandomUtils.generateRandomBytes(16));
            X509Certificate clientCertificate = manager.createCertificate(caPrivateKey,
                    caCertificate, clientPublicKey, subject, serialNumber, lifetime);
            clientCertificate.verify(caCertificate.getPublicKey());

            logger.info("Storing the new client certificate and private key in a key store...");
            char[] clientPassword = new Tag(16).toString().toCharArray();
            List<X509Certificate> certificates = new ArrayList<>();
            certificates.add(clientCertificate);
            certificates.add(caCertificate);
            KeyStore clientKeyStore = manager.createPkcs12KeyStore(CLIENT_ALIAS, clientPassword,
                    clientPrivateKey, certificates);

            logger.info("Writing out the key store and password to files...");
            manager.saveKeyStore(clientOutput, clientKeyStore, clientPassword);
            pwWriter.write(clientPassword);

        } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException |
                NoSuchProviderException | SignatureException | IOException e) {
            logger.error("An error occurred while attempting to generate the client certificate:", e);
            System.exit(1);
        }
        System.exit(0);
    }

    static private String buildSubject(String tenantId, String certificateId, String roleId) {
        StringBuilder builder = new StringBuilder();
        builder.append("CN=");
        builder.append(certificateId);
        builder.append(", O=");
        builder.append(tenantId);
        if (roleId != null) {
            builder.append(", OU=");
            builder.append(roleId);
        }
        return builder.toString();
    }

}
