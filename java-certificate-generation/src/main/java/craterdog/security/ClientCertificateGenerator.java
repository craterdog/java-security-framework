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
     * 1) The name of the target environment (e.g. Sandbox, PreProd, Production, etc.).
     * 2) The name of the client.
     * 3) The path to the directory that contains the private certificate authorities and passwords.
     * 4) An optional tenantId for the new certificate.
     * 5) An optional roleId for the new certificate (requires a tenantId).
     *
     * @param args The arguments that were passed into this program.
     */
    static public void main(String[] args) {
        String environment = args[0];
        String clientKeyStorePrefix = args[1] + "-" + environment;
        String caKeyStorePrefix = args[2] + File.separator + environment + "-CA";
        String tenantId = args.length > 3 ? args[3] : new Tag().toString();
        String roleId = args.length > 4 ? args[4] : null;
        String certificateId = new Tag().toString();

        try (
                FileReader pwReader = new FileReader(caKeyStorePrefix + ".pw");
                FileInputStream caInput = new FileInputStream(caKeyStorePrefix + ".p12");
                FileWriter pwWriter = new FileWriter(clientKeyStorePrefix + ".pw");
                FileOutputStream clientOutput = new FileOutputStream(clientKeyStorePrefix + ".p12")
                ) {
            logger.info("Loading the private certificate authority keys...");
            int size = new Tag().toBytes().length;
            char[] caPassword = new char[size];
            pwReader.read(caPassword);
            RsaCertificateManager manager = new RsaCertificateManager();
            KeyStore caKeyStore = manager.retrieveKeyStore(caInput, caPassword);
            PrivateKey caPrivateKey = manager.retrievePrivateKey(caKeyStore, CA_ALIAS, caPassword);
            X509Certificate caPublicKey = manager.retrieveCertificate(caKeyStore, CA_ALIAS);

            logger.info("Generating a new key pair for the client certificate...");
            KeyPair clientKeyPair = manager.generateKeyPair();
            PublicKey clientPublicKey = clientKeyPair.getPublic();
            PrivateKey clientPrivateKey = clientKeyPair.getPrivate();

            logger.info("Generating and signing a new client certificate...");
            String subject = buildSubject(tenantId, certificateId, roleId);
            long lifetime = 30L /*years*/ * 365L /*days*/ * 24L /*hours*/ * 60L /*minutes*/
                    * 60L /*seconds*/ * 1000L /*milliseconds*/;
            BigInteger serialNumber = new BigInteger(new Tag(certificateId).toBytes());
            X509Certificate clientCertificate = manager.createCertificate(caPrivateKey,
                    caPublicKey, clientPublicKey, subject, serialNumber, lifetime);
            clientCertificate.verify(caPublicKey.getPublicKey());

            logger.info("Storing the new client certificate and private key in a key store...");
            char[] clientPassword = new Tag().toString().toCharArray();
            List<X509Certificate> certificates = new ArrayList<>();
            certificates.add(clientCertificate);
            certificates.add(caPublicKey);
            KeyStore clientKeyStore = manager.createPkcs12KeyStore(CLIENT_ALIAS, clientPassword,
                    clientPrivateKey, certificates);

            logger.info("Writing out the key store and password to files...");
            manager.saveKeyStore(clientOutput, clientKeyStore, clientPassword);
            pwWriter.write(clientPassword);

        } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException |
                NoSuchProviderException | SignatureException | IOException e) {
            logger.info("An error occurred while attempting to generate the client certificate:", e);
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
