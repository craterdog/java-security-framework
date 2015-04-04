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
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;
import org.slf4j.ext.XLogger;
import org.slf4j.ext.XLoggerFactory;


/**
 * This class provides a tool for generating new client certificates using a private
 * certificate authority.
 *
 * @author Derk Norton
 */
public class ClientCertificateSigner {

    static XLogger logger = XLoggerFactory.getXLogger(ClientCertificateSigner.class);

    static private final String CA_ALIAS = "Signer";

    /**
     * The main method for this application.  It expects the following arguments:
     * <ol>
     * <li>The name of the target environment (e.g. Sandbox, PreProd, Production, etc.).</li>
     * <li>The name of the client.</li>
     * <li>The path to the directory that contains the private certificate authorities and passwords.</li>
     * </ol>
     *
     * @param args The arguments that were passed into this program.
     */
    static public void main(String[] args) {
        String environment = args[0];
        String clientCertificatePrefix = args[1] + "-" + environment;
        String caKeyStorePrefix = args[2] + File.separator + environment + "-CA";

        try (
                FileReader pwReader = new FileReader(caKeyStorePrefix + ".pw");
                FileInputStream caInput = new FileInputStream(caKeyStorePrefix + ".p12");
                PemReader csrReader = new PemReader(new FileReader(clientCertificatePrefix + ".csr"));
                PemWriter pemWriter = new PemWriter(new FileWriter(clientCertificatePrefix + ".pem"))
                ) {
            logger.info("Loading the private certificate authority keys...");
            int size = new Tag(16).toString().length();
            char[] caPassword = new char[size];
            pwReader.read(caPassword);
            RsaCertificateManager manager = new RsaCertificateManager();
            KeyStore caKeyStore = manager.retrieveKeyStore(caInput, caPassword);
            PrivateKey caPrivateKey = manager.retrievePrivateKey(caKeyStore, CA_ALIAS, caPassword);
            X509Certificate caCertificate = manager.retrieveCertificate(caKeyStore, CA_ALIAS);

            logger.info("Reading in the certificate signing request...");
            byte[] requestBytes = csrReader.readPemObject().getContent();
            PKCS10CertificationRequest csr = new PKCS10CertificationRequest(requestBytes);

            logger.info("Generating and signing a new client certificate...");
            long lifetime = 30L /*years*/ * 365L /*days*/ * 24L /*hours*/ * 60L /*minutes*/
                    * 60L /*seconds*/ * 1000L /*milliseconds*/;
            BigInteger serialNumber = new BigInteger(RandomUtils.generateRandomBytes(16));
            X509Certificate clientCertificate = manager.signCertificateRequest(caPrivateKey, caCertificate, csr, serialNumber, lifetime);
            clientCertificate.verify(caCertificate.getPublicKey());

            logger.info("Writing out the certificates to a file...");
            pemWriter.writeObject(new PemObject("CERTIFICATE", clientCertificate.getEncoded()));
            pemWriter.writeObject(new PemObject("CERTIFICATE", caCertificate.getEncoded()));

        } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException |
                NoSuchProviderException | SignatureException | IOException e) {
            logger.info("An error occurred while attempting to generate the client certificate:", e);
            System.exit(1);
        }
        System.exit(0);
    }

}
