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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;


/**
 * This class provides an RSA specific implementation of the CertificateManager abstract class.
 *
 * @author Derk Norton
 */
public final class RsaCertificateManager extends CertificateManager {

    static private final String ASYMMETRIC_SIGNATURE_ALGORITHM = "SHA256withRSA";
    static private final String PROVIDER_NAME = BouncyCastleProvider.PROVIDER_NAME;


    static {
        if (Security.getProvider(PROVIDER_NAME) == null) {
            logger.debug("Adding security provider: {}", PROVIDER_NAME);
            Security.addProvider(new BouncyCastleProvider());
        }
    }


    @Override
    public X509Certificate createCertificateAuthority(PrivateKey privateKey, PublicKey publicKey,
            String subjectString, BigInteger serialNumber, long lifetime) {
        try {
            logger.entry();

            logger.debug("Initializing the certificate generator...");
            Date startDate = new Date();
            Date expiryDate = new Date(startDate.getTime() + lifetime);
            X500Principal issuer = new X500Principal(subjectString);
            X500Principal subject = new X500Principal(subjectString);
            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuer, serialNumber,
                    startDate, expiryDate, subject, publicKey);
            JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
            builder.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(publicKey));
            builder.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(publicKey));
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));  // adds CA:TRUE extension
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign));
            ContentSigner signer = new JcaContentSignerBuilder(ASYMMETRIC_SIGNATURE_ALGORITHM).build(privateKey);
            X509Certificate result = new JcaX509CertificateConverter().setProvider(PROVIDER_NAME)
                    .getCertificate(builder.build(signer));
            result.checkValidity(new Date());
            result.verify(result.getPublicKey());

            logger.exit();
            return result;

        } catch (CertIOException | CertificateException | InvalidKeyException | OperatorCreationException |
                NoSuchProviderException | NoSuchAlgorithmException | SignatureException e) {
            RuntimeException exception = new RuntimeException("An unexpected exception occurred while attempting to generate a new certificate authority.", e);
            logger.error(exception.toString());
            throw exception;
        }
    }


    /**
     * This method creates a new certificate signing request (CSR) using the specified key pair
     * and subject string.  This is a convenience method that really should be part of the
     * <code>CertificateManagement</code> interface except that it depends on a Bouncy Castle
     * class in the signature.  The java security framework does not have a similar class so it
     * has been left out of the interface.
     *
     * @param privateKey The private key to be used to sign the request.
     * @param publicKey The corresponding public key that is to be wrapped in the new certificate.
     * @param subjectString The subject string to be included in the generated certificate.
     *
     * @return The newly created CSR.
     */
    public PKCS10CertificationRequest createSigningRequest(PrivateKey privateKey,
            PublicKey publicKey, String subjectString) {
        try {
            logger.entry();

            logger.debug("Creating the CSR...");
            X500Principal subject = new X500Principal(subjectString);
            ContentSigner signer = new JcaContentSignerBuilder(ASYMMETRIC_SIGNATURE_ALGORITHM).build(privateKey);
            PKCS10CertificationRequest result = new JcaPKCS10CertificationRequestBuilder(subject, publicKey)
                    .setLeaveOffEmptyAttributes(true).build(signer);

            logger.exit();
            return result;

        } catch (OperatorCreationException e) {
            RuntimeException exception = new RuntimeException("An unexpected exception occurred while attempting to generate a new certificate signing request.", e);
            logger.error(exception.toString());
            throw exception;
        }
    }


    /**
     * This method signs a certificate signing request (CSR) using the specified certificate
     * authority (CA).   This is a convenience method that really should be part of the
     * <code>CertificateManagement</code> interface except that it depends on a Bouncy Castle
     * class in the signature.  The java security framework does not have a similar class so it
     * has been left out of the interface.
     *
     * @param caPrivateKey The private key for the certificate authority.
     * @param caCertificate The certificate containing the public key for the certificate authority.
     * @param request The certificate signing request (CSR) to be signed.
     * @param serialNumber The serial number for the new certificate.
     * @param lifetime How long the certificate should be valid.
     *
     * @return The newly signed certificate.
     */
    public X509Certificate signCertificateRequest(PrivateKey caPrivateKey, X509Certificate caCertificate,
            PKCS10CertificationRequest request, BigInteger serialNumber, long lifetime) {
        try {
            logger.entry();

            logger.debug("Extract public key and subject from the CSR...");
            PublicKey publicKey = new JcaPEMKeyConverter().getPublicKey(request.getSubjectPublicKeyInfo());
            String subject = request.getSubject().toString();

            logger.debug("Generate and sign the certificate...");
            X509Certificate result = createCertificate(caPrivateKey, caCertificate, publicKey, subject, serialNumber, lifetime);

            logger.exit();
            return result;

        } catch (PEMException e) {
            RuntimeException exception = new RuntimeException("An unexpected exception occurred while attempting to sign a certificate.", e);
            logger.error(exception.toString());
            throw exception;
        }
    }


    @Override
    public X509Certificate createCertificate(PrivateKey caPrivateKey, X509Certificate caCertificate,
            PublicKey publicKey, String subjectString, BigInteger serialNumber, long lifetime) {
        try {
            logger.entry();

            logger.debug("Initializing the certificate generator...");
            Date startDate = new Date();
            Date expiryDate = new Date(startDate.getTime() + lifetime);
            X509Certificate issuer = caCertificate;
            X500Principal subject = new X500Principal(subjectString);
            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuer, serialNumber,
                    startDate, expiryDate, subject, publicKey);
            JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
            builder.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(caCertificate));
            builder.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(publicKey));
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

            ContentSigner signer = new JcaContentSignerBuilder(ASYMMETRIC_SIGNATURE_ALGORITHM).build(caPrivateKey);
            X509Certificate result = new JcaX509CertificateConverter().setProvider(PROVIDER_NAME)
                    .getCertificate(builder.build(signer));
            result.checkValidity(new Date());
            result.verify(caCertificate.getPublicKey());

            logger.exit();
            return result;

        } catch (CertIOException | OperatorCreationException | CertificateException | NoSuchAlgorithmException |
                InvalidKeyException | NoSuchProviderException | SignatureException e) {
            RuntimeException exception = new RuntimeException("An unexpected exception occurred while attempting to generate a new certificate.", e);
            logger.error(exception.toString());
            throw exception;
        }
    }


    /**
     * This method encodes a certificate signing request (CSR) into a string for transport purposes.
     * This is a convenience method that really should be part of the
     * <code>CertificateManagement</code> interface except that it depends on a Bouncy Castle
     * class in the signature.  The java security framework does not have a similar class so it
     * has been left out of the interface.
     *
     * @param csr The certificate signing request.
     * @return The encoded certificate signing request string.
     */
    public String encodeSigningRequest(PKCS10CertificationRequest csr) {
        logger.entry();
        try (StringWriter swriter = new StringWriter(); PemWriter pwriter = new PemWriter(swriter)) {
            pwriter.writeObject(new PemObject("CERTIFICATE REQUEST", csr.getEncoded()));
            pwriter.flush();
            String result = swriter.toString();
            logger.exit();
            return result;
        } catch (IOException e) {
            RuntimeException exception = new RuntimeException("An unexpected exception occurred while attempting to encode a certificate signing request.", e);
            logger.error(exception.toString());
            throw exception;
        }
    }


    /**
     * This method decodes a certificate signing request (CSR) from a string.  This is a convenience
     * method that really should be part of the <code>CertificateManagement</code> interface except
     * that it depends on a Bouncy Castle class in the signature.  The java security framework does
     * not have a similar class so it has been left out of the interface.
     *
     * @param csr The encoded certificate signing request.
     * @return The decoded certificate signing request.
     */
    public PKCS10CertificationRequest decodeSigningRequest(String csr) {
        logger.entry();
        try (StringReader sreader = new StringReader(csr); PemReader preader = new PemReader(sreader)) {
            byte[] requestBytes = preader.readPemObject().getContent();
            PKCS10CertificationRequest result = new PKCS10CertificationRequest(requestBytes);
            logger.exit();
            return result;
        } catch (IOException e) {
            RuntimeException exception = new RuntimeException("An unexpected exception occurred while attempting to decode a certificate signing request.", e);
            logger.error(exception.toString());
            throw exception;
        }
    }


    @Override
    public String encodeCertificate(X509Certificate certificate) {
        logger.entry();
        try (StringWriter swriter = new StringWriter(); PemWriter pwriter = new PemWriter(swriter)) {
            pwriter.writeObject(new PemObject("CERTIFICATE", certificate.getEncoded()));
            pwriter.flush();
            String result = swriter.toString();
            logger.exit();
            return result;
        } catch (IOException | CertificateEncodingException e) {
            RuntimeException exception = new RuntimeException("An unexpected exception occurred while attempting to encode a certificate.", e);
            logger.error(exception.toString());
            throw exception;
        }
    }


    @Override
    public X509Certificate decodeCertificate(String pem) {
        logger.entry();
        try (StringReader sreader = new StringReader(pem); PemReader preader = new PemReader(sreader)) {
            byte[] requestBytes = preader.readPemObject().getContent();
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            ByteArrayInputStream in = new ByteArrayInputStream(requestBytes);
            X509Certificate result = (X509Certificate) factory.generateCertificate(in);
            logger.exit();
            return result;
        } catch (IOException | CertificateException e) {
            RuntimeException exception = new RuntimeException("An unexpected exception occurred while attempting to decode a certificate.", e);
            logger.error(exception.toString());
            throw exception;
        }
    }

}
