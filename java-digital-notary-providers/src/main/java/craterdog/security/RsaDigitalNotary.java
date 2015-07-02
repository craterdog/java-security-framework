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

import static craterdog.security.Notarization.VALID_FOR_ONE_YEAR;
import craterdog.primitives.Tag;
import craterdog.security.mappers.NotaryKeyModule;
import craterdog.smart.SmartObject;
import craterdog.smart.SmartObjectMapper;
import craterdog.smart.UseToStringAsValueMixIn;
import craterdog.utils.Base32Utils;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.joda.time.DateTime;
import org.slf4j.ext.XLogger;
import org.slf4j.ext.XLoggerFactory;

/**
 * This class can be used to sign and verify digital notarized documents using a private/public
 * key pair.  It uses RSA-2048 for asymmetric (public/private) key signature generation and
 * verification.
 *
 * @author Derk Norton
 */
public final class RsaDigitalNotary implements Notarization {

    static private final XLogger logger = XLoggerFactory.getXLogger(RsaDigitalNotary.class);

    static private final String HASH_ALGORITHM = "SHA256";

    private final CertificateManager manager = new RsaCertificateManager();
    private final MessageCryptex cryptex = new RsaAesMessageCryptex();

    /**
     * The signing algorithm used to sign and verify the documents.
     */
    public final String algorithm = cryptex.getAsymmetricSignatureAlgorithm();

    /**
     * The major version number of the implementation of this digital notary.
     */
    public final int majorVersion = 1;

    /**
     * The minor version number of the implementation of this digital notary.
     */
    public final int minorVersion = 0;


    @Override
    public NotaryKey generateNotaryKey() {
        logger.entry();

        logger.debug("Generating a new RSA key pair...");
        KeyPair keyPair = manager.generateKeyPair();
        PrivateKey signingKey = keyPair.getPrivate();
        PublicKey verificationKey = keyPair.getPublic();

        logger.debug("Creating a notary key...");
        NotaryKey notaryKey = new NotaryKey();
        notaryKey.keyId = new Tag();
        notaryKey.signingKey = signingKey;
        notaryKey.verificationKey = verificationKey;

        logger.debug("Adding a watermark...");
        notaryKey.watermark = generateWatermark(VALID_FOR_ONE_YEAR);

        logger.exit(notaryKey);
        return notaryKey;
    }


    @Override
    public String serializeNotaryKey(NotaryKey notaryKey, char[] password) {
        logger.entry(notaryKey);
        String json;
        try {
            SmartObjectMapper mapper = new SmartObjectMapper(new NotaryKeyModule(password));
            mapper.addMixIn(Tag.class, UseToStringAsValueMixIn.class);
            json = mapper.writeValueAsString(notaryKey);
        } catch (Exception e) {
            throw new RuntimeException("Unable to serialize a notary key.", e);
        }
        logger.exit(json);
        return json;
    }


    @Override
    public NotaryKey deserializeNotaryKey(String json, char[] password) throws IOException {
        logger.entry(json);
        SmartObjectMapper mapper = new SmartObjectMapper(new NotaryKeyModule(password));
        mapper.addMixIn(Tag.class, UseToStringAsValueMixIn.class);
        NotaryKey notaryKey = mapper.readValue(json, NotaryKey.class);
        logger.exit(notaryKey);
        return notaryKey;
    }


    @Override
    public Citation generateCitation(URI location, String document) {
        logger.entry(location, document);
        Citation citation = new Citation();
        citation.documentLocation = location;
        citation.sha256DocumentHash = cryptex.hashString(document);
        logger.exit(citation);
        return citation;
    }


    @Override
    public boolean citationIsValid(Citation citation, String document) {
        logger.entry(citation);
        boolean result = true;
        try {
            validateCitation(citation, document);
        } catch (Exception e) {
            logger.debug("A '{}' exception was thrown while validating the following citation: {}", e.getMessage(), citation);
            result = false;
        }
        logger.exit(result);
        return result;
    }


    @Override
    public Citation generateCitation(URI location, SmartObject<? extends SmartObject<?>> document) {
        logger.entry(location, document);
        Citation citation = generateCitation(location, document.toString());
        logger.exit(citation);
        return citation;
    }


    @Override
    public boolean citationIsValid(Citation citation, SmartObject<? extends SmartObject<?>> document) {
        logger.entry(citation);
        boolean result = citationIsValid(citation, document.toString());
        logger.exit(result);
        return result;
    }


    @Override
    public String generateSignature(String document, NotaryKey notaryKey) {
        logger.entry(document, notaryKey);

        logger.debug("Verifying that the notary key has not expired...");
        Watermark watermark = notaryKey.watermark;
        validateWatermark(watermark);

        logger.debug("Signing the document...");
        PrivateKey signingKey = notaryKey.signingKey;
        String signature = generateSignature(document, signingKey);

        logger.exit(signature);
        return signature;
    }


    @Override
    public boolean signatureIsValid(String document, String signature, PublicKey verificationKey) {
        logger.entry(document, signature, verificationKey);
        boolean result = true;
        try {
            validateSignature(document, signature, verificationKey);
        } catch (Exception e) {
            logger.debug("A '{}' exception was thrown while validating the following signature: {}", e.getMessage(), signature);
            result = false;
        }
        logger.exit(result);
        return result;
    }


    @Override
    public String generateSignature(SmartObject<? extends SmartObject<?>> document, NotaryKey notaryKey) {
        logger.entry(document, notaryKey);

        logger.debug("Verifying that the notary key has not expired...");
        Watermark watermark = notaryKey.watermark;
        validateWatermark(watermark);

        logger.debug("Signing the document...");
        PrivateKey signingKey = notaryKey.signingKey;
        String documentString = document.toString();
        String signature = generateSignature(documentString, signingKey);

        logger.exit(signature);
        return signature;
    }


    @Override
    public boolean signatureIsValid(SmartObject<? extends SmartObject<?>> document, String signature, PublicKey verificationKey) {
        logger.entry(document, signature, verificationKey);
        boolean result = true;
        try {
            String documentString = document.toString();
            validateSignature(documentString, signature, verificationKey);
        } catch (Exception e) {
            logger.debug("A '{}' exception was thrown while validating the following signature: {}", e.getMessage(), signature);
            result = false;
        }
        logger.exit(result);
        return result;
    }


    @Override
    public Watermark generateWatermark(int secondsToLive) {
        logger.entry(secondsToLive);
        Watermark watermark = new Watermark();
        watermark.signingAlgorithm = algorithm;
        watermark.majorVersion = majorVersion;
        watermark.minorVersion = minorVersion;
        watermark.creationTimestamp = DateTime.now();
        watermark.expirationTimestamp = watermark.creationTimestamp.plusSeconds(secondsToLive);
        logger.exit(watermark);
        return watermark;
    }


    @Override
    public boolean watermarkIsValid(Watermark watermark) {
        logger.entry(watermark);
        boolean result = true;
        try {
            validateWatermark(watermark);
        } catch (Exception e) {
            logger.debug("A '{}' exception was thrown while validating the following watermark: {}", e.getMessage(), watermark);
            result = false;
        }
        logger.exit(result);
        return result;
    }


    @Override
    public DigitalSeal notarizeDocument(String documentType, String document, NotaryKey notaryKey, Citation certificateCitation) {
        logger.entry(document, notaryKey, certificateCitation);

        logger.debug("Verifying that the notary key has not expired...");
        Watermark watermark = notaryKey.watermark;
        validateWatermark(watermark);

        logger.debug("Signing the document...");
        PrivateKey signingKey = notaryKey.signingKey;
        String signature = generateSignature(document, signingKey);

        logger.debug("Create a digital notary seal...");
        SealAttributes attributes = new SealAttributes();
        attributes.timestamp = DateTime.now();
        attributes.documentType = documentType;
        attributes.documentSignature = signature;
        attributes.certificateCitation = certificateCitation;
        DigitalSeal seal = new DigitalSeal();
        seal.attributes = attributes;
        validateAttributes(seal);
        seal.notarySignature = generateSignature(attributes.toString(), signingKey);

        logger.exit(seal);
        return seal;
    }


    @Override
    public boolean documentIsValid(String document, DigitalSeal seal, PublicKey verificationKey) {
        logger.entry(document, verificationKey, seal);
        boolean result = true;
        try {
            logger.debug("Validating the digital seal's attributes...");
            validateAttributes(seal);

            logger.debug("Validating the notary signature of the document...");
            String signature = seal.attributes.documentSignature;
            validateSignature(document, signature, verificationKey);

            logger.debug("Validating the notary signature of the digital seal...");
            validateSignature(seal.attributes.toString(), seal.notarySignature, verificationKey);
        } catch (Exception e) {
            logger.debug("A '{}' exception was thrown while validating the following document: {}", e.getMessage(), document);
            result = false;
        }
        logger.exit(result);
        return result;
    }


    @Override
    public DigitalSeal notarizeDocument(String documentType, SmartObject<? extends SmartObject<?>> document, NotaryKey notaryKey, Citation certificateCitation) {
        logger.entry(document, notaryKey, certificateCitation);

        logger.debug("Verifying that the notary key has not expired...");
        Watermark watermark = notaryKey.watermark;
        validateWatermark(watermark);

        logger.debug("Signing the document...");
        String documentString = document.toString();
        PrivateKey signingKey = notaryKey.signingKey;
        String signature = generateSignature(documentString, signingKey);

        logger.debug("Create a digital notary seal...");
        SealAttributes attributes = new SealAttributes();
        attributes.timestamp = DateTime.now();
        attributes.documentType = documentType;
        attributes.documentSignature = signature;
        attributes.certificateCitation = certificateCitation;
        DigitalSeal seal = new DigitalSeal();
        seal.attributes = attributes;
        validateAttributes(seal);
        seal.notarySignature = generateSignature(attributes.toString(), signingKey);

        logger.exit(seal);
        return seal;
    }


    @Override
    public boolean documentIsValid(SmartObject<? extends SmartObject<?>> document, DigitalSeal seal, PublicKey verificationKey) {
        logger.entry(document, verificationKey, seal);
        boolean result = true;
        try {
            logger.debug("Validating the digital seal's attributes...");
            validateAttributes(seal);

            logger.debug("Validating the notary signature of the document...");
            String documentString = document.toString();
            String signature = seal.attributes.documentSignature;
            validateSignature(documentString, signature, verificationKey);

            logger.debug("Validating the notary signature of the digital seal...");
            validateSignature(seal.attributes.toString(), seal.notarySignature, verificationKey);
        } catch (Exception e) {
            logger.debug("A '{}' exception was thrown while validating the following document: {}", e.getMessage(), document);
            result = false;
        }
        logger.exit(result);
        return result;
    }


    private void validateCitation(Citation citation, String document) {
        if (citation.documentLocation == null || citation.sha256DocumentHash == null ||
                document == null || document.isEmpty() || citation.sha256DocumentHash.isEmpty() ||
                !citation.sha256DocumentHash.equals(cryptex.hashString(document))) {
            throw new RuntimeException("The citation is invalid.");
        }
    }


    private void validateWatermark(Watermark watermark) {
        if (watermark.expirationTimestamp.isBeforeNow()) {
            throw new RuntimeException("The notary key has expired.");
        }
    }


    private void validateAttributes(DigitalSeal seal) {
        SealAttributes attributes = seal.attributes;
        if (attributes.certificateCitation == null || attributes.timestamp == null ||
                attributes.documentType == null || attributes.documentType.isEmpty() ||
                attributes.documentSignature == null || attributes.documentSignature.isEmpty()) {
            throw new RuntimeException("The following seal has invalid attributes: " + seal);
        }
    }


    private String generateSignature(String document, PrivateKey signingKey) {
        try {
            byte[] documentBytes = document.getBytes("UTF-8");
            byte[] signatureBytes = cryptex.signBytes(signingKey, documentBytes);
            String signature = Base32Utils.encode(signatureBytes);
            return signature;
        } catch (Exception e) {
            throw new RuntimeException("Unable to notarize the following document due to a " + e.getMessage() + " exception: " + document);
        }
    }


    private void validateSignature(String document, String signature, PublicKey verificationKey) {
        try {
            byte[] documentBytes = document.getBytes("UTF-8");
            byte[] signatureBytes = Base32Utils.decode(signature);
            if (!cryptex.bytesAreValid(verificationKey, documentBytes, signatureBytes)) {
                throw new RuntimeException("The following document signature is invalid: " + signature);
            }
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("Unable to validate the following document due to a " + e.getMessage() + " exception: " + document);
        }
    }

}
