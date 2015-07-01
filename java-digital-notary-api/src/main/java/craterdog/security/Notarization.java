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

import craterdog.smart.SmartObject;
import java.io.IOException;
import java.net.URI;
import java.security.PublicKey;

/**
 * This interface defines the methods that must be implemented by all based digital notaries.
 *
 * @author Derk Norton
 */
public interface Notarization {

    /**
     * For a notary seal that expires after one minute.
     */
    static public final int VALID_FOR_ONE_MINUTE = 60;

    /**
     * For a notary seal that expires after one hour.
     */
    static public final int VALID_FOR_ONE_HOUR = VALID_FOR_ONE_MINUTE * 60;

    /**
     * For a notary seal that expires after one day.
     */
    static public final int VALID_FOR_ONE_DAY = VALID_FOR_ONE_HOUR * 24;

    /**
     * For a notary seal that expires after one week.
     */
    static public final int VALID_FOR_ONE_WEEK = VALID_FOR_ONE_DAY * 7;

    /**
     * For a notary seal that expires after one month (30 days).
     */
    static public final int VALID_FOR_ONE_MONTH = VALID_FOR_ONE_DAY * 30;

    /**
     * For a notary seal that expires after one year.
     */
    static public final int VALID_FOR_ONE_YEAR = VALID_FOR_ONE_DAY * 365;

    /**
     * For a notary seal that never expires.
     */
    static public final int VALID_FOR_FOREVER = Integer.MAX_VALUE;

    /**
     * This method generates a new notary key consisting of an asymmetric (public/private) key pair
     * based on the algorithm implemented by the specific notary implementation.
     *
     * @return The newly generated notary key.
     */
    NotaryKey generateNotaryKey();

    /**
     * This method serializes, as a JSON string, the specified notary key encrypting the
     * private signing key using the specified password.
     *
     * @param notaryKey The notary key to be serialized.
     * @param password The password to be used to encrypt the signing key.
     * @return A JSON string representing the notary key.
     */
    String serializeNotaryKey(NotaryKey notaryKey, char[] password);

    /**
     * This method de-serializes, from a JSON string, a notary key using the specified
     * password to decrypt the signing key.
     *
     * @param json The JSON string representing the notary key.
     * @param password The password to be used to decrypt the signing key.
     * @return The reconstituted notary key.
     * @throws java.io.IOException
     */
    NotaryKey deserializeNotaryKey(String json, char[] password) throws IOException;

    /**
     * This method generates a new citation using the specified location URI and document content.
     *
     * @param location A reference to the location of the specified document.
     * @param document The document being cited.
     * @return A new citation referring to the document.
     */
    Citation generateCitation(URI location, String document);

    /**
     * This method checks to see if the specified citation is valid.
     *
     * @param citation The citation to be validated.
     * @param document The document referenced by the citation.
     * @return Whether or not the citation is valid.
     */
    boolean citationIsValid(Citation citation, String document);

    /**
     * This method generates a new citation using the specified location URI and document content.
     *
     * @param location A reference to the location of the specified document.
     * @param document The document being cited.
     * @return A new citation referring to the document.
     */
    Citation generateCitation(URI location, SmartObject<? extends SmartObject<?>> document);

    /**
     * This method checks to see if the specified citation is valid.
     *
     * @param citation The citation to be validated.
     * @param document The document referenced by the citation.
     * @return Whether or not the citation is valid.
     */
    boolean citationIsValid(Citation citation, SmartObject<? extends SmartObject<?>> document);

    /**
     * This method generates a watermark defining the lifetime of a new document as well as
     * the version of the algorithm used to sign and verify the document.
     *
     * @param secondsToLive The number of seconds the document should be valid
     * from the current date and time.
     * @return The newly generated watermark.
     */
    Watermark generateWatermark(int secondsToLive);

    /**
     * This method checks to see if the watermark is still valid.
     *
     * @param watermark The watermark to be validated.
     * @return Whether or not the watermark is valid.
     */
    boolean watermarkIsValid(Watermark watermark);

    /**
     * This method generates a base 32 encoded signature of the specified document using
     * the specified notary key.
     *
     * @param document The document to be signed.
     * @param notaryKey The notary key used to sign the document.
     * @return The base 32 encoded signature.
     */
    String generateSignature(String document, NotaryKey notaryKey);

    /**
     * This method verifies that the specified document and signature match using the
     * specified verification key.
     *
     * @param document The document to be validated.
     * @param signature The base 32 encoded signature of the document.
     * @param verificationKey The public key that should be used to verify the signature.
     * @return Whether or not the signature is valid.
     */
    boolean signatureIsValid(String document, String signature, PublicKey verificationKey);

    /**
     * This method generates a base 32 encoded signature of the specified document using
     * the specified notary key.
     *
     * @param document The document to be signed.
     * @param notaryKey The notary key used to sign the document.
     * @return The base 32 encoded signature.
     */
    String generateSignature(SmartObject<? extends SmartObject<?>> document, NotaryKey notaryKey);

    /**
     * This method verifies that the specified document and signature match using the
     * specified verification key.
     *
     * @param document The document to be validated.
     * @param signature The base 32 encoded signature of the document.
     * @param verificationKey The public key that should be used to verify the signature.
     * @return Whether or not the signature is valid.
     */
    boolean signatureIsValid(SmartObject<? extends SmartObject<?>> document, String signature, PublicKey verificationKey);

    /**
     * This method generates a digital seal from the specified document using the specified
     * private notary key.
     *
     * @param documentType The type of document being notarized.
     * @param document The document to be notarized.
     * @param notaryKey The notary key used to notarize the document.
     * @param certificate A reference to the digital certificate that is associated with the notary key.
     * @return The newly generated digital seal.
     */
    DigitalSeal notarizeDocument(String documentType, String document, NotaryKey notaryKey, Citation certificate);

    /**
     * This method uses the specified public verification key to verify that the specified
     * digital seal is valid for the specified document.
     *
     * @param document The notarized document to be verified.
     * @param seal The digital seal for the document.
     * @param verificationKey The verification key of the notary that signed the document.
     * @return Whether or not the digital seal is valid.
     */
    boolean documentIsValid(String document, DigitalSeal seal, PublicKey verificationKey);

    /**
     * This method generates a digital seal from the specified document using the specified
     * private notary key.
     *
     * @param documentType The type of document being notarized.
     * @param document The document to be notarized.
     * @param notaryKey The notary key used to notarize the document.
     * @param certificate A reference to the digital certificate that is associated with the notary key.
     * @return The newly generated digital seal.
     */
    DigitalSeal notarizeDocument(String documentType, SmartObject<? extends SmartObject<?>> document, NotaryKey notaryKey, Citation certificate);

    /**
     * This method uses the specified public verification key to verify that the specified
     * digital seal is valid for the specified document.
     *
     * @param document The notarized document to be verified.
     * @param seal The digital seal for the document.
     * @param verificationKey The verification key of the notary that signed the document.
     * @return Whether or not the digital seal is valid.
     */
    boolean documentIsValid(SmartObject<? extends SmartObject<?>> document, DigitalSeal seal, PublicKey verificationKey);

}
