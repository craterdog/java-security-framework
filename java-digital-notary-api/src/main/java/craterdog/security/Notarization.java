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
     * This method generates a digital seal from the specified document using the specified
     * private notary key.
     *
     * @param document The document to be notarized.
     * @param notaryKey The notary key used to notarize the document.
     * @return The newly generated digital seal.
     */
    DigitalSeal notarizeDocument(String document, NotaryKey notaryKey);

    /**
     * This method uses the specified public verification key to verify that the specified
     * digital seal is valid for the specified document.
     *
     * @param document The notarized document to be verified.
     * @param verificationKey The verification key of the notary that signed the document.
     * @param notarySeal The digital seal for the document.
     * @return Whether or not the digital seal is valid.
     */
    boolean documentIsValid(String document, PublicKey verificationKey, DigitalSeal notarySeal);

    /**
     * This method generates a digital seal from the specified document using the specified
     * private notary key.
     *
     * @param document The document to be notarized.
     * @param notaryKey The notary key used to notarize the document.
     * @return The newly generated digital seal.
     */
    DigitalSeal notarizeDocument(SmartObject<? extends SmartObject<?>> document, NotaryKey notaryKey);

    /**
     * This method uses the specified public verification key to verify that the specified
     * digital seal is valid for the specified document.
     *
     * @param document The notarized document to be verified.
     * @param verificationKey The verification key of the notary that signed the document.
     * @param notarySeal The digital seal for the document.
     * @return Whether or not the digital seal is valid.
     */
    boolean documentIsValid(SmartObject<? extends SmartObject<?>> document, PublicKey verificationKey, DigitalSeal notarySeal);

}
