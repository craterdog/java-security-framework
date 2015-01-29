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

import java.security.PublicKey;
import org.junit.AfterClass;
import static org.junit.Assert.assertTrue;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.ext.XLogger;
import org.slf4j.ext.XLoggerFactory;


/**
 * This class implements unit tests for the <code>RsaDigitalNotary</code> class.
 *
 * @author Derk
 */
public class RsaDigitalNotaryTest {

    static XLogger logger = XLoggerFactory.getXLogger(RsaDigitalNotaryTest.class);


    /**
     * Log a message at the beginning of the tests.
     */
    @BeforeClass
    public static void setUpClass() {
        logger.info("Running RsaDigitalNotary Unit Tests...\n");
    }


    /**
     * Log a message at the end of the tests.
     */
    @AfterClass
    public static void tearDownClass() {
        logger.info("RsaDigitalNotary Unit Tests Completed.\n");
    }


    @Test
    public void testSigningAndVerification() throws Exception {
        logger.info("Testing round trip digital signing and verification...");

        logger.info("  Generating a new notary key...");
        Notarization notary = new RsaDigitalNotary();
        NotaryKey notaryKey = notary.generateNotaryKey();

        logger.info("  Notarizing a string document...");
        String documentType = "Test Document";
        String stringDocument = "This document MUST be notarized!";
        DigitalSeal seal = notary.notarizeDocument(documentType, stringDocument, notaryKey);

        logger.info("  Verifying the notary seal...");
        PublicKey verificationKey = notaryKey.verificationKey;
        assertTrue("  Invalid notary seal.", notary.documentIsValid(stringDocument, seal, verificationKey));

        logger.info("  Generating a new watermark...");
        Watermark watermark = notary.generateWatermark(Notarization.VALID_FOR_ONE_YEAR);
        logger.info("  The watermark: {}", watermark);

        logger.info("  Notarizing a smart document...");
        documentType = "Watermark";
        seal = notary.notarizeDocument(documentType, watermark, notaryKey);

        logger.info("  Verifying the notary seal...");
        assertTrue("  Invalid notary seal.", notary.documentIsValid(watermark, seal, verificationKey));

        logger.info("Round trip digital signing and verification test completed.\n");
    }

}
