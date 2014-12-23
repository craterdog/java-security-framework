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

import org.slf4j.ext.XLogger;
import org.slf4j.ext.XLoggerFactory;


/**
 * This class provides a tool for encrypting configuration properties.  It can be run using the
 * script that comes with the distribution bundle (.tar.gz file).  The result will be the encrypted
 * and base 32 encoded property value with the required encryption prefix.  For example:
 * * <pre>
 * {@code
 * scripts$ ./encrypt-property.sh mypassword
 *   Property Value: mypassword
 *   Encrypted Value: {AES-128}QJTZAB1R1NDDVVAHZBB2VSP1R0
 * scripts$
 * }
 * </pre>
 *
 * @author Derk Norton
 */
public class PropertyEncryptor {

    static XLogger logger = XLoggerFactory.getXLogger(PropertyEncryptor.class);

    static private final EncryptedPropertyConfigurer encryptor = new EncryptedPropertyConfigurer();


    /**
     * The main method for this application.
     *
     * @param args The arguments that were passed into this program.  There should only be one
     * argument, the property value to be encrypted.
     */
    static public void main(String[] args) {
        String propertyValue = args[0];
        logger.info("Property Value: " + propertyValue);
        String encryptedValue = encryptor.encryptPropertyValue(propertyValue);
        logger.info("Encrypted Value: " + encryptedValue);
    }

}
