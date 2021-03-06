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

import org.junit.AfterClass;
import static org.junit.Assert.assertEquals;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.ext.XLogger;
import org.slf4j.ext.XLoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 * This unit test tests the functionality of the encrypted property placeholder configurer.
 *
 * @author Derk Norton
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration
public class EncryptedPropertyConfigurerTest {

    static XLogger logger = XLoggerFactory.getXLogger(EncryptedPropertyConfigurerTest.class);

    @Configuration
    @PropertySource("classpath:EncryptedPropertyConfigurerTest.properties")
    static class Config {
        @Bean
        static PropertySourcesPlaceholderConfigurer propertySourcesPlaceholderConfigurer() {
            return new EncryptedPropertyConfigurer("XbZHQYKRQcBoBXqU0G43Rw==");
        }
    }


    /**
     * Log a message at the beginning of the tests.
     */
    @BeforeClass
    public static void setUpClass() {
        logger.info("Running EncryptedPropertyConfigurer Unit Tests...\n");
    }


    /**
     * Log a message at the end of the tests.
     */
    @AfterClass
    public static void tearDownClass() {
        logger.info("EncryptedPropertyConfigurer Unit Tests Completed.\n");
    }


    /**
     * Test of conversion of an encrypted property.
     */
    @Test
    public void testRoundTripConversion() {
        logger.info("Testing round trip conversion of encrypted property...");
        String expResult = "private";
        EncryptedPropertyConfigurer configurer = new EncryptedPropertyConfigurer();
        String propertyValue = configurer.encryptPropertyValue(expResult);
        logger.info("  PropertyValue: {}", propertyValue);
        String result = configurer.convertPropertyValue(propertyValue);
        assertEquals(expResult, result);
        logger.info("Round trip conversion of encrypted property testing completed.\n");
    }

    @Value("${unencrypted.value}") String unencryptedValue;
    @Value("${encrypted.value}") String decryptedValue;

    /**
     * This unit test makes sure that the spring injection is working correctly.
     */
    @Test
    public void testSpringIntegration() {
        logger.info("Testing spring injection of encrypted and unencrypted properties...");
        assertEquals("unencryptedString", unencryptedValue);
        assertEquals("decryptedString", decryptedValue);
        logger.info("Spring injection of encrypted and unencrypted properties testing completed.\n");
    }

}
