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

import craterdog.utils.Base64Utils;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.util.StringValueResolver;


/**
 * This class overrides the functionality of the Spring framework's PropertyPlaceHolderConfigurer
 * class to handle encrypted properties.
 *
 * @author Derk Norton
 */
public class EncryptedPropertyConfigurer extends PropertySourcesPlaceholderConfigurer {

    static private final MessageCryptex cryptex = new RsaAesMessageCryptex();  // must be this implementation!
    static private final String ENCRYPTED_NOTATION = "{AES-128}";
    static private final String DEFAULT_ENCODED_KEY = "XbZHQYKRQcBoBXqU0G43Rw==";  // base 64 encoded AES-128 key

    private final SecretKey key;


    /**
     * The default constructor uses the default base 64 encoded secret key for doing the encryption.
     */
    public EncryptedPropertyConfigurer() {
        this.key = new SecretKeySpec(Base64Utils.decode(DEFAULT_ENCODED_KEY), cryptex.getSymmetricKeyType());
    }


    /**
     * This constructor uses a user specified base 64 encoded secret key for doing the encryption.
     *
     * @param encodedKey The base 64 encoded string containing the AES-128 secret key for encryption.
     */
    public EncryptedPropertyConfigurer(String encodedKey) {
        this.key = new SecretKeySpec(Base64Utils.decode(encodedKey), cryptex.getSymmetricKeyType());
    }


    /**
     * This method encrypts a property value in such a way that it can be placed in a properties
     * file and automatically decrypted using this placeholder configurer.
     *
     * @param propertyValue The property value to be encrypted.
     * @return The encrypted property value.
     */
    public String encryptPropertyValue(String propertyValue) {
        byte[] bytes = cryptex.encryptString(key, propertyValue);
        String encryptedValue = Base64Utils.encode(bytes);
        return ENCRYPTED_NOTATION + encryptedValue;
    }

    /**
     * This is method is needed because of https://jira.springsource.org/browse/SPR-8928
     *
     * @param beanFactoryToProcess The factory to be used for the processing.
     * @param valueResolver The value resolver to be used.
     */
    @Override
    protected void doProcessProperties(ConfigurableListableBeanFactory beanFactoryToProcess,
            final StringValueResolver valueResolver) {
        StringValueResolver valueConvertingResolver = (String strVal) ->
                convertPropertyValue(valueResolver.resolveStringValue(strVal));
        super.doProcessProperties(beanFactoryToProcess, valueConvertingResolver);
    }

    /**
     * This method decrypts a base 64 encoded, AES-128 encrypted, property value that is prefixed
     * with "{AES-128}".
     *
     * @param propertyValue The property value to be decrypted.
     * @return The decrypted property value.
     */
    @Override
    protected String convertPropertyValue(String propertyValue) {
        if (StringUtils.isNotBlank(propertyValue) && propertyValue.startsWith(ENCRYPTED_NOTATION)) {
            propertyValue = propertyValue.substring(ENCRYPTED_NOTATION.length());
            byte[] bytes = Base64Utils.decode(propertyValue);
            propertyValue = cryptex.decryptString(key, bytes);
        }
        return propertyValue;
    }

}
