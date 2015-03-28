/************************************************************************
 * Copyright (c) Crater Dog Technologies(TM).  All Rights Reserved.     *
 ************************************************************************
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.        *
 *                                                                      *
 * This code is free software; you can redistribute it and/or modify it *
 * under the terms of The MIT License (MIT), as published by the Open   *
 * Source Initiative. (See http://opensource.org/licenses/MIT)          *
 ************************************************************************/
package craterdog.security.mappers;

import com.fasterxml.jackson.databind.module.SimpleModule;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * This class is a Jackson module that can be added to an object mapper to handle the serialization
 * of a notary key.  The private signing key is password protected.
 *
 * @author Derk Norton
 */
public class NotaryKeyModule extends SimpleModule {

    /**
     * This default constructor adds serializers and deserializers for the public and private keys
     * that make up a notary key.  The serializers will not serialize or deserialize the private
     * key.
     */
    public NotaryKeyModule() {
        super("NotaryKeyModule");
        addSerializer(PublicKey.class, new PublicKeySerializer());
        addDeserializer(PublicKey.class, new PublicKeyDeserializer());
        addSerializer(PrivateKey.class, new PrivateKeySerializer());
        addDeserializer(PrivateKey.class, new PrivateKeyDeserializer());
    }


    /**
     * This constructor adds serializers and deserializers for the public and private keys
     * that make up a notary key.
     * @param password The password to be used to encrypt the private key.
     */
    public NotaryKeyModule(char[] password) {
        super("NotaryKeyModule");
        addSerializer(PublicKey.class, new PublicKeySerializer());
        addDeserializer(PublicKey.class, new PublicKeyDeserializer());
        addSerializer(PrivateKey.class, new PrivateKeySerializer(password));
        addDeserializer(PrivateKey.class, new PrivateKeyDeserializer(password));
    }

}
