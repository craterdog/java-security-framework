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

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import craterdog.security.CertificateManager;
import craterdog.security.RsaCertificateManager;
import java.io.IOException;
import java.security.PrivateKey;

/**
 * This class handles the unmarshaling of a private key from an encrypted PEM string.
 *
 * @author Derk Norton
 */
public class PrivateKeyDeserializer extends JsonDeserializer<PrivateKey> {

    static private final CertificateManager manager = new RsaCertificateManager();

    private final char[] password;


    public PrivateKeyDeserializer() {
        this.password = null;
    }


    public PrivateKeyDeserializer(char[] password) {
        this.password = password;
    }


    @Override
    public PrivateKey deserialize(JsonParser p, DeserializationContext ctxt)
            throws IOException, JsonProcessingException {
        PrivateKey privateKey = null;
        if (password != null) {
            privateKey = manager.decodePrivateKey(p.getValueAsString(), password);
        }
        return privateKey;
    }

}
