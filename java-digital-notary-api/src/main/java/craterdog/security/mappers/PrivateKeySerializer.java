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

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import craterdog.security.CertificateManager;
import craterdog.security.RsaCertificateManager;
import java.io.IOException;
import java.security.PrivateKey;

/**
 * This class handles the marshaling of a private key into a PEM string.  Since
 * the private key must be kept secret this class simply returns a default message.
 *
 * @author Derk Norton
 */
public class PrivateKeySerializer extends JsonSerializer<PrivateKey> {

    static private final CertificateManager manager = new RsaCertificateManager();

    private final char[] password;


    public PrivateKeySerializer() {
        this.password = null;
    }


    public PrivateKeySerializer(char[] password) {
        this.password = password;
    }


    @Override
    public void serialize(PrivateKey privateKey, JsonGenerator generator, SerializerProvider provider)
            throws IOException, JsonProcessingException {
        String pemValue = "<not shown>";
        if (password != null) {
            pemValue = manager.encodePrivateKey(privateKey, password);
        }
        generator.writeString(pemValue);
    }

}
