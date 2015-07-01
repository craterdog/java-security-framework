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

import craterdog.primitives.Tag;
import craterdog.security.mappers.NotaryKeyModule;
import craterdog.smart.SmartObject;
import java.security.PrivateKey;
import java.security.PublicKey;


/**
 * This class defines the attributes associated with a notary key.  A notary key has a private
 * part (signing key) that is used to sign notarized documents.  It also has a public part
 * (verification key) that is used to verify that a document was signed using the notary key.
 *
 * @author Derk Norton
 */
public final class NotaryKey extends SmartObject<NotaryKey> {

    /**
     * The unique identifier for the notary key.
     */
    public Tag keyId;

    /**
     * The private key that is used for signing a notarized document.
     */
    public PrivateKey signingKey;

    /**
     * The public key that is used to verify the signature on a notarized document.
     */
    public PublicKey verificationKey;

    /**
     * The lifetime of the key along with the version of the signing algorithm used to generate it.
     */
    public Watermark watermark;


    /**
     * The default constructor makes sure that the public and private keys can be marshalled
     * properly into JSON.
     */
    public NotaryKey() {
        this.addSerializableClass(new NotaryKeyModule());
    }

}
