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
import craterdog.smart.SmartObject;
import org.joda.time.DateTime;

/**
 * This class defines the attributes that make up an digital seal that is used to sign
 * a document.
 *
 * @author Derk Norton
 */
public final class DigitalSeal extends SmartObject<DigitalSeal> {

    /**
     * The unique identifier for the notary key that was used to generate the signature.
     */
    public Tag notaryKeyId;

    /**
     * A base 32 encoding of the SHA256 hash of the byte encoding for the public verification key
     * associated with the signing key used to generate the signature.
     */
    public String sha256VerificationKeyHash;

    /**
     * The date and time that the document was notarized.
     */
    public DateTime timestamp;

    /**
     * The type of document that this seal notarizes.
     */
    public String documentType;

    /**
     * A base 32 encoding of the bytes that were generated as a signature of the document. The
     * signature must be generated using the following steps:
     * <ol>
     * <li>Format the document as a string.</li>
     * <li>Extract the characters of the string into a "UTF-8" based byte array.</li>
     * <li>Generate the signature bytes for that array using the algorithm specified in the <code>Watermark</code>.</li>
     * <li>Encode the signature bytes as a base 32 string using the craterdog.utils.Base32Utils class.</li>
     * </ol>
     */
    public String documentSignature;


    /**
     * The default constructor ensures that the custom attribute types (like tags) will be
     * formatted correctly when printed.
     */
    public DigitalSeal() {
        this.addSerializableClass(Tag.class);
    }

}
