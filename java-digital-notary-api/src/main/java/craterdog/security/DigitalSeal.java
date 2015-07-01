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

/**
 * This class defines a digital seal that is used to sign a document.
 *
 * @author Derk Norton
 */
public final class DigitalSeal extends SmartObject<DigitalSeal> {

    /**
     * The actual attributes that make up the digital seal.
     */
    public SealAttributes attributes;

    /**
     * A base 32 encoding of the bytes that were generated as a signature of the seal attributes.
     * The signature must be generated using the following steps:
     * <ol>
     * <li>Format the attributes as a string.</li>
     * <li>Extract the characters of the string into a "UTF-8" based byte array.</li>
     * <li>Generate the signature bytes for that array using the algorithm specified in the <code>Watermark</code> of the signed document.</li>
     * <li>Encode the signature bytes as a base 32 string using the craterdog.utils.Base32Utils class.</li>
     * </ol>
     */
    public String notarySignature;

}
