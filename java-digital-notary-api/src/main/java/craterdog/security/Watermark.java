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
import org.joda.time.DateTime;

/**
 * This class defines the attributes that make up a watermark that defines the lifetime of a
 * document and the version of the signing algorithm used to sign it.
 *
 * @author Derk Norton
 */
public final class Watermark extends SmartObject<Watermark> {

    /**
     * The cryptographically secure signing algorithm that should be used to sign and verify all
     * parts of a document.
     */
    public String signingAlgorithm;

    /**
     * The major version number of the implementation of the notary class used to sign the document.
     * The major version number changes when version of the notary class is incompatible with
     * previous versions of the class for doing signing and verification.
     */
    public int majorVersion;

    /**
     * The minor version number of the implementation of the notary class used to sign the document.
     * The minor version number changes when new features are added, or bugs are fixed in
     * previous versions of the class for doing signing and verification. All minor versions under
     * the same major version should be compatible.
     */
    public int minorVersion;

    /**
     * The date and time that the document was created and became valid.
     */
    public DateTime creationTimestamp;

    /**
     * The date and time that the document will become no longer valid.
     */
    public DateTime expirationTimestamp;
}
