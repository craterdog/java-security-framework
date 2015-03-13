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
import java.util.List;

/**
 * This class defines a digitally notarized document.
 *
 * @author Derk Norton
 */
public class NotarizedDocument extends SmartObject<NotarizedDocument> {

    /*
     * This actual attributes that make up the notarized document.
     */
    public DocumentAttributes attributes;

    /**
     * The digital seals notarizing the document.
     */
    public List<DigitalSeal> seals;


    /**
     * The default constructor ensures that the custom attribute types (like tags) will be
     * formatted correctly when printed.
     */
    public NotarizedDocument() {
        this.addSerializableClass(Tag.class);
    }

}
