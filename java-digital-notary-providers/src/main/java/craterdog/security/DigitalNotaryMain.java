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

/**
 * This class is used to run the <code>RsaDigitalNotary</code> methods from
 * the command line.
 *
 * @author Jeff Webb
 */
public class DigitalNotaryMain {

    private static final Notarization notarization = new RsaDigitalNotary();

    public static void main(String[] args) {
        NotaryKey notaryKey = notarization.generateNotaryKey();
        System.out.println(notaryKey);
    }

}
