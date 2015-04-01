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

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.apache.commons.cli.BasicParser;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.MissingArgumentException;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.io.FileUtils;

/**
 * This class is used to run the <code>RsaDigitalNotary</code> methods from
 * the command line.
 *
 * @author Jeff Webb
 */
public class DigitalNotaryMain {

    private static final Notarization notarization = new RsaDigitalNotary();

    private static final String CMD_LINE_SYNTAX = "generate-notary-key [-pubfile <pem file> -prvfile <pem file>]";

    public static void main(String[] args) throws ParseException, IOException {
        HelpFormatter help = new HelpFormatter();
        Options options = new Options();
        options.addOption("help", false, "print this message");
        options.addOption("pubfile", true, "public key input file");
        options.addOption("prvfile", true, "private key input file");

        try {
            CommandLine cli = new BasicParser().parse(options, args);
            String pubfile = cli.getOptionValue("pubfile");
            String prvfile = cli.getOptionValue("prvfile");

            NotaryKey notaryKey = notarization.generateNotaryKey();

            if (pubfile != null || prvfile != null) {
                if (pubfile == null)
                    throw new MissingArgumentException("Missing option: pubfile");
                if (prvfile == null)
                    throw new MissingArgumentException("Missing option: prvfile");

                CertificateManager manager = new RsaCertificateManager();
                PublicKey publicKey = manager.decodePublicKey(FileUtils.readFileToString(new File(pubfile)));
                char[] password = System.console().readPassword("input private key password: ");
                PrivateKey privateKey = manager.decodePrivateKey(FileUtils.readFileToString(new File(prvfile)), password);

                notaryKey.signingKey = privateKey;
                notaryKey.verificationKey = publicKey;

                // make sure it works
                DigitalSeal seal = notarization.notarizeDocument("test document", "test document", notaryKey);
                notarization.documentIsValid("test document", seal, publicKey);
            }
            char[] password = System.console().readPassword("verficationKey password: ");
            System.out.println(notarization.serializeNotaryKey(notaryKey, password));
        } catch (MissingArgumentException | FileNotFoundException ex) {
            System.out.println(ex.getMessage());
            help.printHelp(CMD_LINE_SYNTAX, options);
            System.exit(1);
        }
    }

}
