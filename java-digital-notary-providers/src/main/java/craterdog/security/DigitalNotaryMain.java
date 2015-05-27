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
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.MissingOptionException;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.io.FileUtils;

/**
 * This class is used to run the <code>RsaDigitalNotary</code> methods from
 * the command line.
 *
 * @author web-online
 */
public class DigitalNotaryMain extends DefaultParser {

    /**
     * Notarization implementation
     */
    private static final Notarization notarization = new RsaDigitalNotary();

    public static void main(String[] args) throws ParseException, IOException {
        String script_name = "generate-notary-key";
        DigitalNotaryMain main = new DigitalNotaryMain();
        Option pubfileOption = Option.builder("pubfile").hasArg().argName("filename").desc("pem encoded public key input file").build();
        Option prvfileOption = Option.builder("prvfile").hasArg().argName("filename").desc("pem encoded PKCS#8 format encrypted private key input file").build();

        try {
            main.parse(args, pubfileOption, prvfileOption);
            NotaryKey notaryKey = notarization.generateNotaryKey();

            String pubfile = main.cmd.getOptionValue(pubfileOption.getOpt());
            String prvfile = main.cmd.getOptionValue(prvfileOption.getOpt());
            if (pubfile != null || prvfile != null) {
                if (pubfile == null)
                    throw new MissingOptionException("Missing option: pubfile");
                if (prvfile == null)
                    throw new MissingOptionException("Missing option: prvfile");

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
            writeObjectToFile("notary-key.json", notarization.serializeNotaryKey(notaryKey, password));
        } catch (ParseException | FileNotFoundException ex) {
            System.out.println(ex.getMessage());
            main.printHelp(script_name);
            System.exit(1);
        } catch (ClassCastException ex) {
            String message = ex.getMessage();
            if (message != null && message.contains("PEMEncryptedKeyPair cannot be cast to org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo")) {
                System.out.println("Incorrect format for prvfile. Expected PKCS#8 format encrypted private key.");
                main.printHelp(script_name);
                System.exit(1);
            }
        }
    }

    /**
     * Utility method for writing an Object out to a file.
     * @param fileName the name of the file to write
     * @param data the data to be written by calling toString
     * @throws IOException
     */
    public static void writeObjectToFile(String fileName, Object data) throws IOException {
        FileUtils.writeStringToFile(new File(fileName), data.toString());
    }

    /**
     * Parse the command line arguments with the given additionalOptions.
     * @param arguments command line arguments
     * @param additionalOptions options to add for parsing/validation
     * @throws ParseException
     */
    public void parse(String[] arguments, Option... additionalOptions) throws ParseException {
        Option helpOption = new Option("help", false, "print this message");
        options = new Options().addOption(helpOption);
        for (Option option : additionalOptions) {
            options.addOption(option);
        }
        try {
            parse(options, arguments, null);
        } finally {
            // help hides any other exceptions
            if (cmd.hasOption(helpOption.getOpt())) {
                throw new ParseException(helpOption.getOpt());
            }
        }
    }

    /**
     * Print a help message with a usage
     * @param script_name
     */
    public void printHelp(String script_name) {
        new HelpFormatter().printHelp(script_name, options, true);
    }

}
