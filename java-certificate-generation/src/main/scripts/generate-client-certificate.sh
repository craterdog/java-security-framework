#!/bin/bash
########################################################################
# Copyright (c) Crater Dog Technologies(TM).  All Rights Reserved.     #
########################################################################
# DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.        #
#                                                                      #
# This code is free software; you can redistribute it and/or modify it #
# under the terms of The MIT License (MIT), as published by the Open   #
# Source Initiative. (See http://opensource.org/licenses/MIT)          #
########################################################################

# This script generates a new client certificate and private key in PKCS12 format.  The
# script expects the following command line arguments:
#  * The name of the target environment (e.g. Sandbox, PreProd, Production, etc.).
#  * The name of the client.
#  * The path to the directory that contains the private certificate authorities and passwords.
#  * The subject string containing the CN, O, OU, C, etc. values.
#
# The following two files will be created in the current directory:
#  * <client name>-<environment name>.p12 - the PKCS12 encrypted client private key and certificate keystore
#  * <client-name>-<environment name>.pw - a large random password that was used to encrypt the the keystore
#

# capture the directory and program name
DIRECTORY=$(dirname $0)
PROGRAM=$(basename $0)
NEWLINE=$'\n'

# define the error function
function die {
    echo "$1" 1>&2
    exit 1
}

# make sure that the right number of command line arguments were passed in
test $# -eq 4 || die "Usage: ${PROGRAM} <environment name> <client name> <ca directory path> <subject> ${NEWLINE}Example: ${PROGRAM} Sandbox CoffeeBucks /some/secret/path/ 'CN=http://acmecoffee.com,O=Acme Coffee,C=US'"

# generate a new client certificate keystore for the environment
java -classpath "${DIRECTORY}/../lib/*" craterdog.security.ClientCertificateGenerator "$@"