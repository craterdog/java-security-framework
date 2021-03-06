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

# This script signs a new client certificate based on a certificate signing request (CSR).  The
# script expects the following command line arguments:
#  * The name of the target environment (e.g. Sandbox, PreProd, Production, etc.).
#  * The name of the client.
#  * The path to the directory that contains the private certificate authorities and passwords.
#
# The following file will be created in the current directory:
#  * <client name>-<environment name>.pem - the public certificate chain containing the new client certificate and signer public certificate
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
test $# -eq 3 || die "Usage: ${PROGRAM} <environment name> <client name> <ca directory path>${NEWLINE}Example: ${PROGRAM} Sandbox CoffeeBucks /some/secret/path/"

# create and sign a new client certificate based on the certificate signing request
java -classpath "${DIRECTORY}/../lib/*" craterdog.security.ClientCertificateSigner "$@"


