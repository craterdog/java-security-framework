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
#  * the name of the environment (e.g. Sandbox, PreProd, Production, etc.)
#  * the name of the client
#  * the path to the certificate authority files and their associated passwords
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

# execute the java program to do the work
java -classpath "${DIRECTORY}/../lib/*" craterdog.security.ClientCertificateSigner $1 $2 $3


