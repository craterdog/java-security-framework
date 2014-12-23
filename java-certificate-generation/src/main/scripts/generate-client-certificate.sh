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
#  * the name of the environment (e.g. Sandbox, PreProd, Production, etc.)
#  * the name of the client
#  * the path to the certificate authority files and their associated passwords
#  * the tenantId for the certificate (optional)
#  * the roleId for the certificate (optional, but can only be specified if a tenantId is also specified)
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
test $# -gt 2 && test $# -lt 6 || die "Usage: ${PROGRAM} <environment name> <client name> <ca directory path> [<tenantId> [<roleId>]]${NEWLINE}Example: ${PROGRAM} Sandbox CoffeeBucks /some/secret/path/ AG72AL0DB6123DC3S7LJZ2T7MW"

# execute the java program to do the work
if [ $# -gt 4 ]; then
    java -classpath "${DIRECTORY}/../lib/*" craterdog.security.ClientCertificateGenerator $1 $2 $3 $4 $5
elif [ $# -gt 3 ]; then
    java -classpath "${DIRECTORY}/../lib/*" craterdog.security.ClientCertificateGenerator $1 $2 $3 $4
else
    java -classpath "${DIRECTORY}/../lib/*" craterdog.security.ClientCertificateGenerator $1 $2 $3
fi


