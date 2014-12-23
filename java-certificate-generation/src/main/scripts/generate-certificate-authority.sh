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

# This script generates a new private certificate authority (CA) keystore in PKCS12 format.  The
# script expects the following command line arguments:
#  * the name of the environment (e.g. Sandbox, PreProd, Production, etc.)
#
# The following two files will be created in the current directory:
#  * <environment name>-CA.p12 - the PKCS12 encrypted private certificate authority keystore
#  * <environment name>-CA.pw - a large random password that was used to encrypt the the keystore
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

# make sure that exactly one argument was passed in
test $# == 1 || die "Usage: ${PROGRAM} <environment name>${NEWLINE}Example: ${PROGRAM} Sandbox"

# generate a new private certificate authority keystore for the environment
java -classpath "${DIRECTORY}/../lib/*" craterdog.security.CertificateAuthorityGenerator $1


