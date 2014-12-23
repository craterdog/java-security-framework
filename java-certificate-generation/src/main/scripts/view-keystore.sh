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

# This script allows the public key from a keystore to be viewed.  The
# script expects the following command line arguments:
#  * the name of the keystore (without any file suffix)
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
test $# -eq 1 || die "Usage: ${PROGRAM} <keystore name>${NEWLINE}Example: ${PROGRAM} CoffeeBucks-Sandbox"

# do the work
openssl pkcs12 -in $1.p12 -passin file:$1.pw -clcerts -nokeys | openssl x509 -pubkey -text


