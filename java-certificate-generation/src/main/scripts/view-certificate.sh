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

# This script allows a public certificate stored in a pem file to be viewed.  The
# script expects the following command line arguments:
#  * the name of the certificate (without any file suffix)
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
test $# -eq 1 || die "Usage: ${PROGRAM} <certificate name>${NEWLINE}Example: ${PROGRAM} CoffeeBucks-Sandbox"

# do the work
cat $1.pem | openssl x509 -pubkey -text


