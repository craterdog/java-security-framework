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

# This script generates a new RSA 2048 bit private key and an associated
# certificate signing request containing the public key.  This script
# expects the following command line arguments:
#  * The name of the target environment (e.g. Sandbox, PreProd, Production, etc.).
#  * The name of the client.
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
test $# -eq 2 || die "Usage: ${PROGRAM} <environment name> <client name> ${NEWLINE}Example: ${PROGRAM} Sandbox CoffeeBucks"

# do the work
openssl req -out $2-$1.csr -new -newkey rsa:2048 -nodes -keyout $2-$1.key