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

# This script encrypts a configuration property value using an AES 128 bit key.  The resulting
# encrypted value will include a "{AES-128}" prefix so that it can automatically be decrypted
# by the EncryptedPropertyConfigurer spring placeholder class.

# capture the program name
DIRECTORY=$(dirname $0)
PROGRAM=$(basename $0)

# define the error function
function die {
    echo $1 1>&2
    exit 1
}

# make sure that only one parameter was passed into the script
test $# == 1 || die "Usage: ${PROGRAM} <property value>"

# encrypt the property value
java -classpath "${DIRECTORY}/../lib/*" craterdog.security.PropertyEncryptor $1


