/*
 * Copyright (c) 2024 SoftHSM Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*****************************************************************************
 MLKEMPublicKey.cpp

 ML-KEM (Kyber) public key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "MLKEMPublicKey.h"
#include <string.h>

// Set the type
/*static*/ const char* MLKEMPublicKey::type = "Abstract ML-KEM public key";

// Check if the key is of the given type
bool MLKEMPublicKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

// Get the bit length
unsigned long MLKEMPublicKey::getBitLength() const
{
	// Return bit length based on parameter set
	// ML-KEM-512: 800 bytes = 6400 bits
	// ML-KEM-768: 1184 bytes = 9472 bits
	// ML-KEM-1024: 1568 bytes = 12544 bits
	return getPublicKey().size() * 8;
}

// Get the output length
unsigned long MLKEMPublicKey::getOutputLength() const
{
	return getPublicKey().size();
}

// Setters for the ML-KEM public key components
void MLKEMPublicKey::setPublicKey(const ByteString& inPublicKey)
{
	publicKey = inPublicKey;
}

void MLKEMPublicKey::setParameterSet(unsigned long inParameterSet)
{
	parameterSet = inParameterSet;
}

// Getters for the ML-KEM public key components
const ByteString& MLKEMPublicKey::getPublicKey() const
{
	return publicKey;
}

unsigned long MLKEMPublicKey::getParameterSet() const
{
	return parameterSet;
}

// Serialisation
ByteString MLKEMPublicKey::serialise() const
{
	ByteString paramBytes(parameterSet);
	return paramBytes.serialise() + publicKey.serialise();
}

bool MLKEMPublicKey::deserialise(ByteString& serialised)
{
	ByteString dParam = ByteString::chainDeserialise(serialised);
	ByteString dPublicKey = ByteString::chainDeserialise(serialised);

	if ((dParam.size() == 0) || (dPublicKey.size() == 0))
	{
		return false;
	}

	setParameterSet(dParam.long_val());
	setPublicKey(dPublicKey);

	return true;
}
