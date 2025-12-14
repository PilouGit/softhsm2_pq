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
 MLDSAPrivateKey.cpp

 ML-DSA (Dilithium) private key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "MLDSAPrivateKey.h"
#include <string.h>

// Set the type
/*static*/ const char* MLDSAPrivateKey::type = "Abstract ML-DSA private key";

// Check if the key is of the given type
bool MLDSAPrivateKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

// Get the bit length
unsigned long MLDSAPrivateKey::getBitLength() const
{
	return getPrivateKey().size() * 8;
}

// Get the output length
unsigned long MLDSAPrivateKey::getOutputLength() const
{
	return getPrivateKey().size();
}

// Setters for the ML-DSA private key components
void MLDSAPrivateKey::setPrivateKey(const ByteString& inPrivateKey)
{
	privateKey = inPrivateKey;
}

void MLDSAPrivateKey::setParameterSet(unsigned long inParameterSet)
{
	parameterSet = inParameterSet;
}

// Getters for the ML-DSA private key components
const ByteString& MLDSAPrivateKey::getPrivateKey() const
{
	return privateKey;
}

unsigned long MLDSAPrivateKey::getParameterSet() const
{
	return parameterSet;
}

// Serialisation
ByteString MLDSAPrivateKey::serialise() const
{
	ByteString paramBytes(parameterSet);
	return paramBytes.serialise() + privateKey.serialise();
}

bool MLDSAPrivateKey::deserialise(ByteString& serialised)
{
	ByteString dParam = ByteString::chainDeserialise(serialised);
	ByteString dPrivateKey = ByteString::chainDeserialise(serialised);

	if ((dParam.size() == 0) || (dPrivateKey.size() == 0))
	{
		return false;
	}

	setParameterSet(dParam.long_val());
	setPrivateKey(dPrivateKey);

	return true;
}

// PKCS#8 encoding (use raw format for PQC)
ByteString MLDSAPrivateKey::PKCS8Encode()
{
	return serialise();
}

// PKCS#8 decoding (use raw format for PQC)
bool MLDSAPrivateKey::PKCS8Decode(const ByteString& ber)
{
	ByteString data = ber;
	return deserialise(data);
}
