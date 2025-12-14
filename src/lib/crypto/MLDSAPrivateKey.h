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
 MLDSAPrivateKey.h

 ML-DSA (Dilithium) private key class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_MLDSAPRIVATEKEY_H
#define _SOFTHSM_V2_MLDSAPRIVATEKEY_H

#include "config.h"
#include "PrivateKey.h"

class MLDSAPrivateKey : public PrivateKey
{
public:
	// The type
	static const char* type;

	// Check if the key is of the given type
	virtual bool isOfType(const char* inType);

	// Get the bit length
	virtual unsigned long getBitLength() const;

	// Get the output length
	virtual unsigned long getOutputLength() const;

	// Setters for the ML-DSA private key components
	virtual void setPrivateKey(const ByteString& inPrivateKey);
	virtual void setParameterSet(unsigned long inParameterSet);

	// Getters for the ML-DSA private key components
	virtual const ByteString& getPrivateKey() const;
	virtual unsigned long getParameterSet() const;

	// Serialisation
	virtual ByteString serialise() const;
	virtual bool deserialise(ByteString& serialised);

	// Encode into PKCS#8 DER (not standard for PQC, use raw format)
	virtual ByteString PKCS8Encode();

	// Decode from PKCS#8 BER (not standard for PQC, use raw format)
	virtual bool PKCS8Decode(const ByteString& ber);

protected:
	// Private key data (raw bytes from liboqs)
	ByteString privateKey;

	// Parameter set: 0=ML-DSA-44, 1=ML-DSA-65, 2=ML-DSA-87
	unsigned long parameterSet;
};

#endif // !_SOFTHSM_V2_MLDSAPRIVATEKEY_H
