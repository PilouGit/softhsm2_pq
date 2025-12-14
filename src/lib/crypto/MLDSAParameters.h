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
 MLDSAParameters.h

 ML-DSA parameters
 *****************************************************************************/

#ifndef _SOFTHSM_V2_MLDSAPARAMETERS_H
#define _SOFTHSM_V2_MLDSAPARAMETERS_H

#include "config.h"
#include "AsymmetricParameters.h"

class MLDSAParameters : public AsymmetricParameters
{
public:
	// The type
	static const char* type;

	// Set the parameter set (44, 65, or 87)
	void setParameterSet(unsigned long inParameterSet);

	// Get the parameter set
	unsigned long getParameterSet() const;

	// Check if the parameters are of the given type
	virtual bool areOfType(const char* inType);

	// Serialization
	virtual ByteString serialise() const;
	virtual bool deserialise(ByteString& serialised);

private:
	unsigned long parameterSet;
};

#endif // !_SOFTHSM_V2_MLDSAPARAMETERS_H
