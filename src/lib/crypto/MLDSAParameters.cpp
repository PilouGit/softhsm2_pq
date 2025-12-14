/*
 * Copyright (c) 2024 SoftHSM Project
 * All rights reserved.
 */

#include "config.h"
#include "log.h"
#include "MLDSAParameters.h"
#include <string.h>

// Set the type
/*static*/ const char* MLDSAParameters::type = "ML-DSA Parameters";

// Set the parameter set
void MLDSAParameters::setParameterSet(unsigned long inParameterSet)
{
	parameterSet = inParameterSet;
}

// Get the parameter set
unsigned long MLDSAParameters::getParameterSet() const
{
	return parameterSet;
}

// Check if the parameters are of the given type
bool MLDSAParameters::areOfType(const char* inType)
{
	return !strcmp(type, inType);
}

// Serialization
ByteString MLDSAParameters::serialise() const
{
	ByteString paramBytes(parameterSet);
	return paramBytes.serialise();
}

bool MLDSAParameters::deserialise(ByteString& serialised)
{
	ByteString dParam = ByteString::chainDeserialise(serialised);

	if (dParam.size() == 0)
	{
		return false;
	}

	setParameterSet(dParam.long_val());

	return true;
}
