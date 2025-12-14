/*
 * Copyright (c) 2024 SoftHSM Project
 * All rights reserved.
 */

#include "config.h"
#include "log.h"
#include "MLKEMParameters.h"
#include <string.h>

// Set the type
/*static*/ const char* MLKEMParameters::type = "ML-KEM Parameters";

// Set the parameter set
void MLKEMParameters::setParameterSet(unsigned long inParameterSet)
{
	parameterSet = inParameterSet;
}

// Get the parameter set
unsigned long MLKEMParameters::getParameterSet() const
{
	return parameterSet;
}

// Check if the parameters are of the given type
bool MLKEMParameters::areOfType(const char* inType)
{
	return !strcmp(type, inType);
}

// Serialization
ByteString MLKEMParameters::serialise() const
{
	ByteString paramBytes(parameterSet);
	return paramBytes.serialise();
}

bool MLKEMParameters::deserialise(ByteString& serialised)
{
	ByteString dParam = ByteString::chainDeserialise(serialised);

	if (dParam.size() == 0)
	{
		return false;
	}

	setParameterSet(dParam.long_val());

	return true;
}
