/*
 * Copyright (c) 2024 SoftHSM Project
 * All rights reserved.
 */

#include "config.h"
#include "HybridSignatureParameters.h"
#include <string.h>

#ifdef WITH_PQC

const char* HybridSignatureParameters::type = "Hybrid Signature Parameters";

ByteString HybridSignatureParameters::serialise() const
{
	ByteString mechanism(sizeof(CK_MECHANISM_TYPE));
	memcpy(&mechanism[0], &hybridMechanism, sizeof(CK_MECHANISM_TYPE));

	ByteString paramSet(sizeof(unsigned long));
	memcpy(&paramSet[0], &mldsa_paramSet, sizeof(unsigned long));

	return mechanism.serialise() + paramSet.serialise() + ec_curve.serialise();
}

bool HybridSignatureParameters::deserialise(ByteString& serialised)
{

	ByteString mechanism = ByteString::chainDeserialise(serialised);
	if (mechanism.size() != sizeof(CK_MECHANISM_TYPE))
	{
		return false;
	}

	memcpy(&hybridMechanism, mechanism.const_byte_str(), sizeof(CK_MECHANISM_TYPE));

	ByteString paramSet = ByteString::chainDeserialise(serialised);
	if (paramSet.size() != sizeof(unsigned long))
	{
		return false;
	}

	memcpy(&mldsa_paramSet, paramSet.const_byte_str(), sizeof(unsigned long));

	ByteString dEcCurve = ByteString::chainDeserialise(serialised);
	if (dEcCurve.size() == 0)
	{
		return false;
	}

	setECCurve(dEcCurve);

	return true;
}

void HybridSignatureParameters::setHybridMechanism(CK_MECHANISM_TYPE mechanism)
{
	hybridMechanism = mechanism;
}

void HybridSignatureParameters::setMLDSAParameterSet(CK_ULONG paramSet)
{
	mldsa_paramSet = paramSet;
}

void HybridSignatureParameters::setECCurve(const ByteString& curve)
{
	ec_curve = curve;
}

CK_MECHANISM_TYPE HybridSignatureParameters::getHybridMechanism() const
{
	return hybridMechanism;
}

CK_ULONG HybridSignatureParameters::getMLDSAParameterSet() const
{
	return mldsa_paramSet;
}

ByteString HybridSignatureParameters::getECCurve() const
{
	return ec_curve;
}

bool HybridSignatureParameters::areOfType(const char* inType)
{
	return (strcmp(type, inType) == 0);
}

#endif /* WITH_PQC */
