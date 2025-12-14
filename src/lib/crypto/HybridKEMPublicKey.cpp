/*
 * Copyright (c) 2024 SoftHSM Project
 * All rights reserved.
 */

#include "config.h"
#include "HybridKEMPublicKey.h"
#include <string.h>

#ifdef WITH_PQC

const char* HybridKEMPublicKey::type = "Hybrid KEM Public Key";

HybridKEMPublicKey::HybridKEMPublicKey()
{
	hybridMechanism = 0;
	mlkemParameterSet = 768;
}

HybridKEMPublicKey::~HybridKEMPublicKey()
{
}

void HybridKEMPublicKey::setHybridMechanism(CK_MECHANISM_TYPE mechanism)
{
	hybridMechanism = mechanism;
}

CK_MECHANISM_TYPE HybridKEMPublicKey::getHybridMechanism() const
{
	return hybridMechanism;
}

void HybridKEMPublicKey::setPQCPublicKey(const ByteString& pqcKey)
{
	pqcPublicKey = pqcKey;
}

ByteString HybridKEMPublicKey::getPQCPublicKey() const
{
	return pqcPublicKey;
}

void HybridKEMPublicKey::setClassicalPublicKey(const ByteString& classicalKey)
{
	classicalPublicKey = classicalKey;
}

ByteString HybridKEMPublicKey::getClassicalPublicKey() const
{
	return classicalPublicKey;
}

void HybridKEMPublicKey::setMLKEMParameterSet(unsigned long paramSet)
{
	mlkemParameterSet = paramSet;
}

unsigned long HybridKEMPublicKey::getMLKEMParameterSet() const
{
	return mlkemParameterSet;
}

void HybridKEMPublicKey::setECCurve(const ByteString& curveOID)
{
	ecCurve = curveOID;
}

ByteString HybridKEMPublicKey::getECCurve() const
{
	return ecCurve;
}

bool HybridKEMPublicKey::isOfType(const char* inType)
{
	return (strcmp(type, inType) == 0);
}

unsigned long HybridKEMPublicKey::getBitLength() const
{
	// Return combined bit length (approximate)
	return (pqcPublicKey.size() + classicalPublicKey.size()) * 8;
}

unsigned long HybridKEMPublicKey::getOutputLength() const
{
	// For KEM, output is the shared secret size (32 bytes for all variants)
	return 32;
}

ByteString HybridKEMPublicKey::serialise() const
{
	ByteString mechanism(sizeof(CK_MECHANISM_TYPE));
	memcpy(&mechanism[0], &hybridMechanism, sizeof(CK_MECHANISM_TYPE));

	ByteString paramSet(sizeof(unsigned long));
	memcpy(&paramSet[0], &mlkemParameterSet, sizeof(unsigned long));

	return mechanism.serialise() +
	       paramSet.serialise() +
	       ecCurve.serialise() +
	       pqcPublicKey.serialise() +
	       classicalPublicKey.serialise();
}

bool HybridKEMPublicKey::deserialise(ByteString& serialised)
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

	memcpy(&mlkemParameterSet, paramSet.const_byte_str(), sizeof(unsigned long));

	ByteString dEcCurve = ByteString::chainDeserialise(serialised);
	ByteString dPqcPublicKey = ByteString::chainDeserialise(serialised);
	ByteString dClassicalPublicKey = ByteString::chainDeserialise(serialised);

	if ((dEcCurve.size() == 0) || (dPqcPublicKey.size() == 0) || (dClassicalPublicKey.size() == 0))
	{
		return false;
	}

	setECCurve(dEcCurve);
	setPQCPublicKey(dPqcPublicKey);
	setClassicalPublicKey(dClassicalPublicKey);

	return true;
}

#endif /* WITH_PQC */
