/*
 * Copyright (c) 2024 SoftHSM Project
 * All rights reserved.
 */

#include "config.h"
#include "HybridKEMPrivateKey.h"
#include <string.h>

#ifdef WITH_PQC

const char* HybridKEMPrivateKey::type = "Hybrid KEM Private Key";

HybridKEMPrivateKey::HybridKEMPrivateKey()
{
	hybridMechanism = 0;
	mlkemParameterSet = 768;
}

HybridKEMPrivateKey::~HybridKEMPrivateKey()
{
}

void HybridKEMPrivateKey::setHybridMechanism(CK_MECHANISM_TYPE mechanism)
{
	hybridMechanism = mechanism;
}

CK_MECHANISM_TYPE HybridKEMPrivateKey::getHybridMechanism() const
{
	return hybridMechanism;
}

void HybridKEMPrivateKey::setPQCPrivateKey(const ByteString& pqcKey)
{
	pqcPrivateKey = pqcKey;
}

ByteString HybridKEMPrivateKey::getPQCPrivateKey() const
{
	return pqcPrivateKey;
}

void HybridKEMPrivateKey::setClassicalPrivateKey(const ByteString& classicalKey)
{
	classicalPrivateKey = classicalKey;
}

ByteString HybridKEMPrivateKey::getClassicalPrivateKey() const
{
	return classicalPrivateKey;
}

void HybridKEMPrivateKey::setMLKEMParameterSet(unsigned long paramSet)
{
	mlkemParameterSet = paramSet;
}

unsigned long HybridKEMPrivateKey::getMLKEMParameterSet() const
{
	return mlkemParameterSet;
}

void HybridKEMPrivateKey::setECCurve(const ByteString& curveOID)
{
	ecCurve = curveOID;
}

ByteString HybridKEMPrivateKey::getECCurve() const
{
	return ecCurve;
}

bool HybridKEMPrivateKey::isOfType(const char* inType)
{
	return (strcmp(type, inType) == 0);
}

unsigned long HybridKEMPrivateKey::getBitLength() const
{
	// Return combined bit length (approximate)
	return (pqcPrivateKey.size() + classicalPrivateKey.size()) * 8;
}

unsigned long HybridKEMPrivateKey::getOutputLength() const
{
	// For KEM, output is the shared secret size (32 bytes for all variants)
	return 32;
}

ByteString HybridKEMPrivateKey::PKCS8Encode()
{
	// PKCS#8 encoding not supported for hybrid keys
	// Use custom serialization instead
	return ByteString();
}

bool HybridKEMPrivateKey::PKCS8Decode(const ByteString& /*ber*/)
{
	// PKCS#8 decoding not supported for hybrid keys
	// Use custom deserialization instead
	return false;
}

ByteString HybridKEMPrivateKey::serialise() const
{
	ByteString mechanism(sizeof(CK_MECHANISM_TYPE));
	memcpy(&mechanism[0], &hybridMechanism, sizeof(CK_MECHANISM_TYPE));

	ByteString paramSet(sizeof(unsigned long));
	memcpy(&paramSet[0], &mlkemParameterSet, sizeof(unsigned long));

	return mechanism.serialise() +
	       paramSet.serialise() +
	       ecCurve.serialise() +
	       pqcPrivateKey.serialise() +
	       classicalPrivateKey.serialise();
}

bool HybridKEMPrivateKey::deserialise(ByteString& serialised)
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
	ByteString dPqcPrivateKey = ByteString::chainDeserialise(serialised);
	ByteString dClassicalPrivateKey = ByteString::chainDeserialise(serialised);

	if ((dEcCurve.size() == 0) || (dPqcPrivateKey.size() == 0) || (dClassicalPrivateKey.size() == 0))
	{
		return false;
	}

	setECCurve(dEcCurve);
	setPQCPrivateKey(dPqcPrivateKey);
	setClassicalPrivateKey(dClassicalPrivateKey);

	return true;
}

#endif /* WITH_PQC */
