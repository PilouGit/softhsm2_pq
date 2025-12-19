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
	fprintf(stderr, "DEBUG HybridKEMPublicKey::deserialise: serialised size=%lu\n", serialised.size());
	fflush(stderr);

	ByteString mechanism = ByteString::chainDeserialise(serialised);
	fprintf(stderr, "DEBUG: mechanism size=%lu, expected=%lu\n", mechanism.size(), sizeof(CK_MECHANISM_TYPE));
	fflush(stderr);
	if (mechanism.size() != sizeof(CK_MECHANISM_TYPE))
	{
		fprintf(stderr, "DEBUG: Failed at mechanism size check\n");
		fflush(stderr);
		return false;
	}

	memcpy(&hybridMechanism, mechanism.const_byte_str(), sizeof(CK_MECHANISM_TYPE));
	fprintf(stderr, "DEBUG: hybridMechanism=0x%08lX\n", hybridMechanism);
	fflush(stderr);

	ByteString paramSet = ByteString::chainDeserialise(serialised);
	fprintf(stderr, "DEBUG: paramSet size=%lu, expected=%lu\n", paramSet.size(), sizeof(unsigned long));
	fflush(stderr);
	if (paramSet.size() != sizeof(unsigned long))
	{
		fprintf(stderr, "DEBUG: Failed at paramSet size check\n");
		fflush(stderr);
		return false;
	}

	memcpy(&mlkemParameterSet, paramSet.const_byte_str(), sizeof(unsigned long));
	fprintf(stderr, "DEBUG: mlkemParameterSet=%lu\n", mlkemParameterSet);
	fflush(stderr);

	ByteString dEcCurve = ByteString::chainDeserialise(serialised);
	fprintf(stderr, "DEBUG: dEcCurve size=%lu\n", dEcCurve.size());
	fflush(stderr);
	ByteString dPqcPublicKey = ByteString::chainDeserialise(serialised);
	fprintf(stderr, "DEBUG: dPqcPublicKey size=%lu\n", dPqcPublicKey.size());
	fflush(stderr);
	ByteString dClassicalPublicKey = ByteString::chainDeserialise(serialised);
	fprintf(stderr, "DEBUG: dClassicalPublicKey size=%lu\n", dClassicalPublicKey.size());
	fflush(stderr);

	if ((dEcCurve.size() == 0) || (dPqcPublicKey.size() == 0) || (dClassicalPublicKey.size() == 0))
	{
		fprintf(stderr, "DEBUG: Failed - one or more components have size 0\n");
		fflush(stderr);
		return false;
	}

	setECCurve(dEcCurve);
	setPQCPublicKey(dPqcPublicKey);
	setClassicalPublicKey(dClassicalPublicKey);

	fprintf(stderr, "DEBUG: deserialise successful\n");
	fflush(stderr);
	return true;
}

#endif /* WITH_PQC */
