/*
 * Copyright (c) 2024 SoftHSM Project
 * All rights reserved.
 */

#include "config.h"
#include "HybridKEMParameters.h"
#include <string.h>

#ifdef WITH_PQC

const char* HybridKEMParameters::type = "Hybrid KEM Parameters";

HybridKEMParameters::HybridKEMParameters()
{
	hybridMechanism = 0;
	mlkemParameterSet = 768;  // Default to ML-KEM-768
}

HybridKEMParameters::~HybridKEMParameters()
{
}

void HybridKEMParameters::setHybridMechanism(CK_MECHANISM_TYPE mechanism)
{
	hybridMechanism = mechanism;

	// Automatically configure ML-KEM parameter set and EC curve based on mechanism
	switch (mechanism)
	{
		case CKM_VENDOR_MLKEM768_ECDH_P256:
			mlkemParameterSet = 768;
			// P-256 curve OID: 1.2.840.10045.3.1.7
			{
				unsigned char p256oid[] = {0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};
				ecCurve = ByteString(p256oid, sizeof(p256oid));
			}
			break;

		case CKM_VENDOR_MLKEM1024_ECDH_P384:
			mlkemParameterSet = 1024;
			// P-384 curve OID: 1.3.132.0.34
			{
				unsigned char p384oid[] = {0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22};
				ecCurve = ByteString(p384oid, sizeof(p384oid));
			}
			break;

		case CKM_VENDOR_MLKEM768_X25519:
			mlkemParameterSet = 768;
			// X25519 curve OID: 1.3.101.110
			{
				unsigned char x25519oid[] = {0x06, 0x03, 0x2b, 0x65, 0x6e};
				ecCurve = ByteString(x25519oid, sizeof(x25519oid));
			}
			break;

		default:
			// Keep current values
			break;
	}
}

CK_MECHANISM_TYPE HybridKEMParameters::getHybridMechanism() const
{
	return hybridMechanism;
}

void HybridKEMParameters::setMLKEMParameterSet(unsigned long paramSet)
{
	mlkemParameterSet = paramSet;
}

unsigned long HybridKEMParameters::getMLKEMParameterSet() const
{
	return mlkemParameterSet;
}

void HybridKEMParameters::setECCurve(const ByteString& curveOID)
{
	ecCurve = curveOID;
}

ByteString HybridKEMParameters::getECCurve() const
{
	return ecCurve;
}

bool HybridKEMParameters::areOfType(const char* inType)
{
	return (strcmp(type, inType) == 0);
}

ByteString HybridKEMParameters::serialise() const
{
	ByteString mechanism(sizeof(CK_MECHANISM_TYPE));
	memcpy(&mechanism[0], &hybridMechanism, sizeof(CK_MECHANISM_TYPE));

	ByteString paramSet(sizeof(unsigned long));
	memcpy(&paramSet[0], &mlkemParameterSet, sizeof(unsigned long));

	return mechanism.serialise() + paramSet.serialise() + ecCurve.serialise();
}

bool HybridKEMParameters::deserialise(ByteString& serialised)
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
	if (dEcCurve.size() == 0)
	{
		return false;
	}

	setECCurve(dEcCurve);

	return true;
}

#endif /* WITH_PQC */
