/*
 * Copyright (c) 2024 SoftHSM Project
 * All rights reserved.
 */

#include "config.h"
#include "HybridSignaturePrivateKey.h"
#include <string.h>

#ifdef WITH_PQC

const char* HybridSignaturePrivateKey::type = "Hybrid Signature Private Key";

ByteString HybridSignaturePrivateKey::serialise() const
{
	ByteString mechanism(sizeof(CK_MECHANISM_TYPE));
	memcpy(&mechanism[0], &hybridMechanism, sizeof(CK_MECHANISM_TYPE));

	ByteString paramSet(sizeof(unsigned long));
	memcpy(&paramSet[0], &mldsa_paramSet, sizeof(unsigned long));

	return mechanism.serialise() +
	       paramSet.serialise() +
	       ec_curve.serialise() +
	       pqc_privateKey.serialise() +
	       classical_privateKey.serialise();
}

bool HybridSignaturePrivateKey::deserialise(ByteString& serialised)
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

	ec_curve = ByteString::chainDeserialise(serialised);
	pqc_privateKey = ByteString::chainDeserialise(serialised);
	classical_privateKey = ByteString::chainDeserialise(serialised);

	return true;
}

void HybridSignaturePrivateKey::setHybridMechanism(CK_MECHANISM_TYPE mechanism)
{
	hybridMechanism = mechanism;
}

void HybridSignaturePrivateKey::setMLDSAParameterSet(CK_ULONG paramSet)
{
	mldsa_paramSet = paramSet;
}

void HybridSignaturePrivateKey::setECCurve(const ByteString& curve)
{
	ec_curve = curve;
}

void HybridSignaturePrivateKey::setPQCPrivateKey(const ByteString& pqcKey)
{
	pqc_privateKey = pqcKey;
}

void HybridSignaturePrivateKey::setClassicalPrivateKey(const ByteString& classicalKey)
{
	classical_privateKey = classicalKey;
}

CK_MECHANISM_TYPE HybridSignaturePrivateKey::getHybridMechanism() const
{
	return hybridMechanism;
}

CK_ULONG HybridSignaturePrivateKey::getMLDSAParameterSet() const
{
	return mldsa_paramSet;
}

ByteString HybridSignaturePrivateKey::getECCurve() const
{
	return ec_curve;
}

ByteString HybridSignaturePrivateKey::getPQCPrivateKey() const
{
	return pqc_privateKey;
}

ByteString HybridSignaturePrivateKey::getClassicalPrivateKey() const
{
	return classical_privateKey;
}

bool HybridSignaturePrivateKey::isOfType(const char* inType)
{
	return (strcmp(type, inType) == 0);
}

unsigned long HybridSignaturePrivateKey::getBitLength() const
{
	// Return combined bit length of both keys
	return (pqc_privateKey.size() + classical_privateKey.size()) * 8;
}

unsigned long HybridSignaturePrivateKey::getOutputLength() const
{
	// Return maximum signature size based on mechanism
	switch (hybridMechanism)
	{
		case CKM_VENDOR_MLDSA65_ECDSA_P256:
			return 3309 + 72;  // ~3381 bytes
		case CKM_VENDOR_MLDSA87_ECDSA_P384:
			return 4627 + 104;  // ~4731 bytes
		default:
			return 4731;  // Maximum size
	}
}

ByteString HybridSignaturePrivateKey::PKCS8Encode()
{
	// PKCS#8 encoding not fully supported for hybrid keys
	// Use serialise() instead
	return serialise();
}

bool HybridSignaturePrivateKey::PKCS8Decode(const ByteString& ber)
{
	// PKCS#8 decoding not fully supported for hybrid keys
	// Use deserialise() instead
	ByteString copy = ber;
	return deserialise(copy);
}

#endif /* WITH_PQC */
