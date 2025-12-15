/*
 * Copyright (c) 2024 SoftHSM Project
 * All rights reserved.
 */

#include "config.h"
#include "HybridSignaturePublicKey.h"
#include <string.h>

#ifdef WITH_PQC

const char* HybridSignaturePublicKey::type = "Hybrid Signature Public Key";

ByteString HybridSignaturePublicKey::serialise() const
{
	ByteString mechanism(sizeof(CK_MECHANISM_TYPE));
	memcpy(&mechanism[0], &hybridMechanism, sizeof(CK_MECHANISM_TYPE));

	ByteString paramSet(sizeof(unsigned long));
	memcpy(&paramSet[0], &mldsa_paramSet, sizeof(unsigned long));

	return mechanism.serialise() +
	       paramSet.serialise() +
	       ec_curve.serialise() +
	       pqc_publicKey.serialise() +
	       classical_publicKey.serialise();
}

bool HybridSignaturePublicKey::deserialise(ByteString& serialised)
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
	pqc_publicKey = ByteString::chainDeserialise(serialised);
	classical_publicKey = ByteString::chainDeserialise(serialised);

	return true;
}

void HybridSignaturePublicKey::setHybridMechanism(CK_MECHANISM_TYPE mechanism)
{
	hybridMechanism = mechanism;
}

void HybridSignaturePublicKey::setMLDSAParameterSet(CK_ULONG paramSet)
{
	mldsa_paramSet = paramSet;
}

void HybridSignaturePublicKey::setECCurve(const ByteString& curve)
{
	ec_curve = curve;
}

void HybridSignaturePublicKey::setPQCPublicKey(const ByteString& pqcKey)
{
	pqc_publicKey = pqcKey;
}

void HybridSignaturePublicKey::setClassicalPublicKey(const ByteString& classicalKey)
{
	classical_publicKey = classicalKey;
}

CK_MECHANISM_TYPE HybridSignaturePublicKey::getHybridMechanism() const
{
	return hybridMechanism;
}

CK_ULONG HybridSignaturePublicKey::getMLDSAParameterSet() const
{
	return mldsa_paramSet;
}

ByteString HybridSignaturePublicKey::getECCurve() const
{
	return ec_curve;
}

ByteString HybridSignaturePublicKey::getPQCPublicKey() const
{
	return pqc_publicKey;
}

ByteString HybridSignaturePublicKey::getClassicalPublicKey() const
{
	return classical_publicKey;
}

bool HybridSignaturePublicKey::isOfType(const char* inType)
{
	return (strcmp(type, inType) == 0);
}

unsigned long HybridSignaturePublicKey::getBitLength() const
{
	// Return combined bit length of both keys
	return (pqc_publicKey.size() + classical_publicKey.size()) * 8;
}

unsigned long HybridSignaturePublicKey::getOutputLength() const
{
	// Return maximum signature size based on mechanism
	// ML-DSA-65 max sig: 3309, ECDSA P-256 max: ~72
	// ML-DSA-87 max sig: 4627, ECDSA P-384 max: ~104
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

#endif /* WITH_PQC */
