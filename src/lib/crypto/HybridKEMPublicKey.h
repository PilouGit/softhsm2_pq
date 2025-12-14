/*
 * Copyright (c) 2024 SoftHSM Project
 * All rights reserved.
 */

#ifndef _SOFTHSM_V2_HYBRIDKEMPUBLICKEY_H
#define _SOFTHSM_V2_HYBRIDKEMPUBLICKEY_H

#include "config.h"
#include "PublicKey.h"
#include "ByteString.h"
#include "../pkcs11/vendor_defines.h"

#ifdef WITH_PQC

class HybridKEMPublicKey : public PublicKey
{
public:
	// Type identifier
	static const char* type;

	// Constructor
	HybridKEMPublicKey();

	// Destructor
	virtual ~HybridKEMPublicKey();

	// Set the hybrid mechanism
	void setHybridMechanism(CK_MECHANISM_TYPE mechanism);

	// Get the hybrid mechanism
	CK_MECHANISM_TYPE getHybridMechanism() const;

	// Set PQC public key component (ML-KEM)
	void setPQCPublicKey(const ByteString& pqcKey);

	// Get PQC public key component
	ByteString getPQCPublicKey() const;

	// Set classical public key component (ECDH)
	void setClassicalPublicKey(const ByteString& classicalKey);

	// Get classical public key component
	ByteString getClassicalPublicKey() const;

	// Set ML-KEM parameter set
	void setMLKEMParameterSet(unsigned long paramSet);

	// Get ML-KEM parameter set
	unsigned long getMLKEMParameterSet() const;

	// Set EC curve OID
	void setECCurve(const ByteString& curveOID);

	// Get EC curve OID
	ByteString getECCurve() const;

	// Type checking
	virtual bool isOfType(const char* inType);

	// Get bit length
	virtual unsigned long getBitLength() const;

	// Get output length
	virtual unsigned long getOutputLength() const;

	// Serialization
	virtual ByteString serialise() const;
	virtual bool deserialise(ByteString& serialised);

private:
	CK_MECHANISM_TYPE hybridMechanism;
	unsigned long mlkemParameterSet;
	ByteString ecCurve;
	ByteString pqcPublicKey;
	ByteString classicalPublicKey;
};

#endif /* WITH_PQC */

#endif /* !_SOFTHSM_V2_HYBRIDKEMPUBLICKEY_H */
