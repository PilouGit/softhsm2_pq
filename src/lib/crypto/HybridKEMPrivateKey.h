/*
 * Copyright (c) 2024 SoftHSM Project
 * All rights reserved.
 */

#ifndef _SOFTHSM_V2_HYBRIDKEMPRIVATEKEY_H
#define _SOFTHSM_V2_HYBRIDKEMPRIVATEKEY_H

#include "config.h"
#include "PrivateKey.h"
#include "ByteString.h"
#include "../pkcs11/vendor_defines.h"

#ifdef WITH_PQC

class HybridKEMPrivateKey : public PrivateKey
{
public:
	// Type identifier
	static const char* type;

	// Constructor
	HybridKEMPrivateKey();

	// Destructor
	virtual ~HybridKEMPrivateKey();

	// Set the hybrid mechanism
	void setHybridMechanism(CK_MECHANISM_TYPE mechanism);

	// Get the hybrid mechanism
	CK_MECHANISM_TYPE getHybridMechanism() const;

	// Set PQC private key component (ML-KEM)
	void setPQCPrivateKey(const ByteString& pqcKey);

	// Get PQC private key component
	ByteString getPQCPrivateKey() const;

	// Set classical private key component (ECDH)
	void setClassicalPrivateKey(const ByteString& classicalKey);

	// Get classical private key component
	ByteString getClassicalPrivateKey() const;

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

	// PKCS#8 encoding/decoding (not supported for hybrid keys)
	virtual ByteString PKCS8Encode();
	virtual bool PKCS8Decode(const ByteString& ber);

	// Serialization
	virtual ByteString serialise() const;
	virtual bool deserialise(ByteString& serialised);

private:
	CK_MECHANISM_TYPE hybridMechanism;
	unsigned long mlkemParameterSet;
	ByteString ecCurve;
	ByteString pqcPrivateKey;
	ByteString classicalPrivateKey;
};

#endif /* WITH_PQC */

#endif /* !_SOFTHSM_V2_HYBRIDKEMPRIVATEKEY_H */
