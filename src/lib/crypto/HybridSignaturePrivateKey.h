/*
 * Copyright (c) 2024 SoftHSM Project
 * All rights reserved.
 */

#ifndef _SOFTHSM_V2_HYBRIDSIGNATUREPRIVATEKEY_H
#define _SOFTHSM_V2_HYBRIDSIGNATUREPRIVATEKEY_H

#include "config.h"
#include "PrivateKey.h"
#include "ByteString.h"
#include "../pkcs11/vendor_defines.h"

#ifdef WITH_PQC

class HybridSignaturePrivateKey : public PrivateKey
{
public:
	// Base class functions
	virtual ByteString serialise() const;
	virtual bool deserialise(ByteString& serialised);

	// Setters
	void setHybridMechanism(CK_MECHANISM_TYPE mechanism);
	void setMLDSAParameterSet(CK_ULONG paramSet);
	void setECCurve(const ByteString& curve);
	void setPQCPrivateKey(const ByteString& pqcKey);
	void setClassicalPrivateKey(const ByteString& classicalKey);

	// Getters
	CK_MECHANISM_TYPE getHybridMechanism() const;
	CK_ULONG getMLDSAParameterSet() const;
	ByteString getECCurve() const;
	ByteString getPQCPrivateKey() const;
	ByteString getClassicalPrivateKey() const;

	// Type checking
	virtual bool isOfType(const char* inType);
	static const char* type;

	// Get key bit length
	virtual unsigned long getBitLength() const;

	// Get output length (for signature size estimation)
	virtual unsigned long getOutputLength() const;

	// PKCS#8 encoding/decoding (not fully supported)
	virtual ByteString PKCS8Encode();
	virtual bool PKCS8Decode(const ByteString& ber);

private:
	CK_MECHANISM_TYPE hybridMechanism;
	CK_ULONG mldsa_paramSet;
	ByteString ec_curve;
	ByteString pqc_privateKey;       // ML-DSA private key
	ByteString classical_privateKey;  // ECDSA private key (serialized)
};

#endif /* WITH_PQC */

#endif /* !_SOFTHSM_V2_HYBRIDSIGNATUREPRIVATEKEY_H */
