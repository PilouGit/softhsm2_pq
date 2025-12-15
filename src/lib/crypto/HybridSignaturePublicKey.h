/*
 * Copyright (c) 2024 SoftHSM Project
 * All rights reserved.
 */

#ifndef _SOFTHSM_V2_HYBRIDSIGNATUREPUBLICKEY_H
#define _SOFTHSM_V2_HYBRIDSIGNATUREPUBLICKEY_H

#include "config.h"
#include "PublicKey.h"
#include "ByteString.h"
#include "../pkcs11/vendor_defines.h"

#ifdef WITH_PQC

class HybridSignaturePublicKey : public PublicKey
{
public:
	// Base class functions
	virtual ByteString serialise() const;
	virtual bool deserialise(ByteString& serialised);

	// Setters
	void setHybridMechanism(CK_MECHANISM_TYPE mechanism);
	void setMLDSAParameterSet(CK_ULONG paramSet);
	void setECCurve(const ByteString& curve);
	void setPQCPublicKey(const ByteString& pqcKey);
	void setClassicalPublicKey(const ByteString& classicalKey);

	// Getters
	CK_MECHANISM_TYPE getHybridMechanism() const;
	CK_ULONG getMLDSAParameterSet() const;
	ByteString getECCurve() const;
	ByteString getPQCPublicKey() const;
	ByteString getClassicalPublicKey() const;

	// Type checking
	virtual bool isOfType(const char* inType);
	static const char* type;

	// Get key bit length
	virtual unsigned long getBitLength() const;

	// Get output length (for signature size estimation)
	virtual unsigned long getOutputLength() const;

private:
	CK_MECHANISM_TYPE hybridMechanism;
	CK_ULONG mldsa_paramSet;
	ByteString ec_curve;
	ByteString pqc_publicKey;      // ML-DSA public key
	ByteString classical_publicKey; // ECDSA public key (serialized)
};

#endif /* WITH_PQC */

#endif /* !_SOFTHSM_V2_HYBRIDSIGNATUREPUBLICKEY_H */
