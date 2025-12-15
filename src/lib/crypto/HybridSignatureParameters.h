/*
 * Copyright (c) 2024 SoftHSM Project
 * All rights reserved.
 */

#ifndef _SOFTHSM_V2_HYBRIDSIGNATUREPARAMETERS_H
#define _SOFTHSM_V2_HYBRIDSIGNATUREPARAMETERS_H

#include "config.h"
#include "AsymmetricParameters.h"
#include "ByteString.h"
#include "../pkcs11/vendor_defines.h"

#ifdef WITH_PQC

class HybridSignatureParameters : public AsymmetricParameters
{
public:
	// Base class functions
	virtual ByteString serialise() const;
	virtual bool deserialise(ByteString& serialised);

	// Setters
	void setHybridMechanism(CK_MECHANISM_TYPE mechanism);
	void setMLDSAParameterSet(CK_ULONG paramSet);
	void setECCurve(const ByteString& curve);

	// Getters
	CK_MECHANISM_TYPE getHybridMechanism() const;
	CK_ULONG getMLDSAParameterSet() const;
	ByteString getECCurve() const;

	// Type checking
	virtual bool areOfType(const char* type);
	static const char* type;

private:
	CK_MECHANISM_TYPE hybridMechanism;
	CK_ULONG mldsa_paramSet;  // 65, 87, or 44
	ByteString ec_curve;      // P-256, P-384, etc.
};

#endif /* WITH_PQC */

#endif /* !_SOFTHSM_V2_HYBRIDSIGNATUREPARAMETERS_H */
