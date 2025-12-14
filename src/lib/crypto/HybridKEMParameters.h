/*
 * Copyright (c) 2024 SoftHSM Project
 * All rights reserved.
 */

#ifndef _SOFTHSM_V2_HYBRIDKEMPARAMETERS_H
#define _SOFTHSM_V2_HYBRIDKEMPARAMETERS_H

#include "config.h"
#include "AsymmetricParameters.h"
#include "ByteString.h"
#include "../pkcs11/vendor_defines.h"

#ifdef WITH_PQC

class HybridKEMParameters : public AsymmetricParameters
{
public:
	// Type identifier
	static const char* type;

	// Constructor
	HybridKEMParameters();

	// Destructor
	virtual ~HybridKEMParameters();

	// Set the hybrid mechanism
	void setHybridMechanism(CK_MECHANISM_TYPE mechanism);

	// Get the hybrid mechanism
	CK_MECHANISM_TYPE getHybridMechanism() const;

	// Set ML-KEM parameter set (512, 768, 1024)
	void setMLKEMParameterSet(unsigned long paramSet);

	// Get ML-KEM parameter set
	unsigned long getMLKEMParameterSet() const;

	// Set EC curve OID for ECDH
	void setECCurve(const ByteString& curveOID);

	// Get EC curve OID
	ByteString getECCurve() const;

	// Type checking
	virtual bool areOfType(const char* inType);

	// Serialization
	virtual ByteString serialise() const;
	virtual bool deserialise(ByteString& serialised);

private:
	CK_MECHANISM_TYPE hybridMechanism;
	unsigned long mlkemParameterSet;
	ByteString ecCurve;
};

#endif /* WITH_PQC */

#endif /* !_SOFTHSM_V2_HYBRIDKEMPARAMETERS_H */
