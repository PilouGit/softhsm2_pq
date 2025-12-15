/*
 * Copyright (c) 2024 SoftHSM Project
 * All rights reserved.
 */

#ifndef _SOFTHSM_V2_HYBRIDSIGNATUREKEYPAIR_H
#define _SOFTHSM_V2_HYBRIDSIGNATUREKEYPAIR_H

#include "config.h"
#include "AsymmetricKeyPair.h"
#include "HybridSignaturePublicKey.h"
#include "HybridSignaturePrivateKey.h"

#ifdef WITH_PQC

class HybridSignatureKeyPair : public AsymmetricKeyPair
{
public:
	// Constructor
	HybridSignatureKeyPair() {}

	// Destructor
	virtual ~HybridSignatureKeyPair() {}

	// Set the public key
	void setPublicKey(HybridSignaturePublicKey& publicKey);

	// Set the private key
	void setPrivateKey(HybridSignaturePrivateKey& privateKey);

	// Get the public key
	virtual PublicKey* getPublicKey();
	virtual const PublicKey* getConstPublicKey() const;

	// Get the private key
	virtual PrivateKey* getPrivateKey();
	virtual const PrivateKey* getConstPrivateKey() const;

private:
	// The public key
	HybridSignaturePublicKey pubKey;

	// The private key
	HybridSignaturePrivateKey privKey;
};

#endif /* WITH_PQC */

#endif /* !_SOFTHSM_V2_HYBRIDSIGNATUREKEYPAIR_H */
