/*
 * Copyright (c) 2024 SoftHSM Project
 * All rights reserved.
 */

#ifndef _SOFTHSM_V2_HYBRIDKEMKEYPAIR_H
#define _SOFTHSM_V2_HYBRIDKEMKEYPAIR_H

#include "config.h"
#include "AsymmetricKeyPair.h"
#include "HybridKEMPublicKey.h"
#include "HybridKEMPrivateKey.h"

#ifdef WITH_PQC

class HybridKEMKeyPair : public AsymmetricKeyPair
{
public:
	// Constructor
	HybridKEMKeyPair();

	// Destructor
	virtual ~HybridKEMKeyPair();

	// Set the public key
	void setPublicKey(HybridKEMPublicKey& publicKey);

	// Set the private key
	void setPrivateKey(HybridKEMPrivateKey& privateKey);

	// Get the public key
	virtual PublicKey* getPublicKey();
	virtual const PublicKey* getConstPublicKey() const;

	// Get the private key
	virtual PrivateKey* getPrivateKey();
	virtual const PrivateKey* getConstPrivateKey() const;

private:
	HybridKEMPublicKey pubKey;
	HybridKEMPrivateKey privKey;
};

#endif /* WITH_PQC */

#endif /* !_SOFTHSM_V2_HYBRIDKEMKEYPAIR_H */
