/*
 * Copyright (c) 2024 SoftHSM Project
 * All rights reserved.
 */

#include "config.h"
#include "HybridKEMKeyPair.h"

#ifdef WITH_PQC

HybridKEMKeyPair::HybridKEMKeyPair()
{
}

HybridKEMKeyPair::~HybridKEMKeyPair()
{
}

void HybridKEMKeyPair::setPublicKey(HybridKEMPublicKey& publicKey)
{
	pubKey = publicKey;
}

void HybridKEMKeyPair::setPrivateKey(HybridKEMPrivateKey& privateKey)
{
	privKey = privateKey;
}

PublicKey* HybridKEMKeyPair::getPublicKey()
{
	return &pubKey;
}

const PublicKey* HybridKEMKeyPair::getConstPublicKey() const
{
	return &pubKey;
}

PrivateKey* HybridKEMKeyPair::getPrivateKey()
{
	return &privKey;
}

const PrivateKey* HybridKEMKeyPair::getConstPrivateKey() const
{
	return &privKey;
}

#endif /* WITH_PQC */
