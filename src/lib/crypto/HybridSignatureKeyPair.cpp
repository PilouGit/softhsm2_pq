/*
 * Copyright (c) 2024 SoftHSM Project
 * All rights reserved.
 */

#include "config.h"
#include "HybridSignatureKeyPair.h"

#ifdef WITH_PQC

void HybridSignatureKeyPair::setPublicKey(HybridSignaturePublicKey& publicKey)
{
	pubKey = publicKey;
}

void HybridSignatureKeyPair::setPrivateKey(HybridSignaturePrivateKey& privateKey)
{
	privKey = privateKey;
}

PublicKey* HybridSignatureKeyPair::getPublicKey()
{
	return &pubKey;
}

const PublicKey* HybridSignatureKeyPair::getConstPublicKey() const
{
	return &pubKey;
}

PrivateKey* HybridSignatureKeyPair::getPrivateKey()
{
	return &privKey;
}

const PrivateKey* HybridSignatureKeyPair::getConstPrivateKey() const
{
	return &privKey;
}

#endif /* WITH_PQC */
