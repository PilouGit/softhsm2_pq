/*
 * Copyright (c) 2024 SoftHSM Project
 * All rights reserved.
 */

#include "config.h"
#include "OQSMLDSAKeyPair.h"

// Set the public key
void OQSMLDSAKeyPair::setPublicKey(MLDSAPublicKey& publicKey)
{
	pubKey = publicKey;
}

// Set the private key
void OQSMLDSAKeyPair::setPrivateKey(MLDSAPrivateKey& privateKey)
{
	privKey = privateKey;
}

// Return the public key
PublicKey* OQSMLDSAKeyPair::getPublicKey()
{
	return &pubKey;
}

const PublicKey* OQSMLDSAKeyPair::getConstPublicKey() const
{
	return &pubKey;
}

// Return the private key
PrivateKey* OQSMLDSAKeyPair::getPrivateKey()
{
	return &privKey;
}

const PrivateKey* OQSMLDSAKeyPair::getConstPrivateKey() const
{
	return &privKey;
}
