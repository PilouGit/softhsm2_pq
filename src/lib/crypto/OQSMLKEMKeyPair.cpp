/*
 * Copyright (c) 2024 SoftHSM Project
 * All rights reserved.
 */

#include "config.h"
#include "OQSMLKEMKeyPair.h"

// Set the public key
void OQSMLKEMKeyPair::setPublicKey(MLKEMPublicKey& publicKey)
{
	pubKey = publicKey;
}

// Set the private key
void OQSMLKEMKeyPair::setPrivateKey(MLKEMPrivateKey& privateKey)
{
	privKey = privateKey;
}

// Return the public key
PublicKey* OQSMLKEMKeyPair::getPublicKey()
{
	return &pubKey;
}

const PublicKey* OQSMLKEMKeyPair::getConstPublicKey() const
{
	return &pubKey;
}

// Return the private key
PrivateKey* OQSMLKEMKeyPair::getPrivateKey()
{
	return &privKey;
}

const PrivateKey* OQSMLKEMKeyPair::getConstPrivateKey() const
{
	return &privKey;
}
