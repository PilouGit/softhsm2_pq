/*
 * Copyright (c) 2024 SoftHSM Project
 * All rights reserved.
 */

#ifndef _SOFTHSM_V2_OQSMLKEM_H
#define _SOFTHSM_V2_OQSMLKEM_H

#include "config.h"
#include "AsymmetricAlgorithm.h"

class OQSMLKEM : public AsymmetricAlgorithm
{
public:
	// Encryption functions (not applicable for KEM)
	virtual bool encrypt(PublicKey* publicKey, const ByteString& data, ByteString& encryptedData, const AsymMech::Type padding);
	virtual bool decrypt(PrivateKey* privateKey, const ByteString& encryptedData, ByteString& data, const AsymMech::Type padding);

	// Key generation
	virtual bool generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* rng = NULL);
	virtual unsigned long getMinKeySize();
	virtual unsigned long getMaxKeySize();

	// Parameter reconstruction
	virtual bool reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData);

	// Key reconstruction
	virtual bool reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData);
	virtual bool reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData);
	virtual bool reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData);

	// Key creation
	virtual PublicKey* newPublicKey();
	virtual PrivateKey* newPrivateKey();

	// KEM operations (ML-KEM specific)
	virtual bool encapsulate(PublicKey* publicKey, ByteString& ciphertext, ByteString& sharedSecret);
	virtual bool decapsulate(PrivateKey* privateKey, const ByteString& ciphertext, ByteString& sharedSecret);
};

#endif // !_SOFTHSM_V2_OQSMLKEM_H
