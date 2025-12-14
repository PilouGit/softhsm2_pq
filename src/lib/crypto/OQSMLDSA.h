/*
 * Copyright (c) 2024 SoftHSM Project
 * All rights reserved.
 */

#ifndef _SOFTHSM_V2_OQSMLDSA_H
#define _SOFTHSM_V2_OQSMLDSA_H

#include "config.h"
#include "AsymmetricAlgorithm.h"

class OQSMLDSA : public AsymmetricAlgorithm
{
public:
	// Encryption functions (not applicable for signature algorithm)
	virtual bool encrypt(PublicKey* publicKey, const ByteString& data, ByteString& encryptedData, const AsymMech::Type padding);
	virtual bool decrypt(PrivateKey* privateKey, const ByteString& encryptedData, ByteString& data, const AsymMech::Type padding);

	// Signature functions
	virtual bool sign(PrivateKey* privateKey, const ByteString& dataToSign, ByteString& signature, const AsymMech::Type mechanism, const void* param = NULL, const size_t paramLen = 0);
	virtual bool verify(PublicKey* publicKey, const ByteString& originalData, const ByteString& signature, const AsymMech::Type mechanism, const void* param = NULL, const size_t paramLen = 0);

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
};

#endif // !_SOFTHSM_V2_OQSMLDSA_H
