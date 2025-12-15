/*
 * Copyright (c) 2024 SoftHSM Project
 * All rights reserved.
 */

#ifndef _SOFTHSM_V2_HYBRIDSIGNATURE_H
#define _SOFTHSM_V2_HYBRIDSIGNATURE_H

#include "config.h"
#include "AsymmetricAlgorithm.h"
#include "AsymmetricKeyPair.h"
#include "HybridSignatureParameters.h"
#include "PublicKey.h"
#include "PrivateKey.h"
#include "ByteString.h"
#include "RNG.h"
#include "../pkcs11/vendor_defines.h"

#ifdef WITH_PQC

/**
 * Hybrid Signature combining ML-DSA and ECDSA
 *
 * Implements hybrid signature schemes:
 * - ML-DSA-65 + ECDSA P-256
 * - ML-DSA-87 + ECDSA P-384
 *
 * Signature format: sig_mldsa || sig_ecdsa
 * Verification: Both signatures must verify independently
 */
class HybridSignature : public AsymmetricAlgorithm
{
public:
	HybridSignature();
	virtual ~HybridSignature();

	// Key generation
	virtual bool generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* rng = NULL);

	// Signing and verification
	virtual bool sign(PrivateKey* privateKey, const ByteString& dataToSign, ByteString& signature, const AsymMech::Type mechanism, const void* param = NULL, const size_t paramLen = 0);
	virtual bool verify(PublicKey* publicKey, const ByteString& originalData, const ByteString& signature, const AsymMech::Type mechanism, const void* param = NULL, const size_t paramLen = 0);

	// Encryption functions (not applicable)
	virtual bool encrypt(PublicKey* publicKey, const ByteString& data, ByteString& encryptedData, const AsymMech::Type padding);
	virtual bool decrypt(PrivateKey* privateKey, const ByteString& encryptedData, ByteString& data, const AsymMech::Type padding);

	// Key size limits
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
	virtual AsymmetricParameters* newParameters();

	// Recycling
	virtual void recycleKeyPair(AsymmetricKeyPair* toRecycle);
	virtual void recycleParameters(AsymmetricParameters* toRecycle);
	virtual void recyclePublicKey(PublicKey* toRecycle);
	virtual void recyclePrivateKey(PrivateKey* toRecycle);

private:
	/**
	 * Get signature sizes for a given mechanism
	 * @param mechanism The hybrid signature mechanism
	 * @param sigMLDSASize Output: ML-DSA signature size
	 * @param sigECDSASize Output: ECDSA signature size (max)
	 * @return true if sizes retrieved successfully
	 */
	bool getSignatureSizes(CK_MECHANISM_TYPE mechanism, size_t& sigMLDSASize, size_t& sigECDSASize);

	/**
	 * Split combined signature into ML-DSA and ECDSA components
	 * @param signature The combined signature
	 * @param mechanism The hybrid signature mechanism
	 * @param sigMLDSA Output: ML-DSA signature
	 * @param sigECDSA Output: ECDSA signature
	 * @return true if split successfully
	 */
	bool splitSignature(const ByteString& signature, CK_MECHANISM_TYPE mechanism,
	                    ByteString& sigMLDSA, ByteString& sigECDSA);
};

#endif /* WITH_PQC */

#endif /* !_SOFTHSM_V2_HYBRIDSIGNATURE_H */
