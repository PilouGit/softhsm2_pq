/*
 * Copyright (c) 2024 SoftHSM Project
 * All rights reserved.
 */

#ifndef _SOFTHSM_V2_HYBRIDKEM_H
#define _SOFTHSM_V2_HYBRIDKEM_H

#include "config.h"
#include "AsymmetricAlgorithm.h"
#include "HybridKEMParameters.h"
#include "HybridKEMPublicKey.h"
#include "HybridKEMPrivateKey.h"
#include "../pkcs11/vendor_defines.h"

#ifdef WITH_PQC

/**
 * HybridKEM - Hybrid Key Encapsulation Mechanism
 *
 * Combines ML-KEM (post-quantum) with ECDH (classical) using a KDF combiner.
 * Provides security as long as at least one component is secure.
 *
 * Supported combinations:
 * - ML-KEM-768 + ECDH P-256 (128-bit security)
 * - ML-KEM-1024 + ECDH P-384 (192-bit security)
 * - ML-KEM-768 + X25519 (128-bit security)
 */
class HybridKEM : public AsymmetricAlgorithm
{
public:
	// Constructor
	HybridKEM();

	// Destructor
	virtual ~HybridKEM();

	// Key generation
	virtual bool generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* rng = NULL);

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

	// Encryption/Decryption (not supported for KEM)
	virtual bool encrypt(PublicKey* publicKey, const ByteString& data, ByteString& encryptedData, const AsymMech::Type padding);
	virtual bool decrypt(PrivateKey* privateKey, const ByteString& encryptedData, ByteString& data, const AsymMech::Type padding);

	// Hybrid KEM operations
	/**
	 * Encapsulate - Generate shared secret using hybrid KEM
	 *
	 * @param publicKey Hybrid public key (contains both PQC and classical components)
	 * @param ciphertext Output: combined ciphertext (ct_pqc || ct_classical)
	 * @param sharedSecret Output: combined shared secret via KDF
	 * @return true on success
	 */
	virtual bool encapsulate(PublicKey* publicKey, ByteString& ciphertext, ByteString& sharedSecret);

	/**
	 * Decapsulate - Recover shared secret using hybrid KEM
	 *
	 * @param privateKey Hybrid private key (contains both PQC and classical components)
	 * @param ciphertext Combined ciphertext (ct_pqc || ct_classical)
	 * @param sharedSecret Output: combined shared secret via KDF
	 * @return true on success
	 */
	virtual bool decapsulate(PrivateKey* privateKey, const ByteString& ciphertext, ByteString& sharedSecret);

private:
	/**
	 * Get the mechanism label for KDF
	 */
	ByteString getMechanismLabel(CK_MECHANISM_TYPE mechanism);

	/**
	 * Split combined ciphertext into PQC and classical components
	 */
	bool splitCiphertext(const ByteString& ciphertext, CK_MECHANISM_TYPE mechanism,
	                     ByteString& ctPQC, ByteString& ctClassical);

	/**
	 * Get ciphertext sizes for a given mechanism
	 */
	bool getCiphertextSizes(CK_MECHANISM_TYPE mechanism,
	                        size_t& ctPQCSize, size_t& ctClassicalSize);
};

#endif /* WITH_PQC */

#endif /* !_SOFTHSM_V2_HYBRIDKEM_H */
