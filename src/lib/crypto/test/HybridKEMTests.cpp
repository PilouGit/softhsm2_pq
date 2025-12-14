/*
 * Copyright (c) 2024 SoftHSM Project
 * All rights reserved.
 */

#include <stdlib.h>
#include <string.h>
#include <cppunit/extensions/HelperMacros.h>
#include "HybridKEMTests.h"
#include "CryptoFactory.h"
#include "OQSCryptoFactory.h"
#include "HybridKEM.h"
#include "HybridKEMParameters.h"
#include "HybridKEMPublicKey.h"
#include "HybridKEMPrivateKey.h"
#include "HybridKEMKeyPair.h"
#include "../pkcs11/vendor_defines.h"

CPPUNIT_TEST_SUITE_REGISTRATION(HybridKEMTests);

void HybridKEMTests::setUp()
{
	CryptoFactory::i();
	OQSCryptoFactory::i();
}

void HybridKEMTests::tearDown()
{
	CryptoFactory::reset();
	OQSCryptoFactory::reset();
}

void HybridKEMTests::testKeyGeneration()
{
#ifdef WITH_PQC
	// Test hybrid mechanisms (P-256 and P-384)
	// Note: X25519 is not supported via ECDH in OpenSSL/SoftHSM
	CK_MECHANISM_TYPE mechanisms[] = {
		CKM_VENDOR_MLKEM768_ECDH_P256,
		CKM_VENDOR_MLKEM1024_ECDH_P384
	};

	for (size_t i = 0; i < 2; i++)
	{
		CK_MECHANISM_TYPE mechanism = mechanisms[i];

		// Create parameters
		HybridKEMParameters params;
		params.setHybridMechanism(mechanism);

		// Get HybridKEM algorithm
		HybridKEM hybridkem;

		// Generate key pair
		AsymmetricKeyPair* kp = NULL;
		CPPUNIT_ASSERT(hybridkem.generateKeyPair(&kp, &params));
		CPPUNIT_ASSERT(kp != NULL);

		// Check key types
		HybridKEMPublicKey* pub = (HybridKEMPublicKey*) kp->getPublicKey();
		HybridKEMPrivateKey* priv = (HybridKEMPrivateKey*) kp->getPrivateKey();

		CPPUNIT_ASSERT(pub != NULL);
		CPPUNIT_ASSERT(priv != NULL);
		CPPUNIT_ASSERT(pub->isOfType(HybridKEMPublicKey::type));
		CPPUNIT_ASSERT(priv->isOfType(HybridKEMPrivateKey::type));

		// Check mechanism matches
		CPPUNIT_ASSERT(pub->getHybridMechanism() == mechanism);
		CPPUNIT_ASSERT(priv->getHybridMechanism() == mechanism);

		// Check that keys have data
		CPPUNIT_ASSERT(pub->getPQCPublicKey().size() > 0);
		CPPUNIT_ASSERT(pub->getClassicalPublicKey().size() > 0);
		CPPUNIT_ASSERT(priv->getPQCPrivateKey().size() > 0);
		CPPUNIT_ASSERT(priv->getClassicalPrivateKey().size() > 0);

		hybridkem.recycleKeyPair(kp);
	}
#endif
}

void HybridKEMTests::testSerialisation()
{
#ifdef WITH_PQC
	// Test serialization/deserialization for one mechanism
	CK_MECHANISM_TYPE mechanism = CKM_VENDOR_MLKEM768_ECDH_P256;

	// Create parameters
	HybridKEMParameters params;
	params.setHybridMechanism(mechanism);

	// Get HybridKEM algorithm
	HybridKEM hybridkem;

	// Generate key pair
	AsymmetricKeyPair* kp = NULL;
	CPPUNIT_ASSERT(hybridkem.generateKeyPair(&kp, &params));

	// Serialize public key
	HybridKEMPublicKey* pub = (HybridKEMPublicKey*) kp->getPublicKey();
	ByteString serialisedPub = pub->serialise();
	CPPUNIT_ASSERT(serialisedPub.size() > 0);

	// Deserialize public key
	HybridKEMPublicKey pub2;
	ByteString serialisedPubCopy = serialisedPub;
	CPPUNIT_ASSERT(pub2.deserialise(serialisedPubCopy));

	// Check deserialized public key
	CPPUNIT_ASSERT(pub2.getHybridMechanism() == mechanism);
	CPPUNIT_ASSERT(pub2.getPQCPublicKey() == pub->getPQCPublicKey());
	CPPUNIT_ASSERT(pub2.getClassicalPublicKey() == pub->getClassicalPublicKey());

	// Serialize private key
	HybridKEMPrivateKey* priv = (HybridKEMPrivateKey*) kp->getPrivateKey();
	ByteString serialisedPriv = priv->serialise();
	CPPUNIT_ASSERT(serialisedPriv.size() > 0);

	// Deserialize private key
	HybridKEMPrivateKey priv2;
	ByteString serialisedPrivCopy = serialisedPriv;
	CPPUNIT_ASSERT(priv2.deserialise(serialisedPrivCopy));

	// Check deserialized private key
	CPPUNIT_ASSERT(priv2.getHybridMechanism() == mechanism);
	CPPUNIT_ASSERT(priv2.getPQCPrivateKey() == priv->getPQCPrivateKey());
	CPPUNIT_ASSERT(priv2.getClassicalPrivateKey() == priv->getClassicalPrivateKey());

	// Serialize parameters
	ByteString serialisedParams = params.serialise();
	CPPUNIT_ASSERT(serialisedParams.size() > 0);

	// Deserialize parameters
	HybridKEMParameters params2;
	ByteString serialisedParamsCopy = serialisedParams;
	CPPUNIT_ASSERT(params2.deserialise(serialisedParamsCopy));
	CPPUNIT_ASSERT(params2.getHybridMechanism() == mechanism);

	// Reconstruct parameters using algorithm
	AsymmetricParameters* dP = NULL;
	ByteString serialisedParamsCopy2 = serialisedParams;
	CPPUNIT_ASSERT(hybridkem.reconstructParameters(&dP, serialisedParamsCopy2));
	CPPUNIT_ASSERT(dP != NULL);

	HybridKEMParameters* dParams = (HybridKEMParameters*) dP;
	CPPUNIT_ASSERT(dParams->getHybridMechanism() == mechanism);

	delete dP;
	hybridkem.recycleKeyPair(kp);
#endif
}

void HybridKEMTests::testEncapsulateDecapsulate()
{
#ifdef WITH_PQC
	// Test encapsulation/decapsulation (P-256 and P-384)
	// Note: X25519 is not supported via ECDH in OpenSSL/SoftHSM
	CK_MECHANISM_TYPE mechanisms[] = {
		CKM_VENDOR_MLKEM768_ECDH_P256,
		CKM_VENDOR_MLKEM1024_ECDH_P384
	};

	for (size_t i = 0; i < 2; i++)
	{
		CK_MECHANISM_TYPE mechanism = mechanisms[i];

		// Create parameters
		HybridKEMParameters params;
		params.setHybridMechanism(mechanism);

		// Get HybridKEM algorithm
		HybridKEM hybridkem;

		// Generate key pair
		AsymmetricKeyPair* kp = NULL;
		CPPUNIT_ASSERT(hybridkem.generateKeyPair(&kp, &params));

		HybridKEMPublicKey* pub = (HybridKEMPublicKey*) kp->getPublicKey();
		HybridKEMPrivateKey* priv = (HybridKEMPrivateKey*) kp->getPrivateKey();

		// Encapsulate
		ByteString ciphertext;
		ByteString sharedSecret1;
		CPPUNIT_ASSERT(hybridkem.encapsulate(pub, ciphertext, sharedSecret1));
		CPPUNIT_ASSERT(ciphertext.size() > 0);
		CPPUNIT_ASSERT(sharedSecret1.size() == 32); // KDF output is 32 bytes

		// Decapsulate
		ByteString sharedSecret2;
		CPPUNIT_ASSERT(hybridkem.decapsulate(priv, ciphertext, sharedSecret2));
		CPPUNIT_ASSERT(sharedSecret2.size() == 32);

		// Shared secrets must match
		CPPUNIT_ASSERT(sharedSecret1 == sharedSecret2);

		// Test that different ciphertext produces different shared secret
		ByteString ciphertext2;
		ByteString sharedSecret3;
		CPPUNIT_ASSERT(hybridkem.encapsulate(pub, ciphertext2, sharedSecret3));

		// Different encapsulations should produce different ciphertexts and secrets
		CPPUNIT_ASSERT(ciphertext != ciphertext2);
		CPPUNIT_ASSERT(sharedSecret1 != sharedSecret3);

		hybridkem.recycleKeyPair(kp);
	}
#endif
}
