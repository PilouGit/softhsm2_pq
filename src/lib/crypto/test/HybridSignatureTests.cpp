/*
 * Copyright (c) 2024 SoftHSM Project
 * All rights reserved.
 */

#include <stdlib.h>
#include <string.h>
#include <cppunit/extensions/HelperMacros.h>
#include "HybridSignatureTests.h"
#include "CryptoFactory.h"
#include "OQSCryptoFactory.h"
#include "HybridSignature.h"
#include "HybridSignatureParameters.h"
#include "HybridSignaturePublicKey.h"
#include "HybridSignaturePrivateKey.h"
#include "HybridSignatureKeyPair.h"
#include "../pkcs11/vendor_defines.h"

CPPUNIT_TEST_SUITE_REGISTRATION(HybridSignatureTests);

void HybridSignatureTests::setUp()
{
	CryptoFactory::i();
	OQSCryptoFactory::i();
}

void HybridSignatureTests::tearDown()
{
	CryptoFactory::reset();
	OQSCryptoFactory::reset();
}

void HybridSignatureTests::testKeyGeneration()
{
#ifdef WITH_PQC
	// Test hybrid signature mechanisms (P-256 and P-384)
	CK_MECHANISM_TYPE mechanisms[] = {
		CKM_VENDOR_MLDSA65_ECDSA_P256,
		CKM_VENDOR_MLDSA87_ECDSA_P384
	};

	CK_ULONG mldsaParams[] = { 65, 87 };
	ByteString ecCurves[] = {
		ByteString("06082a8648ce3d030107"),  // prime256v1 (P-256)
		ByteString("06052b81040022")         // secp384r1 (P-384)
	};

	for (size_t i = 0; i < 2; i++)
	{
		CK_MECHANISM_TYPE mechanism = mechanisms[i];

		// Create parameters
		HybridSignatureParameters params;
		params.setHybridMechanism(mechanism);
		params.setMLDSAParameterSet(mldsaParams[i]);
		params.setECCurve(ecCurves[i]);

		// Get HybridSignature algorithm
		HybridSignature hybridSig;

		// Generate key pair
		AsymmetricKeyPair* kp = NULL;
		CPPUNIT_ASSERT(hybridSig.generateKeyPair(&kp, &params));
		CPPUNIT_ASSERT(kp != NULL);

		// Check key types
		HybridSignaturePublicKey* pub = (HybridSignaturePublicKey*) kp->getPublicKey();
		HybridSignaturePrivateKey* priv = (HybridSignaturePrivateKey*) kp->getPrivateKey();

		CPPUNIT_ASSERT(pub != NULL);
		CPPUNIT_ASSERT(priv != NULL);
		CPPUNIT_ASSERT(pub->isOfType(HybridSignaturePublicKey::type));
		CPPUNIT_ASSERT(priv->isOfType(HybridSignaturePrivateKey::type));

		// Check mechanism matches
		CPPUNIT_ASSERT(pub->getHybridMechanism() == mechanism);
		CPPUNIT_ASSERT(priv->getHybridMechanism() == mechanism);

		// Check that keys have data
		CPPUNIT_ASSERT(pub->getPQCPublicKey().size() > 0);
		CPPUNIT_ASSERT(pub->getClassicalPublicKey().size() > 0);
		CPPUNIT_ASSERT(priv->getPQCPrivateKey().size() > 0);
		CPPUNIT_ASSERT(priv->getClassicalPrivateKey().size() > 0);

		hybridSig.recycleKeyPair(kp);
	}
#endif
}

void HybridSignatureTests::testSerialisation()
{
#ifdef WITH_PQC
	// Test serialization/deserialization for one mechanism
	CK_MECHANISM_TYPE mechanism = CKM_VENDOR_MLDSA65_ECDSA_P256;

	// Create parameters
	HybridSignatureParameters params;
	params.setHybridMechanism(mechanism);
	params.setMLDSAParameterSet(65);
	params.setECCurve(ByteString("06082a8648ce3d030107"));  // prime256v1 (P-256)

	// Get HybridSignature algorithm
	HybridSignature hybridSig;

	// Generate key pair
	AsymmetricKeyPair* kp = NULL;
	CPPUNIT_ASSERT(hybridSig.generateKeyPair(&kp, &params));

	// Serialize public key
	HybridSignaturePublicKey* pub = (HybridSignaturePublicKey*) kp->getPublicKey();
	ByteString serialisedPub = pub->serialise();
	CPPUNIT_ASSERT(serialisedPub.size() > 0);

	// Deserialize public key
	HybridSignaturePublicKey pub2;
	ByteString serialisedPubCopy = serialisedPub;
	CPPUNIT_ASSERT(pub2.deserialise(serialisedPubCopy));

	// Check deserialized public key
	CPPUNIT_ASSERT(pub2.getHybridMechanism() == mechanism);
	CPPUNIT_ASSERT(pub2.getPQCPublicKey() == pub->getPQCPublicKey());
	CPPUNIT_ASSERT(pub2.getClassicalPublicKey() == pub->getClassicalPublicKey());

	// Serialize private key
	HybridSignaturePrivateKey* priv = (HybridSignaturePrivateKey*) kp->getPrivateKey();
	ByteString serialisedPriv = priv->serialise();
	CPPUNIT_ASSERT(serialisedPriv.size() > 0);

	// Deserialize private key
	HybridSignaturePrivateKey priv2;
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
	HybridSignatureParameters params2;
	ByteString serialisedParamsCopy = serialisedParams;
	CPPUNIT_ASSERT(params2.deserialise(serialisedParamsCopy));
	CPPUNIT_ASSERT(params2.getHybridMechanism() == mechanism);

	// Reconstruct parameters using algorithm
	AsymmetricParameters* dP = NULL;
	ByteString serialisedParamsCopy2 = serialisedParams;
	CPPUNIT_ASSERT(hybridSig.reconstructParameters(&dP, serialisedParamsCopy2));
	CPPUNIT_ASSERT(dP != NULL);

	HybridSignatureParameters* dParams = (HybridSignatureParameters*) dP;
	CPPUNIT_ASSERT(dParams->getHybridMechanism() == mechanism);

	delete dP;
	hybridSig.recycleKeyPair(kp);
#endif
}

void HybridSignatureTests::testSigningVerifying()
{
#ifdef WITH_PQC
	// Test signing/verification for both mechanisms
	CK_MECHANISM_TYPE mechanisms[] = {
		CKM_VENDOR_MLDSA65_ECDSA_P256,
		CKM_VENDOR_MLDSA87_ECDSA_P384
	};

	CK_ULONG mldsaParams[] = { 65, 87 };
	ByteString ecCurves[] = {
		ByteString("06082a8648ce3d030107"),  // prime256v1 (P-256)
		ByteString("06052b81040022")         // secp384r1 (P-384)
	};

	for (size_t i = 0; i < 2; i++)
	{
		CK_MECHANISM_TYPE mechanism = mechanisms[i];

		// Create parameters
		HybridSignatureParameters params;
		params.setHybridMechanism(mechanism);
		params.setMLDSAParameterSet(mldsaParams[i]);
		params.setECCurve(ecCurves[i]);

		// Get HybridSignature algorithm
		HybridSignature hybridSig;

		// Generate key pair
		AsymmetricKeyPair* kp = NULL;
		CPPUNIT_ASSERT(hybridSig.generateKeyPair(&kp, &params));

		HybridSignaturePublicKey* pub = (HybridSignaturePublicKey*) kp->getPublicKey();
		HybridSignaturePrivateKey* priv = (HybridSignaturePrivateKey*) kp->getPrivateKey();

		// Create test message
		ByteString message((const unsigned char*)"Test message for hybrid signature", 34);

		// Sign
		ByteString signature;
		CPPUNIT_ASSERT(hybridSig.sign(priv, message, signature, AsymMech::Unknown));
		CPPUNIT_ASSERT(signature.size() > 0);

		// Verify
		CPPUNIT_ASSERT(hybridSig.verify(pub, message, signature, AsymMech::Unknown));

		// Test that wrong message fails verification
		ByteString wrongMessage((const unsigned char*)"Wrong message", 13);
		CPPUNIT_ASSERT(!hybridSig.verify(pub, wrongMessage, signature, AsymMech::Unknown));

		// Test that corrupted signature fails
		ByteString corruptedSig = signature;
		corruptedSig[0] ^= 0xFF;  // Flip bits
		CPPUNIT_ASSERT(!hybridSig.verify(pub, message, corruptedSig, AsymMech::Unknown));

		hybridSig.recycleKeyPair(kp);
	}
#endif
}
