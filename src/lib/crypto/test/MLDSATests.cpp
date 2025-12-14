/*
 * Copyright (c) 2024 SoftHSM Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*****************************************************************************
 MLDSATests.cpp

 Contains test cases to test the ML-DSA (Dilithium) class
 *****************************************************************************/

#include <stdlib.h>
#include <vector>
#include <cppunit/extensions/HelperMacros.h>
#include "MLDSATests.h"
#include "CryptoFactory.h"
#include "AsymmetricKeyPair.h"
#include "AsymmetricAlgorithm.h"

#ifdef WITH_PQC
#include "OQSCryptoFactory.h"
#include "MLDSAParameters.h"
#include "MLDSAPublicKey.h"
#include "MLDSAPrivateKey.h"

CPPUNIT_TEST_SUITE_REGISTRATION(MLDSATests);

// ML-DSA parameter sets: 44, 65, 87
static const std::vector<unsigned long> parameterSets = { 44, 65, 87 };

void MLDSATests::setUp()
{
	mldsa = NULL;
	mldsa = OQSCryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::MLDSA);

	// Check the ML-DSA object
	CPPUNIT_ASSERT(mldsa != NULL);
}

void MLDSATests::tearDown()
{
	if (mldsa != NULL)
	{
		OQSCryptoFactory::i()->recycleAsymmetricAlgorithm(mldsa);
	}

	fflush(stdout);
}

void MLDSATests::testKeyGeneration()
{
	for (unsigned long paramSet : parameterSets)
	{
		// Set parameters
		MLDSAParameters* p = new MLDSAParameters;
		p->setParameterSet(paramSet);

		// Generate key-pair
		AsymmetricKeyPair* kp = NULL;
		CPPUNIT_ASSERT(mldsa->generateKeyPair(&kp, p));
		CPPUNIT_ASSERT(kp != NULL);

		MLDSAPublicKey* pub = (MLDSAPublicKey*) kp->getPublicKey();
		MLDSAPrivateKey* priv = (MLDSAPrivateKey*) kp->getPrivateKey();

		CPPUNIT_ASSERT(pub != NULL);
		CPPUNIT_ASSERT(priv != NULL);
		CPPUNIT_ASSERT(pub->getParameterSet() == paramSet);
		CPPUNIT_ASSERT(priv->getParameterSet() == paramSet);

		// Verify key sizes are non-zero
		CPPUNIT_ASSERT(pub->getPublicKey().size() > 0);
		CPPUNIT_ASSERT(priv->getPrivateKey().size() > 0);

		mldsa->recycleParameters(p);
		mldsa->recycleKeyPair(kp);
	}
}

void MLDSATests::testSerialisation()
{
	for (unsigned long paramSet : parameterSets)
	{
		// Get parameters
		MLDSAParameters* p = new MLDSAParameters;
		p->setParameterSet(paramSet);

		// Serialise the parameters
		ByteString serialisedParams = p->serialise();

		// Deserialise the parameters
		AsymmetricParameters* dP = NULL;
		CPPUNIT_ASSERT(mldsa->reconstructParameters(&dP, serialisedParams));
		CPPUNIT_ASSERT(dP != NULL);
		CPPUNIT_ASSERT(dP->areOfType(MLDSAParameters::type));

		MLDSAParameters* ddP = (MLDSAParameters*) dP;
		CPPUNIT_ASSERT(p->getParameterSet() == ddP->getParameterSet());

		// Generate a key-pair
		AsymmetricKeyPair* kp = NULL;
		CPPUNIT_ASSERT(mldsa->generateKeyPair(&kp, dP));
		CPPUNIT_ASSERT(kp != NULL);

		// Serialise the public key
		MLDSAPublicKey* pubKey = (MLDSAPublicKey*) kp->getPublicKey();
		ByteString serialisedPub = pubKey->serialise();

		// Deserialise the public key
		PublicKey* dPub = NULL;
		CPPUNIT_ASSERT(mldsa->reconstructPublicKey(&dPub, serialisedPub));
		CPPUNIT_ASSERT(dPub != NULL);

		MLDSAPublicKey* dPubKey = (MLDSAPublicKey*) dPub;
		CPPUNIT_ASSERT(pubKey->getParameterSet() == dPubKey->getParameterSet());
		CPPUNIT_ASSERT(pubKey->getPublicKey() == dPubKey->getPublicKey());

		// Serialise the private key
		MLDSAPrivateKey* privKey = (MLDSAPrivateKey*) kp->getPrivateKey();
		ByteString serialisedPriv = privKey->serialise();

		// Deserialise the private key
		PrivateKey* dPriv = NULL;
		CPPUNIT_ASSERT(mldsa->reconstructPrivateKey(&dPriv, serialisedPriv));
		CPPUNIT_ASSERT(dPriv != NULL);

		MLDSAPrivateKey* dPrivKey = (MLDSAPrivateKey*) dPriv;
		CPPUNIT_ASSERT(privKey->getParameterSet() == dPrivKey->getParameterSet());
		CPPUNIT_ASSERT(privKey->getPrivateKey() == dPrivKey->getPrivateKey());

		mldsa->recycleParameters(p);
		mldsa->recycleParameters(dP);
		mldsa->recycleKeyPair(kp);
		mldsa->recyclePublicKey(dPub);
		mldsa->recyclePrivateKey(dPriv);
	}
}

void MLDSATests::testSigningVerifying()
{
	for (unsigned long paramSet : parameterSets)
	{
		// Set parameters
		MLDSAParameters* p = new MLDSAParameters;
		p->setParameterSet(paramSet);

		// Generate key-pair
		AsymmetricKeyPair* kp = NULL;
		CPPUNIT_ASSERT(mldsa->generateKeyPair(&kp, p));
		CPPUNIT_ASSERT(kp != NULL);

		MLDSAPublicKey* pub = (MLDSAPublicKey*) kp->getPublicKey();
		MLDSAPrivateKey* priv = (MLDSAPrivateKey*) kp->getPrivateKey();

		// Test message
		ByteString message("Test message for ML-DSA signing");

		// Sign the message
		ByteString signature;
		CPPUNIT_ASSERT(mldsa->sign(priv, message, signature, AsymMech::MLDSA));

		// Verify signature is non-empty
		CPPUNIT_ASSERT(signature.size() > 0);

		// Verify the signature
		CPPUNIT_ASSERT(mldsa->verify(pub, message, signature, AsymMech::MLDSA));

		// Test with modified message (verification should fail)
		ByteString modifiedMessage = message;
		modifiedMessage[0] ^= 0x01; // Flip one bit
		CPPUNIT_ASSERT(!mldsa->verify(pub, modifiedMessage, signature, AsymMech::MLDSA));

		// Test with modified signature (verification should fail)
		ByteString modifiedSignature = signature;
		modifiedSignature[0] ^= 0x01; // Flip one bit
		CPPUNIT_ASSERT(!mldsa->verify(pub, message, modifiedSignature, AsymMech::MLDSA));

		// Test with empty message
		ByteString emptyMessage;
		ByteString emptySignature;
		CPPUNIT_ASSERT(mldsa->sign(priv, emptyMessage, emptySignature, AsymMech::MLDSA));
		CPPUNIT_ASSERT(mldsa->verify(pub, emptyMessage, emptySignature, AsymMech::MLDSA));

		// Test with long message
		ByteString longMessage;
		for (int i = 0; i < 1000; i++)
		{
			longMessage += (unsigned char)i;
		}
		ByteString longSignature;
		CPPUNIT_ASSERT(mldsa->sign(priv, longMessage, longSignature, AsymMech::MLDSA));
		CPPUNIT_ASSERT(mldsa->verify(pub, longMessage, longSignature, AsymMech::MLDSA));

		mldsa->recycleParameters(p);
		mldsa->recycleKeyPair(kp);
	}
}

#endif // WITH_PQC
