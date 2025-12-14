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
 MLKEMTests.cpp

 Contains test cases to test the ML-KEM (Kyber) class
 *****************************************************************************/

#include <stdlib.h>
#include <vector>
#include <cppunit/extensions/HelperMacros.h>
#include "MLKEMTests.h"
#include "CryptoFactory.h"
#include "AsymmetricKeyPair.h"
#include "AsymmetricAlgorithm.h"

#ifdef WITH_PQC
#include "OQSCryptoFactory.h"
#include "MLKEMParameters.h"
#include "MLKEMPublicKey.h"
#include "MLKEMPrivateKey.h"
#include "OQSMLKEM.h"

CPPUNIT_TEST_SUITE_REGISTRATION(MLKEMTests);

// ML-KEM parameter sets: 512, 768, 1024
static const std::vector<unsigned long> parameterSets = { 512, 768, 1024 };

void MLKEMTests::setUp()
{
	mlkem = NULL;
	mlkem = OQSCryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::MLKEM);

	// Check the ML-KEM object
	CPPUNIT_ASSERT(mlkem != NULL);
}

void MLKEMTests::tearDown()
{
	if (mlkem != NULL)
	{
		OQSCryptoFactory::i()->recycleAsymmetricAlgorithm(mlkem);
	}

	fflush(stdout);
}

void MLKEMTests::testKeyGeneration()
{
	for (unsigned long paramSet : parameterSets)
	{
		// Set parameters
		MLKEMParameters* p = new MLKEMParameters;
		p->setParameterSet(paramSet);

		// Generate key-pair
		AsymmetricKeyPair* kp = NULL;
		CPPUNIT_ASSERT(mlkem->generateKeyPair(&kp, p));
		CPPUNIT_ASSERT(kp != NULL);

		MLKEMPublicKey* pub = (MLKEMPublicKey*) kp->getPublicKey();
		MLKEMPrivateKey* priv = (MLKEMPrivateKey*) kp->getPrivateKey();

		CPPUNIT_ASSERT(pub != NULL);
		CPPUNIT_ASSERT(priv != NULL);
		CPPUNIT_ASSERT(pub->getParameterSet() == paramSet);
		CPPUNIT_ASSERT(priv->getParameterSet() == paramSet);

		// Verify key sizes are non-zero
		CPPUNIT_ASSERT(pub->getPublicKey().size() > 0);
		CPPUNIT_ASSERT(priv->getPrivateKey().size() > 0);

		mlkem->recycleParameters(p);
		mlkem->recycleKeyPair(kp);
	}
}

void MLKEMTests::testSerialisation()
{
	for (unsigned long paramSet : parameterSets)
	{
		// Get parameters
		MLKEMParameters* p = new MLKEMParameters;
		p->setParameterSet(paramSet);

		// Serialise the parameters
		ByteString serialisedParams = p->serialise();

		// Deserialise the parameters
		AsymmetricParameters* dP = NULL;
		CPPUNIT_ASSERT(mlkem->reconstructParameters(&dP, serialisedParams));
		CPPUNIT_ASSERT(dP != NULL);
		CPPUNIT_ASSERT(dP->areOfType(MLKEMParameters::type));

		MLKEMParameters* ddP = (MLKEMParameters*) dP;
		CPPUNIT_ASSERT(p->getParameterSet() == ddP->getParameterSet());

		// Generate a key-pair
		AsymmetricKeyPair* kp = NULL;
		CPPUNIT_ASSERT(mlkem->generateKeyPair(&kp, dP));
		CPPUNIT_ASSERT(kp != NULL);

		// Serialise the public key
		MLKEMPublicKey* pubKey = (MLKEMPublicKey*) kp->getPublicKey();
		ByteString serialisedPub = pubKey->serialise();

		// Deserialise the public key
		PublicKey* dPub = NULL;
		CPPUNIT_ASSERT(mlkem->reconstructPublicKey(&dPub, serialisedPub));
		CPPUNIT_ASSERT(dPub != NULL);

		MLKEMPublicKey* dPubKey = (MLKEMPublicKey*) dPub;
		CPPUNIT_ASSERT(pubKey->getParameterSet() == dPubKey->getParameterSet());
		CPPUNIT_ASSERT(pubKey->getPublicKey() == dPubKey->getPublicKey());

		// Serialise the private key
		MLKEMPrivateKey* privKey = (MLKEMPrivateKey*) kp->getPrivateKey();
		ByteString serialisedPriv = privKey->serialise();

		// Deserialise the private key
		PrivateKey* dPriv = NULL;
		CPPUNIT_ASSERT(mlkem->reconstructPrivateKey(&dPriv, serialisedPriv));
		CPPUNIT_ASSERT(dPriv != NULL);

		MLKEMPrivateKey* dPrivKey = (MLKEMPrivateKey*) dPriv;
		CPPUNIT_ASSERT(privKey->getParameterSet() == dPrivKey->getParameterSet());
		CPPUNIT_ASSERT(privKey->getPrivateKey() == dPrivKey->getPrivateKey());

		mlkem->recycleParameters(p);
		mlkem->recycleParameters(dP);
		mlkem->recycleKeyPair(kp);
		mlkem->recyclePublicKey(dPub);
		mlkem->recyclePrivateKey(dPriv);
	}
}

void MLKEMTests::testEncapsulateDecapsulate()
{
	for (unsigned long paramSet : parameterSets)
	{
		// Set parameters
		MLKEMParameters* p = new MLKEMParameters;
		p->setParameterSet(paramSet);

		// Generate key-pair
		AsymmetricKeyPair* kp = NULL;
		CPPUNIT_ASSERT(mlkem->generateKeyPair(&kp, p));
		CPPUNIT_ASSERT(kp != NULL);

		MLKEMPublicKey* pub = (MLKEMPublicKey*) kp->getPublicKey();
		MLKEMPrivateKey* priv = (MLKEMPrivateKey*) kp->getPrivateKey();

		// Encapsulate
		ByteString ciphertext;
		ByteString sharedSecret1;
		OQSMLKEM* mlkemAlg = dynamic_cast<OQSMLKEM*>(mlkem);
		CPPUNIT_ASSERT(mlkemAlg != NULL);
		CPPUNIT_ASSERT(mlkemAlg->encapsulate(pub, ciphertext, sharedSecret1));

		// Verify ciphertext and shared secret are non-empty
		CPPUNIT_ASSERT(ciphertext.size() > 0);
		CPPUNIT_ASSERT(sharedSecret1.size() > 0);

		// Decapsulate
		ByteString sharedSecret2;
		CPPUNIT_ASSERT(mlkemAlg->decapsulate(priv, ciphertext, sharedSecret2));

		// Verify shared secrets match
		CPPUNIT_ASSERT(sharedSecret1.size() == sharedSecret2.size());
		CPPUNIT_ASSERT(sharedSecret1 == sharedSecret2);

		// Test with wrong ciphertext (should fail or produce different shared secret)
		ByteString wrongCiphertext = ciphertext;
		if (wrongCiphertext.size() > 0)
		{
			wrongCiphertext[0] ^= 0x01; // Flip one bit
		}
		ByteString wrongSharedSecret;
		// Decapsulation with wrong ciphertext should succeed but produce different shared secret
		// (implicit rejection in ML-KEM produces pseudorandom shared secret)
		CPPUNIT_ASSERT(mlkemAlg->decapsulate(priv, wrongCiphertext, wrongSharedSecret));
		CPPUNIT_ASSERT(wrongSharedSecret != sharedSecret1);

		mlkem->recycleParameters(p);
		mlkem->recycleKeyPair(kp);
	}
}

#endif // WITH_PQC
