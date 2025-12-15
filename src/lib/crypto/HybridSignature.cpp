/*
 * Copyright (c) 2024 SoftHSM Project
 * All rights reserved.
 */

#include "config.h"
#include "log.h"
#include "HybridSignature.h"
#include "HybridSignatureKeyPair.h"
#include "CryptoFactory.h"
#include "OQSCryptoFactory.h"
#include "OQSMLDSA.h"
#include "MLDSAParameters.h"
#include "MLDSAPublicKey.h"
#include "MLDSAPrivateKey.h"
#include "ECParameters.h"
#include "ECPublicKey.h"
#include "ECPrivateKey.h"

#ifdef WITH_PQC

HybridSignature::HybridSignature()
{
}

HybridSignature::~HybridSignature()
{
}

bool HybridSignature::generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* /*rng*/)
{
	fflush(stdout);

	if ((ppKeyPair == NULL) || (parameters == NULL))
	{
		fflush(stdout);
		return false;
	}

	if (!parameters->areOfType(HybridSignatureParameters::type))
	{
		ERROR_MSG("Invalid parameters for Hybrid Signature key generation");
		fflush(stdout);
		return false;
	}

	HybridSignatureParameters* params = (HybridSignatureParameters*) parameters;
	CK_MECHANISM_TYPE mechanism = params->getHybridMechanism();
	fflush(stdout);

	// Generate ML-DSA key pair
	MLDSAParameters mldsaParams;
	mldsaParams.setParameterSet(params->getMLDSAParameterSet());

	fflush(stdout);
	AsymmetricAlgorithm* mldsa = OQSCryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::MLDSA);
	if (mldsa == NULL)
	{
		ERROR_MSG("Failed to get ML-DSA algorithm");
		fflush(stdout);
		return false;
	}
	fflush(stdout);

	AsymmetricKeyPair* mldsaKP = NULL;
	fflush(stdout);
	if (!mldsa->generateKeyPair(&mldsaKP, &mldsaParams))
	{
		ERROR_MSG("Failed to generate ML-DSA key pair");
		fflush(stdout);
		OQSCryptoFactory::i()->recycleAsymmetricAlgorithm(mldsa);
		return false;
	}
	fflush(stdout);

	// Generate ECDSA key pair
	fflush(stdout);
	ECParameters ecParams;
	ecParams.setEC(params->getECCurve());
	fflush(stdout);

	fflush(stdout);
	AsymmetricAlgorithm* ecdsa = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::ECDSA);
	if (ecdsa == NULL)
	{
		ERROR_MSG("Failed to get ECDSA algorithm");
		fflush(stdout);
		mldsa->recycleKeyPair(mldsaKP);
		OQSCryptoFactory::i()->recycleAsymmetricAlgorithm(mldsa);
		return false;
	}
	fflush(stdout);

	AsymmetricKeyPair* ecdsaKP = NULL;
	fflush(stdout);
	if (!ecdsa->generateKeyPair(&ecdsaKP, &ecParams))
	{
		ERROR_MSG("Failed to generate ECDSA key pair");
		fflush(stdout);
		mldsa->recycleKeyPair(mldsaKP);
		OQSCryptoFactory::i()->recycleAsymmetricAlgorithm(mldsa);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(ecdsa);
		return false;
	}
	fflush(stdout);

	// Create hybrid key pair
	fflush(stdout);
	HybridSignatureKeyPair* hybridKP = new HybridSignatureKeyPair();

	// Combine public keys
	fflush(stdout);
	HybridSignaturePublicKey hybridPub;
	hybridPub.setHybridMechanism(mechanism);
	hybridPub.setMLDSAParameterSet(params->getMLDSAParameterSet());
	hybridPub.setECCurve(params->getECCurve());

	MLDSAPublicKey* mldsaPub = (MLDSAPublicKey*) mldsaKP->getPublicKey();
	PublicKey* ecPub = ecdsaKP->getPublicKey();

	// Store keys
	hybridPub.setPQCPublicKey(mldsaPub->getPublicKey());
	hybridPub.setClassicalPublicKey(ecPub->serialise());
	fflush(stdout);

	// Combine private keys
	fflush(stdout);
	HybridSignaturePrivateKey hybridPriv;
	hybridPriv.setHybridMechanism(mechanism);
	hybridPriv.setMLDSAParameterSet(params->getMLDSAParameterSet());
	hybridPriv.setECCurve(params->getECCurve());

	MLDSAPrivateKey* mldsaPriv = (MLDSAPrivateKey*) mldsaKP->getPrivateKey();
	PrivateKey* ecPriv = ecdsaKP->getPrivateKey();

	hybridPriv.setPQCPrivateKey(mldsaPriv->getPrivateKey());
	hybridPriv.setClassicalPrivateKey(ecPriv->serialise());
	fflush(stdout);

	fflush(stdout);
	hybridKP->setPublicKey(hybridPub);
	hybridKP->setPrivateKey(hybridPriv);
	fflush(stdout);

	// Clean up
	fflush(stdout);
	mldsa->recycleKeyPair(mldsaKP);
	ecdsa->recycleKeyPair(ecdsaKP);
	OQSCryptoFactory::i()->recycleAsymmetricAlgorithm(mldsa);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(ecdsa);

	fflush(stdout);
	*ppKeyPair = hybridKP;
	return true;
}

bool HybridSignature::getSignatureSizes(CK_MECHANISM_TYPE mechanism, size_t& sigMLDSASize, size_t& sigECDSASize)
{
	switch (mechanism)
	{
		case CKM_VENDOR_MLDSA65_ECDSA_P256:
			sigMLDSASize = 3309;  // ML-DSA-65 signature size
			sigECDSASize = 72;    // ECDSA P-256 signature max size (DER encoded)
			return true;

		case CKM_VENDOR_MLDSA87_ECDSA_P384:
			sigMLDSASize = 4627;  // ML-DSA-87 signature size
			sigECDSASize = 104;   // ECDSA P-384 signature max size (DER encoded)
			return true;

		default:
			return false;
	}
}

bool HybridSignature::splitSignature(const ByteString& signature, CK_MECHANISM_TYPE mechanism,
                                     ByteString& sigMLDSA, ByteString& sigECDSA)
{
	size_t sigMLDSASize, sigECDSASize;
	if (!getSignatureSizes(mechanism, sigMLDSASize, sigECDSASize))
	{
		return false;
	}

	// ML-DSA signature is fixed size, ECDSA varies
	if (signature.size() < sigMLDSASize + 8)  // ML-DSA + minimum ECDSA
	{
		ERROR_MSG("Invalid signature size: %zu (expected >= %zu)",
		          signature.size(), sigMLDSASize + 8);
		return false;
	}

	sigMLDSA = signature.substr(0, sigMLDSASize);
	sigECDSA = signature.substr(sigMLDSASize, signature.size() - sigMLDSASize);

	return true;
}

bool HybridSignature::sign(PrivateKey* privateKey, const ByteString& dataToSign, ByteString& signature,
                           const AsymMech::Type /*mechanism*/, const void* /*param*/, const size_t /*paramLen*/)
{
	if (!privateKey->isOfType(HybridSignaturePrivateKey::type))
	{
		ERROR_MSG("Invalid key type for Hybrid Signature signing");
		return false;
	}

	HybridSignaturePrivateKey* hybridPriv = (HybridSignaturePrivateKey*) privateKey;

	// Reconstruct ML-DSA private key
	MLDSAPrivateKey mldsaPriv;
	mldsaPriv.setParameterSet(hybridPriv->getMLDSAParameterSet());
	mldsaPriv.setPrivateKey(hybridPriv->getPQCPrivateKey());

	// Sign with ML-DSA
	AsymmetricAlgorithm* mldsa = OQSCryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::MLDSA);
	if (mldsa == NULL)
	{
		ERROR_MSG("Failed to get ML-DSA algorithm");
		return false;
	}

	ByteString sigMLDSA;
	if (!mldsa->sign(&mldsaPriv, dataToSign, sigMLDSA, AsymMech::MLDSA))
	{
		ERROR_MSG("ML-DSA signing failed");
		OQSCryptoFactory::i()->recycleAsymmetricAlgorithm(mldsa);
		return false;
	}

	// Get ECDSA algorithm
	AsymmetricAlgorithm* ecdsa = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::ECDSA);
	if (ecdsa == NULL)
	{
		ERROR_MSG("Failed to get ECDSA algorithm");
		OQSCryptoFactory::i()->recycleAsymmetricAlgorithm(mldsa);
		return false;
	}

	// Reconstruct EC private key from serialized data
	ByteString ecPrivData = hybridPriv->getClassicalPrivateKey();
	ByteString ecPrivCopy = ecPrivData;
	PrivateKey* ecPriv = NULL;
	if (!ecdsa->reconstructPrivateKey(&ecPriv, ecPrivCopy))
	{
		ERROR_MSG("Failed to reconstruct EC private key");
		OQSCryptoFactory::i()->recycleAsymmetricAlgorithm(mldsa);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(ecdsa);
		return false;
	}

	// Sign with ECDSA
	ByteString sigECDSA;
	if (!ecdsa->sign(ecPriv, dataToSign, sigECDSA, AsymMech::ECDSA))
	{
		ERROR_MSG("ECDSA signing failed");
		delete ecPriv;
		OQSCryptoFactory::i()->recycleAsymmetricAlgorithm(mldsa);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(ecdsa);
		return false;
	}

	// Combine signatures: sig_mldsa || sig_ecdsa
	signature = sigMLDSA + sigECDSA;

	// Clean up
	delete ecPriv;
	OQSCryptoFactory::i()->recycleAsymmetricAlgorithm(mldsa);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(ecdsa);

	return true;
}

bool HybridSignature::verify(PublicKey* publicKey, const ByteString& originalData, const ByteString& signature,
                             const AsymMech::Type /*mechanism*/, const void* /*param*/, const size_t /*paramLen*/)
{
	if (!publicKey->isOfType(HybridSignaturePublicKey::type))
	{
		ERROR_MSG("Invalid key type for Hybrid Signature verification");
		return false;
	}

	HybridSignaturePublicKey* hybridPub = (HybridSignaturePublicKey*) publicKey;
	CK_MECHANISM_TYPE mech = hybridPub->getHybridMechanism();

	// Split signature
	ByteString sigMLDSA, sigECDSA;
	if (!splitSignature(signature, mech, sigMLDSA, sigECDSA))
	{
		ERROR_MSG("Failed to split signature");
		return false;
	}

	// Reconstruct ML-DSA public key
	MLDSAPublicKey mldsaPub;
	mldsaPub.setParameterSet(hybridPub->getMLDSAParameterSet());
	mldsaPub.setPublicKey(hybridPub->getPQCPublicKey());

	// Verify with ML-DSA
	AsymmetricAlgorithm* mldsa = OQSCryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::MLDSA);
	if (mldsa == NULL)
	{
		ERROR_MSG("Failed to get ML-DSA algorithm");
		return false;
	}

	if (!mldsa->verify(&mldsaPub, originalData, sigMLDSA, AsymMech::MLDSA))
	{
		ERROR_MSG("ML-DSA verification failed");
		OQSCryptoFactory::i()->recycleAsymmetricAlgorithm(mldsa);
		return false;
	}

	// Get ECDSA algorithm
	AsymmetricAlgorithm* ecdsa = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::ECDSA);
	if (ecdsa == NULL)
	{
		ERROR_MSG("Failed to get ECDSA algorithm");
		OQSCryptoFactory::i()->recycleAsymmetricAlgorithm(mldsa);
		return false;
	}

	// Reconstruct EC public key
	ByteString ecPubData = hybridPub->getClassicalPublicKey();
	ByteString ecPubCopy = ecPubData;
	PublicKey* ecPub = NULL;
	if (!ecdsa->reconstructPublicKey(&ecPub, ecPubCopy))
	{
		ERROR_MSG("Failed to reconstruct EC public key");
		OQSCryptoFactory::i()->recycleAsymmetricAlgorithm(mldsa);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(ecdsa);
		return false;
	}

	// Verify with ECDSA
	bool result = ecdsa->verify(ecPub, originalData, sigECDSA, AsymMech::ECDSA);
	if (!result)
	{
		ERROR_MSG("ECDSA verification failed");
	}

	// Clean up
	delete ecPub;
	OQSCryptoFactory::i()->recycleAsymmetricAlgorithm(mldsa);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(ecdsa);

	// Both signatures must verify
	return result;
}

unsigned long HybridSignature::getMinKeySize()
{
	return 65;  // ML-DSA-65 minimum
}

unsigned long HybridSignature::getMaxKeySize()
{
	return 87;  // ML-DSA-87 maximum
}

bool HybridSignature::reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData)
{
	if ((ppParams == NULL) || (serialisedData.size() == 0))
	{
		return false;
	}

	HybridSignatureParameters* params = new HybridSignatureParameters();

	if (!params->deserialise(serialisedData))
	{
		delete params;
		return false;
	}

	*ppParams = params;
	return true;
}

bool HybridSignature::reconstructKeyPair(AsymmetricKeyPair** /*ppKeyPair*/, ByteString& /*serialisedData*/)
{
	ERROR_MSG("reconstructKeyPair not implemented for Hybrid Signature");
	return false;
}

bool HybridSignature::reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData)
{
	HybridSignaturePublicKey* pub = new HybridSignaturePublicKey();

	if (!pub->deserialise(serialisedData))
	{
		delete pub;
		return false;
	}

	*ppPublicKey = pub;
	return true;
}

bool HybridSignature::reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData)
{
	HybridSignaturePrivateKey* priv = new HybridSignaturePrivateKey();

	if (!priv->deserialise(serialisedData))
	{
		delete priv;
		return false;
	}

	*ppPrivateKey = priv;
	return true;
}

PublicKey* HybridSignature::newPublicKey()
{
	return (PublicKey*) new HybridSignaturePublicKey();
}

PrivateKey* HybridSignature::newPrivateKey()
{
	return (PrivateKey*) new HybridSignaturePrivateKey();
}

AsymmetricParameters* HybridSignature::newParameters()
{
	return (AsymmetricParameters*) new HybridSignatureParameters();
}

bool HybridSignature::encrypt(PublicKey* /*publicKey*/, const ByteString& /*data*/, ByteString& /*encryptedData*/, const AsymMech::Type /*padding*/)
{
	ERROR_MSG("Hybrid Signature does not support encrypt operation");
	return false;
}

bool HybridSignature::decrypt(PrivateKey* /*privateKey*/, const ByteString& /*encryptedData*/, ByteString& /*data*/, const AsymMech::Type /*padding*/)
{
	ERROR_MSG("Hybrid Signature does not support decrypt operation");
	return false;
}

void HybridSignature::recycleKeyPair(AsymmetricKeyPair* toRecycle)
{
	delete toRecycle;
}

void HybridSignature::recycleParameters(AsymmetricParameters* toRecycle)
{
	delete toRecycle;
}

void HybridSignature::recyclePublicKey(PublicKey* toRecycle)
{
	delete toRecycle;
}

void HybridSignature::recyclePrivateKey(PrivateKey* toRecycle)
{
	delete toRecycle;
}

#endif /* WITH_PQC */
