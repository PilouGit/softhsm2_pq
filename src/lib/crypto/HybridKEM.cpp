/*
 * Copyright (c) 2024 SoftHSM Project
 * All rights reserved.
 */

#include "config.h"
#include "log.h"
#include "HybridKEM.h"
#include "HybridKEMKeyPair.h"
#include "HybridCombiner.h"
#include "CryptoFactory.h"
#include "OQSCryptoFactory.h"
#include "OQSMLKEM.h"
#include "MLKEMParameters.h"
#include "MLKEMPublicKey.h"
#include "MLKEMPrivateKey.h"
#include "ECParameters.h"
#include "ECPublicKey.h"
#include "ECPrivateKey.h"

#ifdef WITH_PQC

HybridKEM::HybridKEM()
{
}

HybridKEM::~HybridKEM()
{
}

bool HybridKEM::generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* /*rng*/)
{
	printf("DEBUG: generateKeyPair called\n");
	if ((ppKeyPair == NULL) || (parameters == NULL))
	{
		printf("DEBUG: NULL parameters\n");
		return false;
	}

	if (!parameters->areOfType(HybridKEMParameters::type))
	{
		ERROR_MSG("Invalid parameters for Hybrid KEM key generation");
		printf("DEBUG: Wrong parameter type\n");
		return false;
	}

	HybridKEMParameters* params = (HybridKEMParameters*) parameters;
	CK_MECHANISM_TYPE mechanism = params->getHybridMechanism();
	printf("DEBUG: mechanism=%lu, mlkem_param=%lu, ec_curve_size=%zu\n",
	       (unsigned long)mechanism, params->getMLKEMParameterSet(), params->getECCurve().size());

	// Generate ML-KEM key pair
	MLKEMParameters mlkemParams;
	mlkemParams.setParameterSet(params->getMLKEMParameterSet());

	printf("DEBUG: Getting ML-KEM algorithm\n");
	AsymmetricAlgorithm* mlkem = OQSCryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::MLKEM);
	if (mlkem == NULL)
	{
		ERROR_MSG("Failed to get ML-KEM algorithm");
		printf("DEBUG: Failed to get ML-KEM algorithm\n");
		return false;
	}

	printf("DEBUG: Generating ML-KEM key pair\n");
	AsymmetricKeyPair* mlkemKP = NULL;
	if (!mlkem->generateKeyPair(&mlkemKP, &mlkemParams))
	{
		ERROR_MSG("Failed to generate ML-KEM key pair");
		printf("DEBUG: Failed to generate ML-KEM key pair\n");
		OQSCryptoFactory::i()->recycleAsymmetricAlgorithm(mlkem);
		return false;
	}

	printf("DEBUG: ML-KEM key pair generated successfully\n");

	// Generate ECDH key pair
	ECParameters ecParams;
	ecParams.setEC(params->getECCurve());

	printf("DEBUG: Getting ECDH algorithm\n");
	AsymmetricAlgorithm* ecdh = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::ECDH);
	if (ecdh == NULL)
	{
		ERROR_MSG("Failed to get ECDH algorithm");
		printf("DEBUG: Failed to get ECDH algorithm\n");
		mlkem->recycleKeyPair(mlkemKP);
		OQSCryptoFactory::i()->recycleAsymmetricAlgorithm(mlkem);
		return false;
	}

	printf("DEBUG: Generating ECDH key pair\n");
	AsymmetricKeyPair* ecdhKP = NULL;
	if (!ecdh->generateKeyPair(&ecdhKP, &ecParams))
	{
		ERROR_MSG("Failed to generate ECDH key pair");
		printf("DEBUG: Failed to generate ECDH key pair\n");
		mlkem->recycleKeyPair(mlkemKP);
		OQSCryptoFactory::i()->recycleAsymmetricAlgorithm(mlkem);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(ecdh);
		return false;
	}

	printf("DEBUG: ECDH key pair generated successfully\n");

	// Create hybrid key pair
	printf("DEBUG: Creating hybrid key pair\n");
	HybridKEMKeyPair* hybridKP = new HybridKEMKeyPair();

	// Combine public keys
	printf("DEBUG: Combining public keys\n");
	HybridKEMPublicKey hybridPub;
	hybridPub.setHybridMechanism(mechanism);
	hybridPub.setMLKEMParameterSet(params->getMLKEMParameterSet());
	hybridPub.setECCurve(params->getECCurve());

	MLKEMPublicKey* mlkemPub = (MLKEMPublicKey*) mlkemKP->getPublicKey();
	PublicKey* ecPub = ecdhKP->getPublicKey();

	printf("DEBUG: ML-KEM pub key size=%zu, EC pub serialized size=%zu\n",
	       mlkemPub->getPublicKey().size(), ecPub->serialise().size());

	// Store serialized keys
	hybridPub.setPQCPublicKey(mlkemPub->getPublicKey());
	hybridPub.setClassicalPublicKey(ecPub->serialise());

	// Combine private keys
	printf("DEBUG: Combining private keys\n");
	HybridKEMPrivateKey hybridPriv;
	hybridPriv.setHybridMechanism(mechanism);
	hybridPriv.setMLKEMParameterSet(params->getMLKEMParameterSet());
	hybridPriv.setECCurve(params->getECCurve());

	MLKEMPrivateKey* mlkemPriv = (MLKEMPrivateKey*) mlkemKP->getPrivateKey();
	PrivateKey* ecPriv = ecdhKP->getPrivateKey();

	printf("DEBUG: ML-KEM priv key size=%zu, EC priv serialized size=%zu\n",
	       mlkemPriv->getPrivateKey().size(), ecPriv->serialise().size());

	hybridPriv.setPQCPrivateKey(mlkemPriv->getPrivateKey());
	hybridPriv.setClassicalPrivateKey(ecPriv->serialise());

	printf("DEBUG: Setting keys in hybrid key pair\n");
	hybridKP->setPublicKey(hybridPub);
	hybridKP->setPrivateKey(hybridPriv);

	// Clean up
	printf("DEBUG: Cleaning up\n");
	mlkem->recycleKeyPair(mlkemKP);
	ecdh->recycleKeyPair(ecdhKP);
	OQSCryptoFactory::i()->recycleAsymmetricAlgorithm(mlkem);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(ecdh);

	printf("DEBUG: Returning success\n");
	*ppKeyPair = hybridKP;
	return true;
}

ByteString HybridKEM::getMechanismLabel(CK_MECHANISM_TYPE mechanism)
{
	const char* label = "";

	switch (mechanism)
	{
		case CKM_VENDOR_MLKEM768_ECDH_P256:
			label = "ML-KEM-768-ECDH-P256";
			break;
		case CKM_VENDOR_MLKEM1024_ECDH_P384:
			label = "ML-KEM-1024-ECDH-P384";
			break;
		case CKM_VENDOR_MLKEM768_X25519:
			label = "ML-KEM-768-X25519";
			break;
		default:
			label = "HYBRID-KEM";
			break;
	}

	return ByteString((const unsigned char*)label, strlen(label));
}

bool HybridKEM::getCiphertextSizes(CK_MECHANISM_TYPE mechanism, size_t& ctPQCSize, size_t& ctClassicalSize)
{
	switch (mechanism)
	{
		case CKM_VENDOR_MLKEM768_ECDH_P256:
			ctPQCSize = 1088;  // ML-KEM-768 ciphertext
			ctClassicalSize = 93;  // P-256 public key (DER encoded)
			return true;

		case CKM_VENDOR_MLKEM1024_ECDH_P384:
			ctPQCSize = 1568;  // ML-KEM-1024 ciphertext
			ctClassicalSize = 122;  // P-384 public key (DER encoded)
			return true;

		case CKM_VENDOR_MLKEM768_X25519:
			ctPQCSize = 1088;  // ML-KEM-768 ciphertext
			ctClassicalSize = 32;  // X25519 public key
			return true;

		default:
			return false;
	}
}

bool HybridKEM::splitCiphertext(const ByteString& ciphertext, CK_MECHANISM_TYPE mechanism,
                                ByteString& ctPQC, ByteString& ctClassical)
{
	size_t ctPQCSize, ctClassicalSize;
	if (!getCiphertextSizes(mechanism, ctPQCSize, ctClassicalSize))
	{
		return false;
	}

	if (ciphertext.size() != ctPQCSize + ctClassicalSize)
	{
		ERROR_MSG("Invalid ciphertext size: %zu (expected %zu)",
		          ciphertext.size(), ctPQCSize + ctClassicalSize);
		return false;
	}

	ctPQC = ciphertext.substr(0, ctPQCSize);
	ctClassical = ciphertext.substr(ctPQCSize, ctClassicalSize);

	return true;
}

bool HybridKEM::encapsulate(PublicKey* publicKey, ByteString& ciphertext, ByteString& sharedSecret)
{
	printf("DEBUG: encapsulate called, publicKey=%p\n", (void*)publicKey);
	fflush(stdout);
	if (publicKey == NULL)
	{
		printf("DEBUG: publicKey is NULL\n");
		fflush(stdout);
		return false;
	}
	printf("DEBUG: publicKey is valid, checking type\n");
	fflush(stdout);
	printf("DEBUG: About to call isOfType, type=%p\n", (void*)HybridKEMPublicKey::type);
	fflush(stdout);
	if (!publicKey->isOfType(HybridKEMPublicKey::type))
	{
		ERROR_MSG("Invalid key type for Hybrid KEM encapsulation");
		printf("DEBUG: Invalid key type\n");
		return false;
	}
	printf("DEBUG: Key type valid\n");

	HybridKEMPublicKey* hybridPub = (HybridKEMPublicKey*) publicKey;
	CK_MECHANISM_TYPE mechanism = hybridPub->getHybridMechanism();
	printf("DEBUG: mechanism=%lu\n", (unsigned long)mechanism);

	// Reconstruct ML-KEM public key
	MLKEMPublicKey mlkemPub;
	mlkemPub.setParameterSet(hybridPub->getMLKEMParameterSet());
	mlkemPub.setPublicKey(hybridPub->getPQCPublicKey());
	printf("DEBUG: ML-KEM public key reconstructed\n");

	// Encapsulate with ML-KEM
	AsymmetricAlgorithm* mlkem = OQSCryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::MLKEM);
	if (mlkem == NULL)
	{
		ERROR_MSG("Failed to get ML-KEM algorithm");
		printf("DEBUG: Failed to get ML-KEM algorithm\n");
		return false;
	}

	OQSMLKEM* mlkemAlg = dynamic_cast<OQSMLKEM*>(mlkem);
	if (mlkemAlg == NULL)
	{
		ERROR_MSG("Invalid ML-KEM algorithm type");
		printf("DEBUG: Invalid ML-KEM algorithm type\n");
		OQSCryptoFactory::i()->recycleAsymmetricAlgorithm(mlkem);
		return false;
	}

	printf("DEBUG: Starting ML-KEM encapsulation\n");
	ByteString ctPQC, ssPQC;
	if (!mlkemAlg->encapsulate(&mlkemPub, ctPQC, ssPQC))
	{
		ERROR_MSG("ML-KEM encapsulation failed");
		printf("DEBUG: ML-KEM encapsulation failed\n");
		OQSCryptoFactory::i()->recycleAsymmetricAlgorithm(mlkem);
		return false;
	}
	printf("DEBUG: ML-KEM encapsulation succeeded, ctPQC size=%zu, ssPQC size=%zu\n",
	       ctPQC.size(), ssPQC.size());

	// Get ECDH algorithm
	printf("DEBUG: Getting ECDH algorithm\n");
	fflush(stdout);
	AsymmetricAlgorithm* ecdh = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::ECDH);
	if (ecdh == NULL)
	{
		ERROR_MSG("Failed to get ECDH algorithm");
		printf("DEBUG: Failed to get ECDH algorithm\n");
		fflush(stdout);
		OQSCryptoFactory::i()->recycleAsymmetricAlgorithm(mlkem);
		return false;
	}
	printf("DEBUG: ECDH algorithm obtained\n");
	fflush(stdout);

	// Reconstruct EC public key from serialized data
	printf("DEBUG: Reconstructing EC public key\n");
	fflush(stdout);
	ByteString ecPubData = hybridPub->getClassicalPublicKey();
	printf("DEBUG: EC pub data size=%zu\n", ecPubData.size());
	fflush(stdout);
	ByteString ecPubSerializedCopy = ecPubData; // Copy for deserialization
	PublicKey* ecPub = NULL;
	if (!ecdh->reconstructPublicKey(&ecPub, ecPubSerializedCopy))
	{
		ERROR_MSG("Failed to reconstruct EC public key");
		printf("DEBUG: Failed to reconstruct EC public key\n");
		fflush(stdout);
		OQSCryptoFactory::i()->recycleAsymmetricAlgorithm(mlkem);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(ecdh);
		return false;
	}
	printf("DEBUG: EC public key reconstructed\n");
	fflush(stdout);

	// Create EC parameters for ephemeral key generation
	printf("DEBUG: Creating EC parameters\n");
	fflush(stdout);
	ByteString ecCurveData = hybridPub->getECCurve();
	printf("DEBUG: EC curve data size=%zu\n", ecCurveData.size());
	fflush(stdout);
	ECParameters* ecParams = new ECParameters();
	ecParams->setEC(ecCurveData);
	printf("DEBUG: EC parameters created\n");
	fflush(stdout);

	// Generate ephemeral ECDH key pair
	printf("DEBUG: Generating ephemeral ECDH key pair\n");
	fflush(stdout);
	AsymmetricKeyPair* ephemeralKP = NULL;
	if (!ecdh->generateKeyPair(&ephemeralKP, ecParams))
	{
		ERROR_MSG("Failed to generate ephemeral ECDH key pair");
		printf("DEBUG: Failed to generate ephemeral ECDH key pair\n");
		fflush(stdout);
		delete ecPub;
		delete ecParams;
		OQSCryptoFactory::i()->recycleAsymmetricAlgorithm(mlkem);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(ecdh);
		return false;
	}
	printf("DEBUG: Ephemeral ECDH key pair generated\n");
	fflush(stdout);

	// Derive shared secret
	printf("DEBUG: Deriving ECDH shared secret\n");
	fflush(stdout);
	SymmetricKey* symKey = NULL;
	PrivateKey* ephemeralPriv = ephemeralKP->getPrivateKey();
	if (!ecdh->deriveKey(&symKey, ecPub, ephemeralPriv))
	{
		ERROR_MSG("ECDH key derivation failed");
		printf("DEBUG: ECDH key derivation failed\n");
		fflush(stdout);
		delete ecPub;
		delete ecParams;
		ecdh->recycleKeyPair(ephemeralKP);
		OQSCryptoFactory::i()->recycleAsymmetricAlgorithm(mlkem);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(ecdh);
		return false;
	}
	printf("DEBUG: ECDH shared secret derived\n");
	fflush(stdout);

	ByteString ssClassical = symKey->getKeyBits();
	printf("DEBUG: ssClassical size=%zu\n", ssClassical.size());
	fflush(stdout);
	delete symKey;

	// The ephemeral public key is the "ciphertext" for ECDH
	printf("DEBUG: Getting ephemeral public key\n");
	fflush(stdout);
	PublicKey* ephemeralPub = ephemeralKP->getPublicKey();
	ByteString ctClassical = ephemeralPub->serialise();
	printf("DEBUG: ctClassical size=%zu\n", ctClassical.size());
	fflush(stdout);

	// Combine ciphertexts
	printf("DEBUG: Combining ciphertexts\n");
	fflush(stdout);
	ciphertext = ctPQC + ctClassical;
	printf("DEBUG: Combined ciphertext size=%zu\n", ciphertext.size());
	fflush(stdout);

	// Combine shared secrets using KDF
	ByteString label = getMechanismLabel(mechanism);
	sharedSecret = HybridCombiner::combineSHA256(ssPQC, ssClassical, label, 32);

	// Clean up
	delete ecPub;
	delete ecParams;
	ecdh->recycleKeyPair(ephemeralKP);
	OQSCryptoFactory::i()->recycleAsymmetricAlgorithm(mlkem);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(ecdh);

	return true;
}

bool HybridKEM::decapsulate(PrivateKey* privateKey, const ByteString& ciphertext, ByteString& sharedSecret)
{
	printf("DEBUG: decapsulate called\n");
	fflush(stdout);
	if (!privateKey->isOfType(HybridKEMPrivateKey::type))
	{
		ERROR_MSG("Invalid key type for Hybrid KEM decapsulation");
		printf("DEBUG: Invalid key type\n");
		fflush(stdout);
		return false;
	}

	HybridKEMPrivateKey* hybridPriv = (HybridKEMPrivateKey*) privateKey;
	CK_MECHANISM_TYPE mechanism = hybridPriv->getHybridMechanism();
	printf("DEBUG: mechanism=%lu, ciphertext size=%zu\n", (unsigned long)mechanism, ciphertext.size());
	fflush(stdout);

	// Split ciphertext
	ByteString ctPQC, ctClassical;
	if (!splitCiphertext(ciphertext, mechanism, ctPQC, ctClassical))
	{
		ERROR_MSG("Failed to split ciphertext");
		printf("DEBUG: Failed to split ciphertext\n");
		fflush(stdout);
		return false;
	}
	printf("DEBUG: Ciphertext split: ctPQC=%zu, ctClassical=%zu\n", ctPQC.size(), ctClassical.size());
	fflush(stdout);

	// Reconstruct ML-KEM private key
	MLKEMPrivateKey mlkemPriv;
	mlkemPriv.setParameterSet(hybridPriv->getMLKEMParameterSet());
	mlkemPriv.setPrivateKey(hybridPriv->getPQCPrivateKey());
	printf("DEBUG: ML-KEM private key reconstructed\n");
	fflush(stdout);

	// Decapsulate with ML-KEM
	AsymmetricAlgorithm* mlkem = OQSCryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::MLKEM);
	if (mlkem == NULL)
	{
		ERROR_MSG("Failed to get ML-KEM algorithm");
		printf("DEBUG: Failed to get ML-KEM algorithm\n");
		fflush(stdout);
		return false;
	}

	OQSMLKEM* mlkemAlg = dynamic_cast<OQSMLKEM*>(mlkem);
	if (mlkemAlg == NULL)
	{
		ERROR_MSG("Invalid ML-KEM algorithm type");
		printf("DEBUG: Invalid ML-KEM algorithm type\n");
		fflush(stdout);
		OQSCryptoFactory::i()->recycleAsymmetricAlgorithm(mlkem);
		return false;
	}

	printf("DEBUG: Starting ML-KEM decapsulation\n");
	fflush(stdout);
	ByteString ssPQC;
	if (!mlkemAlg->decapsulate(&mlkemPriv, ctPQC, ssPQC))
	{
		ERROR_MSG("ML-KEM decapsulation failed");
		printf("DEBUG: ML-KEM decapsulation failed\n");
		fflush(stdout);
		OQSCryptoFactory::i()->recycleAsymmetricAlgorithm(mlkem);
		return false;
	}
	printf("DEBUG: ML-KEM decapsulation succeeded, ssPQC size=%zu\n", ssPQC.size());
	fflush(stdout);

	// Get ECDH algorithm
	printf("DEBUG: Getting ECDH algorithm\n");
	fflush(stdout);
	AsymmetricAlgorithm* ecdh = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::ECDH);
	if (ecdh == NULL)
	{
		ERROR_MSG("Failed to get ECDH algorithm");
		printf("DEBUG: Failed to get ECDH algorithm\n");
		fflush(stdout);
		OQSCryptoFactory::i()->recycleAsymmetricAlgorithm(mlkem);
		return false;
	}

	// Reconstruct EC private key from serialized data
	printf("DEBUG: Reconstructing EC private key\n");
	fflush(stdout);
	ByteString ecPrivData = hybridPriv->getClassicalPrivateKey();
	printf("DEBUG: EC priv data size=%zu\n", ecPrivData.size());
	fflush(stdout);
	ByteString ecPrivCopy = ecPrivData;
	PrivateKey* ecPriv = NULL;
	if (!ecdh->reconstructPrivateKey(&ecPriv, ecPrivCopy))
	{
		ERROR_MSG("Failed to reconstruct EC private key");
		printf("DEBUG: Failed to reconstruct EC private key\n");
		fflush(stdout);
		OQSCryptoFactory::i()->recycleAsymmetricAlgorithm(mlkem);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(ecdh);
		return false;
	}
	printf("DEBUG: EC private key reconstructed\n");
	fflush(stdout);

	// Reconstruct ephemeral public key from ciphertext (serialized public key)
	printf("DEBUG: Reconstructing ephemeral public key from ctClassical\n");
	fflush(stdout);
	ByteString ctClassicalCopy = ctClassical;
	PublicKey* ephemeralPub = NULL;
	if (!ecdh->reconstructPublicKey(&ephemeralPub, ctClassicalCopy))
	{
		ERROR_MSG("Failed to reconstruct ephemeral public key");
		printf("DEBUG: Failed to reconstruct ephemeral public key\n");
		fflush(stdout);
		delete ecPriv;
		OQSCryptoFactory::i()->recycleAsymmetricAlgorithm(mlkem);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(ecdh);
		return false;
	}
	printf("DEBUG: Ephemeral public key reconstructed\n");
	fflush(stdout);

	// Derive shared secret
	printf("DEBUG: Deriving ECDH shared secret\n");
	fflush(stdout);
	SymmetricKey* symKey = NULL;
	if (!ecdh->deriveKey(&symKey, ephemeralPub, ecPriv))
	{
		ERROR_MSG("ECDH key derivation failed");
		printf("DEBUG: ECDH key derivation failed\n");
		fflush(stdout);
		delete ecPriv;
		delete ephemeralPub;
		OQSCryptoFactory::i()->recycleAsymmetricAlgorithm(mlkem);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(ecdh);
		return false;
	}
	printf("DEBUG: ECDH shared secret derived\n");
	fflush(stdout);

	ByteString ssClassical = symKey->getKeyBits();
	printf("DEBUG: ssClassical size=%zu\n", ssClassical.size());
	fflush(stdout);
	delete symKey;

	// Combine shared secrets using KDF
	printf("DEBUG: Combining shared secrets\n");
	fflush(stdout);
	ByteString label = getMechanismLabel(mechanism);
	sharedSecret = HybridCombiner::combineSHA256(ssPQC, ssClassical, label, 32);
	printf("DEBUG: Combined shared secret size=%zu\n", sharedSecret.size());
	fflush(stdout);

	// Clean up
	delete ecPriv;
	delete ephemeralPub;
	OQSCryptoFactory::i()->recycleAsymmetricAlgorithm(mlkem);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(ecdh);

	printf("DEBUG: decapsulate succeeded\n");
	fflush(stdout);
	return true;
}

unsigned long HybridKEM::getMinKeySize()
{
	return 768;  // ML-KEM-768 minimum
}

unsigned long HybridKEM::getMaxKeySize()
{
	return 1024;  // ML-KEM-1024 maximum
}

bool HybridKEM::reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData)
{
	if ((ppParams == NULL) || (serialisedData.size() == 0))
	{
		return false;
	}

	HybridKEMParameters* params = new HybridKEMParameters();

	if (!params->deserialise(serialisedData))
	{
		delete params;
		return false;
	}

	*ppParams = params;
	return true;
}

bool HybridKEM::reconstructKeyPair(AsymmetricKeyPair** /*ppKeyPair*/, ByteString& /*serialisedData*/)
{
	ERROR_MSG("reconstructKeyPair not implemented for Hybrid KEM");
	return false;
}

bool HybridKEM::reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData)
{
	HybridKEMPublicKey* pub = new HybridKEMPublicKey();

	if (!pub->deserialise(serialisedData))
	{
		delete pub;
		return false;
	}

	*ppPublicKey = pub;
	return true;
}

bool HybridKEM::reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData)
{
	HybridKEMPrivateKey* priv = new HybridKEMPrivateKey();

	if (!priv->deserialise(serialisedData))
	{
		delete priv;
		return false;
	}

	*ppPrivateKey = priv;
	return true;
}

PublicKey* HybridKEM::newPublicKey()
{
	return (PublicKey*) new HybridKEMPublicKey();
}

PrivateKey* HybridKEM::newPrivateKey()
{
	return (PrivateKey*) new HybridKEMPrivateKey();
}

AsymmetricParameters* HybridKEM::newParameters()
{
	return (AsymmetricParameters*) new HybridKEMParameters();
}

bool HybridKEM::encrypt(PublicKey* /*publicKey*/, const ByteString& /*data*/, ByteString& /*encryptedData*/, const AsymMech::Type /*padding*/)
{
	ERROR_MSG("Hybrid KEM does not support encrypt operation, use encapsulate instead");
	return false;
}

bool HybridKEM::decrypt(PrivateKey* /*privateKey*/, const ByteString& /*encryptedData*/, ByteString& /*data*/, const AsymMech::Type /*padding*/)
{
	ERROR_MSG("Hybrid KEM does not support decrypt operation, use decapsulate instead");
	return false;
}

#endif /* WITH_PQC */
