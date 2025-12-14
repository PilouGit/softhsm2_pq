/*
 * Copyright (c) 2024 SoftHSM Project
 * All rights reserved.
 */

#include "config.h"
#include "log.h"
#include "OQSMLKEM.h"
#include "MLKEMPublicKey.h"
#include "MLKEMPrivateKey.h"
#include "MLKEMParameters.h"
#include "OQSMLKEMKeyPair.h"
#include "CryptoFactory.h"

#ifdef WITH_PQC
#include <oqs/oqs.h>
#endif

// ML-KEM does not support encrypt/decrypt operations
bool OQSMLKEM::encrypt(PublicKey* publicKey, const ByteString& data, ByteString& encryptedData, const AsymMech::Type padding)
{
	ERROR_MSG("ML-KEM does not support encrypt operation, use encapsulate instead");
	return false;
}

bool OQSMLKEM::decrypt(PrivateKey* privateKey, const ByteString& encryptedData, ByteString& data, const AsymMech::Type padding)
{
	ERROR_MSG("ML-KEM does not support decrypt operation, use decapsulate instead");
	return false;
}

bool OQSMLKEM::generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* rng)
{
#ifdef WITH_PQC
	// Check parameters
	if ((ppKeyPair == NULL) || (parameters == NULL))
	{
		return false;
	}

	if (!parameters->areOfType(MLKEMParameters::type))
	{
		ERROR_MSG("Invalid parameters supplied for ML-KEM key generation");
		return false;
	}

	MLKEMParameters* params = (MLKEMParameters*) parameters;
	unsigned long paramSet = params->getParameterSet();

	// Determine OQS algorithm name based on parameter set
	const char* alg_name = NULL;
	switch (paramSet)
	{
		case 512:
			alg_name = OQS_KEM_alg_ml_kem_512;
			break;
		case 768:
			alg_name = OQS_KEM_alg_ml_kem_768;
			break;
		case 1024:
			alg_name = OQS_KEM_alg_ml_kem_1024;
			break;
		default:
			ERROR_MSG("Invalid ML-KEM parameter set: %lu", paramSet);
			return false;
	}

	// Initialize OQS KEM
	OQS_KEM* kem = OQS_KEM_new(alg_name);
	if (kem == NULL)
	{
		ERROR_MSG("Failed to initialize OQS KEM for %s", alg_name);
		return false;
	}

	// Allocate key buffers
	uint8_t* public_key = (uint8_t*)malloc(kem->length_public_key);
	uint8_t* secret_key = (uint8_t*)malloc(kem->length_secret_key);

	if (public_key == NULL || secret_key == NULL)
	{
		ERROR_MSG("Failed to allocate memory for ML-KEM keys");
		free(public_key);
		free(secret_key);
		OQS_KEM_free(kem);
		return false;
	}

	// Generate keypair
	OQS_STATUS status = OQS_KEM_keypair(kem, public_key, secret_key);
	if (status != OQS_SUCCESS)
	{
		ERROR_MSG("ML-KEM key generation failed");
		free(public_key);
		free(secret_key);
		OQS_KEM_free(kem);
		return false;
	}

	// Create key pair
	OQSMLKEMKeyPair* kp = new OQSMLKEMKeyPair();

	MLKEMPublicKey pub;
	pub.setParameterSet(paramSet);
	pub.setPublicKey(ByteString(public_key, kem->length_public_key));

	MLKEMPrivateKey priv;
	priv.setParameterSet(paramSet);
	priv.setPrivateKey(ByteString(secret_key, kem->length_secret_key));

	kp->setPublicKey(pub);
	kp->setPrivateKey(priv);

	// Clean up
	free(public_key);
	free(secret_key);
	OQS_KEM_free(kem);

	*ppKeyPair = kp;

	return true;
#else
	ERROR_MSG("ML-KEM not available - library compiled without PQC support");
	return false;
#endif
}

unsigned long OQSMLKEM::getMinKeySize()
{
	return 512; // ML-KEM-512
}

unsigned long OQSMLKEM::getMaxKeySize()
{
	return 1024; // ML-KEM-1024
}

bool OQSMLKEM::reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData)
{
	// Check input parameters
	if ((ppParams == NULL) || (serialisedData.size() == 0))
	{
		return false;
	}

	MLKEMParameters* params = new MLKEMParameters();

	if (!params->deserialise(serialisedData))
	{
		delete params;
		return false;
	}

	*ppParams = params;
	return true;
}

bool OQSMLKEM::reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData)
{
	// Not used for key reconstruction in SoftHSM
	ERROR_MSG("reconstructKeyPair not implemented for ML-KEM");
	return false;
}

bool OQSMLKEM::reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData)
{
	MLKEMPublicKey* pub = new MLKEMPublicKey();

	if (!pub->deserialise(serialisedData))
	{
		delete pub;
		return false;
	}

	*ppPublicKey = pub;
	return true;
}

bool OQSMLKEM::reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData)
{
	MLKEMPrivateKey* priv = new MLKEMPrivateKey();

	if (!priv->deserialise(serialisedData))
	{
		delete priv;
		return false;
	}

	*ppPrivateKey = priv;
	return true;
}

PublicKey* OQSMLKEM::newPublicKey()
{
	return (PublicKey*) new MLKEMPublicKey();
}

PrivateKey* OQSMLKEM::newPrivateKey()
{
	return (PrivateKey*) new MLKEMPrivateKey();
}

bool OQSMLKEM::encapsulate(PublicKey* publicKey, ByteString& ciphertext, ByteString& sharedSecret)
{
#ifdef WITH_PQC
	// Check if the public key is the right type
	if (!publicKey->isOfType(MLKEMPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied");
		return false;
	}

	MLKEMPublicKey* mlkemKey = (MLKEMPublicKey*) publicKey;
	unsigned long paramSet = mlkemKey->getParameterSet();

	// Determine OQS algorithm name based on parameter set
	const char* alg_name = NULL;
	switch (paramSet)
	{
		case 512:
			alg_name = OQS_KEM_alg_ml_kem_512;
			break;
		case 768:
			alg_name = OQS_KEM_alg_ml_kem_768;
			break;
		case 1024:
			alg_name = OQS_KEM_alg_ml_kem_1024;
			break;
		default:
			ERROR_MSG("Invalid ML-KEM parameter set: %lu", paramSet);
			return false;
	}

	// Initialize OQS KEM
	OQS_KEM* kem = OQS_KEM_new(alg_name);
	if (kem == NULL)
	{
		ERROR_MSG("Failed to initialize OQS KEM for %s", alg_name);
		return false;
	}

	// Allocate buffers for ciphertext and shared secret
	uint8_t* ct_buf = (uint8_t*)malloc(kem->length_ciphertext);
	uint8_t* ss_buf = (uint8_t*)malloc(kem->length_shared_secret);

	if (ct_buf == NULL || ss_buf == NULL)
	{
		ERROR_MSG("Failed to allocate memory for ML-KEM encapsulation");
		free(ct_buf);
		free(ss_buf);
		OQS_KEM_free(kem);
		return false;
	}

	// Perform encapsulation
	OQS_STATUS status = OQS_KEM_encaps(kem, ct_buf, ss_buf,
	                                    mlkemKey->getPublicKey().const_byte_str());

	if (status != OQS_SUCCESS)
	{
		ERROR_MSG("ML-KEM encapsulation failed");
		free(ct_buf);
		free(ss_buf);
		OQS_KEM_free(kem);
		return false;
	}

	// Set output parameters
	ciphertext = ByteString(ct_buf, kem->length_ciphertext);
	sharedSecret = ByteString(ss_buf, kem->length_shared_secret);

	// Clean up
	free(ct_buf);
	free(ss_buf);
	OQS_KEM_free(kem);

	return true;
#else
	ERROR_MSG("ML-KEM not available - library compiled without PQC support");
	return false;
#endif
}

bool OQSMLKEM::decapsulate(PrivateKey* privateKey, const ByteString& ciphertext, ByteString& sharedSecret)
{
#ifdef WITH_PQC
	// Check if the private key is the right type
	if (!privateKey->isOfType(MLKEMPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied");
		return false;
	}

	MLKEMPrivateKey* mlkemKey = (MLKEMPrivateKey*) privateKey;
	unsigned long paramSet = mlkemKey->getParameterSet();

	// Determine OQS algorithm name based on parameter set
	const char* alg_name = NULL;
	switch (paramSet)
	{
		case 512:
			alg_name = OQS_KEM_alg_ml_kem_512;
			break;
		case 768:
			alg_name = OQS_KEM_alg_ml_kem_768;
			break;
		case 1024:
			alg_name = OQS_KEM_alg_ml_kem_1024;
			break;
		default:
			ERROR_MSG("Invalid ML-KEM parameter set: %lu", paramSet);
			return false;
	}

	// Initialize OQS KEM
	OQS_KEM* kem = OQS_KEM_new(alg_name);
	if (kem == NULL)
	{
		ERROR_MSG("Failed to initialize OQS KEM for %s", alg_name);
		return false;
	}

	// Verify ciphertext size
	if (ciphertext.size() != kem->length_ciphertext)
	{
		ERROR_MSG("Invalid ciphertext size: %zu (expected %zu)", ciphertext.size(), kem->length_ciphertext);
		OQS_KEM_free(kem);
		return false;
	}

	// Allocate buffer for shared secret
	uint8_t* ss_buf = (uint8_t*)malloc(kem->length_shared_secret);
	if (ss_buf == NULL)
	{
		ERROR_MSG("Failed to allocate memory for ML-KEM decapsulation");
		OQS_KEM_free(kem);
		return false;
	}

	// Perform decapsulation
	OQS_STATUS status = OQS_KEM_decaps(kem, ss_buf,
	                                    ciphertext.const_byte_str(),
	                                    mlkemKey->getPrivateKey().const_byte_str());

	if (status != OQS_SUCCESS)
	{
		ERROR_MSG("ML-KEM decapsulation failed");
		free(ss_buf);
		OQS_KEM_free(kem);
		return false;
	}

	// Set output parameter
	sharedSecret = ByteString(ss_buf, kem->length_shared_secret);

	// Clean up
	free(ss_buf);
	OQS_KEM_free(kem);

	return true;
#else
	ERROR_MSG("ML-KEM not available - library compiled without PQC support");
	return false;
#endif
}
