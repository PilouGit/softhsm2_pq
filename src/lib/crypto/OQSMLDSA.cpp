/*
 * Copyright (c) 2024 SoftHSM Project
 * All rights reserved.
 */

#include "config.h"
#include "log.h"
#include "OQSMLDSA.h"
#include "MLDSAPublicKey.h"
#include "MLDSAPrivateKey.h"
#include "MLDSAParameters.h"
#include "OQSMLDSAKeyPair.h"
#include "CryptoFactory.h"

#ifdef WITH_PQC
#include <oqs/oqs.h>
#endif

// ML-DSA does not support encrypt/decrypt operations
bool OQSMLDSA::encrypt(PublicKey* publicKey, const ByteString& data, ByteString& encryptedData, const AsymMech::Type padding)
{
	ERROR_MSG("ML-DSA is a signature algorithm, not an encryption algorithm");
	return false;
}

bool OQSMLDSA::decrypt(PrivateKey* privateKey, const ByteString& encryptedData, ByteString& data, const AsymMech::Type padding)
{
	ERROR_MSG("ML-DSA is a signature algorithm, not an encryption algorithm");
	return false;
}

bool OQSMLDSA::generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* rng)
{
#ifdef WITH_PQC
	// Check parameters
	if ((ppKeyPair == NULL) || (parameters == NULL))
	{
		return false;
	}

	if (!parameters->areOfType(MLDSAParameters::type))
	{
		ERROR_MSG("Invalid parameters supplied for ML-DSA key generation");
		return false;
	}

	MLDSAParameters* params = (MLDSAParameters*) parameters;
	unsigned long paramSet = params->getParameterSet();

	// Determine OQS algorithm name based on parameter set
	const char* alg_name = NULL;
	switch (paramSet)
	{
		case 44:
			alg_name = OQS_SIG_alg_ml_dsa_44;
			break;
		case 65:
			alg_name = OQS_SIG_alg_ml_dsa_65;
			break;
		case 87:
			alg_name = OQS_SIG_alg_ml_dsa_87;
			break;
		default:
			ERROR_MSG("Invalid ML-DSA parameter set: %lu", paramSet);
			return false;
	}

	// Initialize OQS signature
	OQS_SIG* sig = OQS_SIG_new(alg_name);
	if (sig == NULL)
	{
		ERROR_MSG("Failed to initialize OQS signature for %s", alg_name);
		return false;
	}

	// Allocate key buffers
	uint8_t* public_key = (uint8_t*)malloc(sig->length_public_key);
	uint8_t* secret_key = (uint8_t*)malloc(sig->length_secret_key);

	if (public_key == NULL || secret_key == NULL)
	{
		ERROR_MSG("Failed to allocate memory for ML-DSA keys");
		free(public_key);
		free(secret_key);
		OQS_SIG_free(sig);
		return false;
	}

	// Generate keypair
	OQS_STATUS status = OQS_SIG_keypair(sig, public_key, secret_key);
	if (status != OQS_SUCCESS)
	{
		ERROR_MSG("ML-DSA key generation failed");
		free(public_key);
		free(secret_key);
		OQS_SIG_free(sig);
		return false;
	}

	// Create key pair
	OQSMLDSAKeyPair* kp = new OQSMLDSAKeyPair();

	MLDSAPublicKey pub;
	pub.setParameterSet(paramSet);
	pub.setPublicKey(ByteString(public_key, sig->length_public_key));

	MLDSAPrivateKey priv;
	priv.setParameterSet(paramSet);
	priv.setPrivateKey(ByteString(secret_key, sig->length_secret_key));

	kp->setPublicKey(pub);
	kp->setPrivateKey(priv);

	// Clean up
	free(public_key);
	free(secret_key);
	OQS_SIG_free(sig);

	*ppKeyPair = kp;

	return true;
#else
	ERROR_MSG("ML-DSA not available - library compiled without PQC support");
	return false;
#endif
}

bool OQSMLDSA::sign(PrivateKey* privateKey, const ByteString& dataToSign, ByteString& signature, const AsymMech::Type mechanism, const void* param, const size_t paramLen)
{
#ifdef WITH_PQC
	// Check if the private key is the right type
	if (!privateKey->isOfType(MLDSAPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied");
		return false;
	}

	MLDSAPrivateKey* mldsaKey = (MLDSAPrivateKey*) privateKey;
	unsigned long paramSet = mldsaKey->getParameterSet();

	// Determine OQS algorithm name based on parameter set
	const char* alg_name = NULL;
	switch (paramSet)
	{
		case 44:
			alg_name = OQS_SIG_alg_ml_dsa_44;
			break;
		case 65:
			alg_name = OQS_SIG_alg_ml_dsa_65;
			break;
		case 87:
			alg_name = OQS_SIG_alg_ml_dsa_87;
			break;
		default:
			ERROR_MSG("Invalid ML-DSA parameter set: %lu", paramSet);
			return false;
	}

	// Initialize OQS signature
	OQS_SIG* sig = OQS_SIG_new(alg_name);
	if (sig == NULL)
	{
		ERROR_MSG("Failed to initialize OQS signature for %s", alg_name);
		return false;
	}

	// Allocate signature buffer
	uint8_t* sig_buf = (uint8_t*)malloc(sig->length_signature);
	if (sig_buf == NULL)
	{
		ERROR_MSG("Failed to allocate memory for ML-DSA signature");
		OQS_SIG_free(sig);
		return false;
	}

	size_t sig_len;
	OQS_STATUS status = OQS_SIG_sign(sig, sig_buf, &sig_len,
	                                  dataToSign.const_byte_str(), dataToSign.size(),
	                                  mldsaKey->getPrivateKey().const_byte_str());

	if (status != OQS_SUCCESS)
	{
		ERROR_MSG("ML-DSA signature generation failed");
		free(sig_buf);
		OQS_SIG_free(sig);
		return false;
	}

	signature = ByteString(sig_buf, sig_len);

	free(sig_buf);
	OQS_SIG_free(sig);

	return true;
#else
	ERROR_MSG("ML-DSA not available - library compiled without PQC support");
	return false;
#endif
}

bool OQSMLDSA::verify(PublicKey* publicKey, const ByteString& originalData, const ByteString& signature, const AsymMech::Type mechanism, const void* param, const size_t paramLen)
{
#ifdef WITH_PQC
	// Check if the public key is the right type
	if (!publicKey->isOfType(MLDSAPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied");
		return false;
	}

	MLDSAPublicKey* mldsaKey = (MLDSAPublicKey*) publicKey;
	unsigned long paramSet = mldsaKey->getParameterSet();

	// Determine OQS algorithm name based on parameter set
	const char* alg_name = NULL;
	switch (paramSet)
	{
		case 44:
			alg_name = OQS_SIG_alg_ml_dsa_44;
			break;
		case 65:
			alg_name = OQS_SIG_alg_ml_dsa_65;
			break;
		case 87:
			alg_name = OQS_SIG_alg_ml_dsa_87;
			break;
		default:
			ERROR_MSG("Invalid ML-DSA parameter set: %lu", paramSet);
			return false;
	}

	// Initialize OQS signature
	OQS_SIG* sig = OQS_SIG_new(alg_name);
	if (sig == NULL)
	{
		ERROR_MSG("Failed to initialize OQS signature for %s", alg_name);
		return false;
	}

	OQS_STATUS status = OQS_SIG_verify(sig,
	                                    originalData.const_byte_str(), originalData.size(),
	                                    signature.const_byte_str(), signature.size(),
	                                    mldsaKey->getPublicKey().const_byte_str());

	OQS_SIG_free(sig);

	return (status == OQS_SUCCESS);
#else
	ERROR_MSG("ML-DSA not available - library compiled without PQC support");
	return false;
#endif
}

unsigned long OQSMLDSA::getMinKeySize()
{
	return 44; // ML-DSA-44
}

unsigned long OQSMLDSA::getMaxKeySize()
{
	return 87; // ML-DSA-87
}

bool OQSMLDSA::reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData)
{
	// Check input parameters
	if ((ppParams == NULL) || (serialisedData.size() == 0))
	{
		return false;
	}

	MLDSAParameters* params = new MLDSAParameters();

	if (!params->deserialise(serialisedData))
	{
		delete params;
		return false;
	}

	*ppParams = params;
	return true;
}

bool OQSMLDSA::reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData)
{
	// Not used for key reconstruction in SoftHSM
	ERROR_MSG("reconstructKeyPair not implemented for ML-DSA");
	return false;
}

bool OQSMLDSA::reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData)
{
	MLDSAPublicKey* pub = new MLDSAPublicKey();

	if (!pub->deserialise(serialisedData))
	{
		delete pub;
		return false;
	}

	*ppPublicKey = pub;
	return true;
}

bool OQSMLDSA::reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData)
{
	MLDSAPrivateKey* priv = new MLDSAPrivateKey();

	if (!priv->deserialise(serialisedData))
	{
		delete priv;
		return false;
	}

	*ppPrivateKey = priv;
	return true;
}

PublicKey* OQSMLDSA::newPublicKey()
{
	return (PublicKey*) new MLDSAPublicKey();
}

PrivateKey* OQSMLDSA::newPrivateKey()
{
	return (PrivateKey*) new MLDSAPrivateKey();
}
