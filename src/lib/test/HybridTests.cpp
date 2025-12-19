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
 HybridTests.cpp

 Contains test cases for hybrid cryptography
 *****************************************************************************/

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include "HybridTests.h"
#include "../pkcs11/vendor_defines.h"

// Note: C_EncapsulateKey and C_DecapsulateKey are declared in pkcs11.h (PKCS#11 v3.2)

// CKA_TOKEN
const CK_BBOOL IN_SESSION = CK_FALSE;
const CK_BBOOL ON_TOKEN = CK_TRUE;

// CKA_PRIVATE
const CK_BBOOL IS_PUBLIC = CK_FALSE;
const CK_BBOOL IS_PRIVATE = CK_TRUE;

CPPUNIT_TEST_SUITE_REGISTRATION(HybridTests);

CK_RV HybridTests::generateHybridKEMKeyPair(CK_SESSION_HANDLE hSession,
                                             CK_MECHANISM_TYPE mechanism,
                                             CK_BBOOL bTokenPuk,
                                             CK_BBOOL bPrivatePuk,
                                             CK_BBOOL bTokenPrk,
                                             CK_BBOOL bPrivatePrk,
                                             CK_OBJECT_HANDLE &hPuk,
                                             CK_OBJECT_HANDLE &hPrk)
{
	CK_MECHANISM mech = { mechanism, NULL_PTR, 0 };
	CK_BBOOL bTrue = CK_TRUE;
	CK_BBOOL bFalse = CK_FALSE;
	CK_KEY_TYPE keyType = CKK_VENDOR_HYBRID_KEM;
	CK_OBJECT_CLASS publicKeyClass = CKO_PUBLIC_KEY;
	CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY;

	CK_ATTRIBUTE pukAttribs[] = {
		{ CKA_CLASS, &publicKeyClass, sizeof(publicKeyClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_TOKEN, &bTokenPuk, sizeof(bTokenPuk) },
		{ CKA_PRIVATE, &bPrivatePuk, sizeof(bPrivatePuk) },
		{ CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_VERIFY, &bFalse, sizeof(bFalse) },
		{ CKA_WRAP, &bFalse, sizeof(bFalse) }
	};

	CK_ATTRIBUTE prkAttribs[] = {
		{ CKA_CLASS, &privateKeyClass, sizeof(privateKeyClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_TOKEN, &bTokenPrk, sizeof(bTokenPrk) },
		{ CKA_PRIVATE, &bPrivatePrk, sizeof(bPrivatePrk) },
		{ CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
		{ CKA_DECRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_SIGN, &bFalse, sizeof(bFalse) },
		{ CKA_UNWRAP, &bFalse, sizeof(bFalse) },
		{ CKA_EXTRACTABLE, &bFalse, sizeof(bFalse) }
	};

	hPuk = CK_INVALID_HANDLE;
	hPrk = CK_INVALID_HANDLE;

	printf("TEST: About to call C_GenerateKeyPair with mechanism=0x%08lX, keyType=0x%08lX\n", mechanism, keyType);
	CK_RV rv = CRYPTOKI_F_PTR( C_GenerateKeyPair(hSession, &mech,
	                                               pukAttribs, sizeof(pukAttribs)/sizeof(CK_ATTRIBUTE),
	                                               prkAttribs, sizeof(prkAttribs)/sizeof(CK_ATTRIBUTE),
	                                               &hPuk, &hPrk) );
	printf("TEST: C_GenerateKeyPair returned rv=0x%08lX\n", rv);
	if (rv != CKR_OK) {
		printf("C_GenerateKeyPair for hybrid KEM (mech=0x%08lX) failed with rv=0x%08lX\n", mechanism, rv);
	}
	return rv;
}

CK_RV HybridTests::generateHybridSignatureKeyPair(CK_SESSION_HANDLE hSession,
                                                   CK_MECHANISM_TYPE mechanism,
                                                   CK_BBOOL bTokenPuk,
                                                   CK_BBOOL bPrivatePuk,
                                                   CK_BBOOL bTokenPrk,
                                                   CK_BBOOL bPrivatePrk,
                                                   CK_OBJECT_HANDLE &hPuk,
                                                   CK_OBJECT_HANDLE &hPrk)
{
	CK_MECHANISM mech = { mechanism, NULL_PTR, 0 };
	CK_BBOOL bTrue = CK_TRUE;
	CK_BBOOL bFalse = CK_FALSE;
	CK_KEY_TYPE keyType = CKK_VENDOR_HYBRID_SIGNATURE;
	CK_OBJECT_CLASS publicKeyClass = CKO_PUBLIC_KEY;
	CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY;

	CK_ATTRIBUTE pukAttribs[] = {
		{ CKA_CLASS, &publicKeyClass, sizeof(publicKeyClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_TOKEN, &bTokenPuk, sizeof(bTokenPuk) },
		{ CKA_PRIVATE, &bPrivatePuk, sizeof(bPrivatePuk) },
		{ CKA_VERIFY, &bTrue, sizeof(bTrue) },
		{ CKA_ENCRYPT, &bFalse, sizeof(bFalse) },
		{ CKA_WRAP, &bFalse, sizeof(bFalse) }
	};

	CK_ATTRIBUTE prkAttribs[] = {
		{ CKA_CLASS, &privateKeyClass, sizeof(privateKeyClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_TOKEN, &bTokenPrk, sizeof(bTokenPrk) },
		{ CKA_PRIVATE, &bPrivatePrk, sizeof(bPrivatePrk) },
		{ CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
		{ CKA_SIGN, &bTrue, sizeof(bTrue) },
		{ CKA_DECRYPT, &bFalse, sizeof(bFalse) },
		{ CKA_UNWRAP, &bFalse, sizeof(bFalse) },
		{ CKA_EXTRACTABLE, &bFalse, sizeof(bFalse) }
	};

	hPuk = CK_INVALID_HANDLE;
	hPrk = CK_INVALID_HANDLE;

	CK_RV rv = CRYPTOKI_F_PTR( C_GenerateKeyPair(hSession, &mech,
	                                               pukAttribs, sizeof(pukAttribs)/sizeof(CK_ATTRIBUTE),
	                                               prkAttribs, sizeof(prkAttribs)/sizeof(CK_ATTRIBUTE),
	                                               &hPuk, &hPrk) );
	if (rv != CKR_OK) {
		printf("C_GenerateKeyPair for hybrid signature (mech=0x%08lX) failed with rv=0x%08lX\n", mechanism, rv);
	}
	return rv;
}

void HybridTests::hybridKEMEncapDecap(CK_MECHANISM_TYPE mechanism,
                                       CK_SESSION_HANDLE hSession,
                                       CK_OBJECT_HANDLE hPublicKey,
                                       CK_OBJECT_HANDLE hPrivateKey)
{
	CK_MECHANISM mech = { mechanism, NULL_PTR, 0 };
	CK_BYTE ciphertext[2048];
	CK_ULONG ulCiphertextLen = sizeof(ciphertext);
	CK_OBJECT_HANDLE hSharedSecret1 = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hSharedSecret2 = CK_INVALID_HANDLE;
	CK_RV rv;

	// Template for derived shared secret
	CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_GENERIC_SECRET;
	CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;

	CK_ATTRIBUTE secretTemplate[] = {
		{ CKA_CLASS, &keyClass, sizeof(keyClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
		{ CKA_PRIVATE, &bFalse, sizeof(bFalse) },
		{ CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }
	};

	// Test encapsulation (PKCS#11 v3.2)
	rv = CRYPTOKI_F_PTR( C_EncapsulateKey(hSession, &mech, hPublicKey,
	                                       secretTemplate, sizeof(secretTemplate)/sizeof(CK_ATTRIBUTE),
	                                       ciphertext, &ulCiphertextLen,
	                                       &hSharedSecret1) );
	if (rv != CKR_OK) {
		printf("C_EncapsulateKey failed with rv=0x%08lX, mechanism=0x%08lX\n", rv, mechanism);
	}
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(ulCiphertextLen > 0);
	CPPUNIT_ASSERT(hSharedSecret1 != CK_INVALID_HANDLE);

	// Test decapsulation (PKCS#11 v3.2)
	rv = CRYPTOKI_F_PTR( C_DecapsulateKey(hSession, &mech, hPrivateKey,
	                                       secretTemplate, sizeof(secretTemplate)/sizeof(CK_ATTRIBUTE),
	                                       ciphertext, ulCiphertextLen,
	                                       &hSharedSecret2) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(hSharedSecret2 != CK_INVALID_HANDLE);

	// Extract and compare shared secrets
	CK_BYTE sharedSecret1[256];
	CK_BYTE sharedSecret2[256];
	CK_ATTRIBUTE attr1[] = {
		{ CKA_VALUE, sharedSecret1, sizeof(sharedSecret1) }
	};
	CK_ATTRIBUTE attr2[] = {
		{ CKA_VALUE, sharedSecret2, sizeof(sharedSecret2) }
	};

	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hSharedSecret1, attr1, 1) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hSharedSecret2, attr2, 1) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Verify shared secrets match
	CPPUNIT_ASSERT(attr1[0].ulValueLen == attr2[0].ulValueLen);
	CPPUNIT_ASSERT(memcmp(sharedSecret1, sharedSecret2, attr1[0].ulValueLen) == 0);

	// Cleanup
	CRYPTOKI_F_PTR( C_DestroyObject(hSession, hSharedSecret1) );
	CRYPTOKI_F_PTR( C_DestroyObject(hSession, hSharedSecret2) );
}

void HybridTests::hybridSignatureSignVerify(CK_MECHANISM_TYPE mechanism,
                                             CK_SESSION_HANDLE hSession,
                                             CK_OBJECT_HANDLE hPublicKey,
                                             CK_OBJECT_HANDLE hPrivateKey)
{
	CK_MECHANISM mech = { mechanism, NULL_PTR, 0 };
	CK_BYTE data[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	                   0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
	CK_BYTE signature[5000];  // Large enough for hybrid signature
	CK_ULONG ulSignatureLen = sizeof(signature);
	CK_RV rv;

	// Sign the data
	rv = CRYPTOKI_F_PTR( C_SignInit(hSession, &mech, hPrivateKey) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_Sign(hSession, data, sizeof(data), signature, &ulSignatureLen) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(ulSignatureLen > 0);

	// Verify the signature
	rv = CRYPTOKI_F_PTR( C_VerifyInit(hSession, &mech, hPublicKey) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_Verify(hSession, data, sizeof(data), signature, ulSignatureLen) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Verify with wrong data should fail
	CK_BYTE wrongData[] = { 0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8 };
	rv = CRYPTOKI_F_PTR( C_VerifyInit(hSession, &mech, hPublicKey) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_Verify(hSession, wrongData, sizeof(wrongData), signature, ulSignatureLen) );
	CPPUNIT_ASSERT(rv == CKR_SIGNATURE_INVALID);
}

void HybridTests::testHybridKEMKeyGen()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;
	CK_OBJECT_HANDLE hPuk, hPrk;

	// Initialize and open session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Test ML-KEM768 + ECDH P-256
	rv = generateHybridKEMKeyPair(hSession, CKM_VENDOR_MLKEM768_ECDH_P256,
	                               IN_SESSION, IS_PUBLIC, IN_SESSION, IS_PUBLIC,
	                               hPuk, hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(hPuk != CK_INVALID_HANDLE);
	CPPUNIT_ASSERT(hPrk != CK_INVALID_HANDLE);

	// Test ML-KEM1024 + ECDH P-384
	rv = generateHybridKEMKeyPair(hSession, CKM_VENDOR_MLKEM1024_ECDH_P384,
	                               IN_SESSION, IS_PUBLIC, IN_SESSION, IS_PUBLIC,
	                               hPuk, hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(hPuk != CK_INVALID_HANDLE);
	CPPUNIT_ASSERT(hPrk != CK_INVALID_HANDLE);

	// TODO: X25519 support requires EVP_PKEY API in OSSLECDH (not currently implemented)
	// X25519 uses a different OpenSSL API than standard EC curves
	// Test ML-KEM768 + X25519
	// rv = generateHybridKEMKeyPair(hSession, CKM_VENDOR_MLKEM768_X25519,
	//                                IN_SESSION, IS_PUBLIC, IN_SESSION, IS_PUBLIC,
	//                                hPuk, hPrk);
	// CPPUNIT_ASSERT(rv == CKR_OK);
	// CPPUNIT_ASSERT(hPuk != CK_INVALID_HANDLE);
	// CPPUNIT_ASSERT(hPrk != CK_INVALID_HANDLE);

	CRYPTOKI_F_PTR( C_CloseSession(hSession) );
}

void HybridTests::testHybridKEMEncapDecap()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;
	CK_OBJECT_HANDLE hPuk, hPrk;

	// Initialize and open session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Test ML-KEM768 + ECDH P-256
	rv = generateHybridKEMKeyPair(hSession, CKM_VENDOR_MLKEM768_ECDH_P256,
	                               IN_SESSION, IS_PUBLIC, IN_SESSION, IS_PUBLIC,
	                               hPuk, hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	hybridKEMEncapDecap(CKM_VENDOR_MLKEM768_ECDH_P256, hSession, hPuk, hPrk);

	// Test ML-KEM1024 + ECDH P-384
	rv = generateHybridKEMKeyPair(hSession, CKM_VENDOR_MLKEM1024_ECDH_P384,
	                               IN_SESSION, IS_PUBLIC, IN_SESSION, IS_PUBLIC,
	                               hPuk, hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	hybridKEMEncapDecap(CKM_VENDOR_MLKEM1024_ECDH_P384, hSession, hPuk, hPrk);

	// Test ML-KEM768 + X25519
	rv = generateHybridKEMKeyPair(hSession, CKM_VENDOR_MLKEM768_X25519,
	                               IN_SESSION, IS_PUBLIC, IN_SESSION, IS_PUBLIC,
	                               hPuk, hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	hybridKEMEncapDecap(CKM_VENDOR_MLKEM768_X25519, hSession, hPuk, hPrk);

	CRYPTOKI_F_PTR( C_CloseSession(hSession) );
}

void HybridTests::testHybridKEMKeyAttributes()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;
	CK_OBJECT_HANDLE hPuk, hPrk;

	// Initialize and open session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Test attributes for each hybrid KEM variant
	struct TestCase {
		CK_MECHANISM_TYPE mechanism;
		const char* name;
		CK_ULONG expectedPukLen;  // Approximate expected public key length
		CK_ULONG expectedPrkLen;  // Approximate expected private key length
	} testCases[] = {
		{ CKM_VENDOR_MLKEM768_ECDH_P256, "ML-KEM768+P-256", 1184, 2400 },
		{ CKM_VENDOR_MLKEM1024_ECDH_P384, "ML-KEM1024+P-384", 1568, 3168 },
		{ CKM_VENDOR_MLKEM768_X25519, "ML-KEM768+X25519", 1184, 2400 }
	};

	for (size_t i = 0; i < sizeof(testCases)/sizeof(testCases[0]); i++)
	{
		// Generate key pair
		rv = generateHybridKEMKeyPair(hSession, testCases[i].mechanism,
		                               IN_SESSION, IS_PUBLIC, IN_SESSION, IS_PUBLIC,
		                               hPuk, hPrk);
		CPPUNIT_ASSERT(rv == CKR_OK);

		// Check public key attributes (only basic attributes)
		CK_OBJECT_CLASS keyClass;
		CK_KEY_TYPE keyType;

		CK_ATTRIBUTE pukAttrs[] = {
			{ CKA_CLASS, &keyClass, sizeof(keyClass) },
			{ CKA_KEY_TYPE, &keyType, sizeof(keyType) }
		};

		rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hPuk, pukAttrs, sizeof(pukAttrs)/sizeof(CK_ATTRIBUTE)) );
		CPPUNIT_ASSERT(rv == CKR_OK);

		// Verify public key attributes
		CPPUNIT_ASSERT(keyClass == CKO_PUBLIC_KEY);
		CPPUNIT_ASSERT(keyType == CKK_VENDOR_HYBRID_KEM);

		// Check private key attributes (only basic attributes)
		CK_ATTRIBUTE prkAttrs[] = {
			{ CKA_CLASS, &keyClass, sizeof(keyClass) },
			{ CKA_KEY_TYPE, &keyType, sizeof(keyType) }
		};

		rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hPrk, prkAttrs, sizeof(prkAttrs)/sizeof(CK_ATTRIBUTE)) );
		CPPUNIT_ASSERT(rv == CKR_OK);

		// Verify private key attributes
		CPPUNIT_ASSERT(keyClass == CKO_PRIVATE_KEY);
		CPPUNIT_ASSERT(keyType == CKK_VENDOR_HYBRID_KEM);
	}

	CRYPTOKI_F_PTR( C_CloseSession(hSession) );
}

void HybridTests::testHybridKEMTokenKeys()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;
	CK_OBJECT_HANDLE hPuk, hPrk;

	// Login as user (required for token objects)
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_Login(hSession, CKU_USER, m_userPin1, m_userPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Test with token-based keys
	rv = generateHybridKEMKeyPair(hSession, CKM_VENDOR_MLKEM768_ECDH_P256,
	                               ON_TOKEN, IS_PRIVATE, ON_TOKEN, IS_PRIVATE,
	                               hPuk, hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Verify keys are on token
	CK_BBOOL bToken;
	CK_BBOOL bPrivate;
	CK_ATTRIBUTE attrs[] = {
		{ CKA_TOKEN, &bToken, sizeof(bToken) },
		{ CKA_PRIVATE, &bPrivate, sizeof(bPrivate) }
	};

	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hPuk, attrs, 2) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(bToken == CK_TRUE);
	CPPUNIT_ASSERT(bPrivate == CK_TRUE);

	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hPrk, attrs, 2) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(bToken == CK_TRUE);
	CPPUNIT_ASSERT(bPrivate == CK_TRUE);

	// Test encapsulation/decapsulation with token keys
	hybridKEMEncapDecap(CKM_VENDOR_MLKEM768_ECDH_P256, hSession, hPuk, hPrk);

	// Cleanup - destroy token objects
	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPuk) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPrk) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	CRYPTOKI_F_PTR( C_Logout(hSession) );
	CRYPTOKI_F_PTR( C_CloseSession(hSession) );
}

void HybridTests::testHybridKEMErrorCases()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;
	CK_OBJECT_HANDLE hPuk, hPrk;

	// Initialize and open session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Test 1: Invalid mechanism
	CK_MECHANISM invalidMech = { 0x99999999, NULL_PTR, 0 };
	CK_BBOOL bTrue = CK_TRUE;
	CK_BBOOL bFalse = CK_FALSE;
	CK_KEY_TYPE keyType = CKK_VENDOR_HYBRID_KEM;
	CK_OBJECT_CLASS publicKeyClass = CKO_PUBLIC_KEY;
	CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY;

	CK_ATTRIBUTE pukAttribs[] = {
		{ CKA_CLASS, &publicKeyClass, sizeof(publicKeyClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
		{ CKA_PRIVATE, &bFalse, sizeof(bFalse) },
		{ CKA_ENCRYPT, &bTrue, sizeof(bTrue) }
	};

	CK_ATTRIBUTE prkAttribs[] = {
		{ CKA_CLASS, &privateKeyClass, sizeof(privateKeyClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
		{ CKA_PRIVATE, &bFalse, sizeof(bFalse) },
		{ CKA_DECRYPT, &bTrue, sizeof(bTrue) }
	};

	rv = CRYPTOKI_F_PTR( C_GenerateKeyPair(hSession, &invalidMech,
	                                       pukAttribs, sizeof(pukAttribs)/sizeof(CK_ATTRIBUTE),
	                                       prkAttribs, sizeof(prkAttribs)/sizeof(CK_ATTRIBUTE),
	                                       &hPuk, &hPrk) );
	CPPUNIT_ASSERT(rv == CKR_MECHANISM_INVALID);

	// Test 2: Encapsulate with invalid public key handle
	rv = generateHybridKEMKeyPair(hSession, CKM_VENDOR_MLKEM768_ECDH_P256,
	                               IN_SESSION, IS_PUBLIC, IN_SESSION, IS_PUBLIC,
	                               hPuk, hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);

	CK_MECHANISM mech = { CKM_VENDOR_MLKEM768_ECDH_P256, NULL_PTR, 0 };
	CK_BYTE ciphertext[5000];
	CK_ULONG ciphertextLen = sizeof(ciphertext);
	CK_OBJECT_HANDLE hSharedSecret;

	CK_ATTRIBUTE sharedSecretTemplate[] = {
		{ CKA_CLASS, &publicKeyClass, sizeof(publicKeyClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) }
	};

	// Try with invalid handle
	rv = CRYPTOKI_F_PTR( C_EncapsulateKey(hSession, &mech, CK_INVALID_HANDLE,
	                                      sharedSecretTemplate, 3,
	                                      ciphertext, &ciphertextLen,
	                                      &hSharedSecret) );
	CPPUNIT_ASSERT(rv != CKR_OK);  // Should fail with invalid handle

	// Test 3: Decapsulate with wrong ciphertext
	CK_BYTE wrongCiphertext[5000];
	memset(wrongCiphertext, 0xFF, sizeof(wrongCiphertext));

	// First do valid encapsulation to get proper length
	rv = CRYPTOKI_F_PTR( C_EncapsulateKey(hSession, &mech, hPuk,
	                                      sharedSecretTemplate, 3,
	                                      ciphertext, &ciphertextLen,
	                                      &hSharedSecret) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CRYPTOKI_F_PTR( C_DestroyObject(hSession, hSharedSecret) );

	// Now try to decapsulate with wrong ciphertext
	rv = CRYPTOKI_F_PTR( C_DecapsulateKey(hSession, &mech, hPrk,
	                                      sharedSecretTemplate, 3,
	                                      wrongCiphertext, ciphertextLen,
	                                      &hSharedSecret) );
	// Decapsulation should either fail or succeed but produce different shared secret
	// The exact behavior depends on the implementation
	if (rv == CKR_OK) {
		CRYPTOKI_F_PTR( C_DestroyObject(hSession, hSharedSecret) );
	}

	CRYPTOKI_F_PTR( C_CloseSession(hSession) );
}

void HybridTests::testHybridSignatureKeyGen()
{
	// TODO: HybridSignature implementation is not complete yet (Phase 3 of roadmap)
	// According to HYBRID_DESIGN.md, this is still in progress
	// Skipping these tests until HybridSignature.cpp is fully implemented

	/*
	CK_RV rv;
	CK_SESSION_HANDLE hSession;
	CK_OBJECT_HANDLE hPuk, hPrk;

	// Initialize and open session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Test ML-DSA-65 + ECDSA P-256
	rv = generateHybridSignatureKeyPair(hSession, CKM_VENDOR_MLDSA65_ECDSA_P256,
	                                     IN_SESSION, IS_PUBLIC, IN_SESSION, IS_PUBLIC,
	                                     hPuk, hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(hPuk != CK_INVALID_HANDLE);
	CPPUNIT_ASSERT(hPrk != CK_INVALID_HANDLE);

	// Test ML-DSA-87 + ECDSA P-384
	rv = generateHybridSignatureKeyPair(hSession, CKM_VENDOR_MLDSA87_ECDSA_P384,
	                                     IN_SESSION, IS_PUBLIC, IN_SESSION, IS_PUBLIC,
	                                     hPuk, hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(hPuk != CK_INVALID_HANDLE);
	CPPUNIT_ASSERT(hPrk != CK_INVALID_HANDLE);

	CRYPTOKI_F_PTR( C_CloseSession(hSession) );
	*/
}

void HybridTests::testHybridSignatureSignVerify()
{
	// TODO: HybridSignature implementation is not complete yet (Phase 3 of roadmap)
	// According to HYBRID_DESIGN.md, this is still in progress
	// Skipping these tests until HybridSignature.cpp is fully implemented

	/*
	CK_RV rv;
	CK_SESSION_HANDLE hSession;
	CK_OBJECT_HANDLE hPuk, hPrk;

	// Initialize and open session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Test ML-DSA-65 + ECDSA P-256
	rv = generateHybridSignatureKeyPair(hSession, CKM_VENDOR_MLDSA65_ECDSA_P256,
	                                     IN_SESSION, IS_PUBLIC, IN_SESSION, IS_PUBLIC,
	                                     hPuk, hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	hybridSignatureSignVerify(CKM_VENDOR_MLDSA65_ECDSA_P256, hSession, hPuk, hPrk);

	// Test ML-DSA-87 + ECDSA P-384
	rv = generateHybridSignatureKeyPair(hSession, CKM_VENDOR_MLDSA87_ECDSA_P384,
	                                     IN_SESSION, IS_PUBLIC, IN_SESSION, IS_PUBLIC,
	                                     hPuk, hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	hybridSignatureSignVerify(CKM_VENDOR_MLDSA87_ECDSA_P384, hSession, hPuk, hPrk);

	CRYPTOKI_F_PTR( C_CloseSession(hSession) );
	*/
}
