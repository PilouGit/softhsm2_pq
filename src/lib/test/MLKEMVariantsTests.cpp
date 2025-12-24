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
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*****************************************************************************
 MLKEMVariantsTests.cpp

 Contains test cases for ML-KEM variant-specific mechanisms
 *****************************************************************************/

#include <config.h>
#include "MLKEMVariantsTests.h"
#include "cryptoki.h"
#include <cstring>

#ifdef WITH_PQC

CPPUNIT_TEST_SUITE_REGISTRATION(MLKEMVariantsTests);

// Helper function to generate ML-KEM key pairs
CK_RV MLKEMVariantsTests::generateMLKEMKeyPair(CK_SESSION_HANDLE hSession,
                                                CK_ULONG parameterSet,
                                                CK_BBOOL bTokenPuk,
                                                CK_BBOOL bPrivatePuk,
                                                CK_BBOOL bTokenPrk,
                                                CK_BBOOL bPrivatePrk,
                                                CK_OBJECT_HANDLE &hPuk,
                                                CK_OBJECT_HANDLE &hPrk)
{
	CK_MECHANISM mech = { CKM_ML_KEM_KEY_PAIR_GEN, NULL_PTR, 0 };
	CK_BBOOL bTrue = CK_TRUE;
	CK_BBOOL bFalse = CK_FALSE;
	CK_KEY_TYPE keyType = CKK_ML_KEM;
	CK_OBJECT_CLASS publicKeyClass = CKO_PUBLIC_KEY;
	CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY;
	CK_BYTE subject[] = { 0x12, 0x34 }; // Dummy subject

	CK_ATTRIBUTE pukAttribs[] = {
		{ CKA_CLASS, &publicKeyClass, sizeof(publicKeyClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_TOKEN, &bTokenPuk, sizeof(bTokenPuk) },
		{ CKA_PRIVATE, &bPrivatePuk, sizeof(bPrivatePuk) },
		{ CKA_SUBJECT, &subject, sizeof(subject) },
		{ CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_VERIFY, &bFalse, sizeof(bFalse) },
		{ CKA_WRAP, &bFalse, sizeof(bFalse) },
		{ CKA_VALUE_LEN, &parameterSet, sizeof(parameterSet) }
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
		{ CKA_EXTRACTABLE, &bFalse, sizeof(bFalse) },
		{ CKA_VALUE_LEN, &parameterSet, sizeof(parameterSet) }
	};

	hPuk = CK_INVALID_HANDLE;
	hPrk = CK_INVALID_HANDLE;

	CK_RV rv = CRYPTOKI_F_PTR( C_GenerateKeyPair(hSession, &mech,
	                                               pukAttribs, sizeof(pukAttribs)/sizeof(CK_ATTRIBUTE),
	                                               prkAttribs, sizeof(prkAttribs)/sizeof(CK_ATTRIBUTE),
	                                               &hPuk, &hPrk) );
	if (rv != CKR_OK) {
		printf("C_GenerateKeyPair for ML-KEM (parameterSet=%lu) failed with rv=0x%08lX\n", parameterSet, rv);
	}
	return rv;
}

// Helper function to perform encapsulation and decapsulation
void MLKEMVariantsTests::mlkemEncapDecap(CK_MECHANISM_TYPE mechanism,
                                          CK_SESSION_HANDLE hSession,
                                          CK_OBJECT_HANDLE hPublicKey,
                                          CK_OBJECT_HANDLE hPrivateKey,
                                          CK_ULONG expectedCiphertextLen)
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
	CPPUNIT_ASSERT(ulCiphertextLen == expectedCiphertextLen);
	CPPUNIT_ASSERT(hSharedSecret1 != CK_INVALID_HANDLE);

	// Test decapsulation (PKCS#11 v3.2)
	rv = CRYPTOKI_F_PTR( C_DecapsulateKey(hSession, &mech, hPrivateKey,
	                                       secretTemplate, sizeof(secretTemplate)/sizeof(CK_ATTRIBUTE),
	                                       ciphertext, ulCiphertextLen,
	                                       &hSharedSecret2) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(hSharedSecret2 != CK_INVALID_HANDLE);

	// Extract and compare shared secrets
	CK_BYTE secret1[32];
	CK_BYTE secret2[32];
	CK_ATTRIBUTE valueAttrib1 = { CKA_VALUE, secret1, sizeof(secret1) };
	CK_ATTRIBUTE valueAttrib2 = { CKA_VALUE, secret2, sizeof(secret2) };

	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hSharedSecret1, &valueAttrib1, 1) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(valueAttrib1.ulValueLen == 32); // ML-KEM always produces 32-byte shared secret

	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hSharedSecret2, &valueAttrib2, 1) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(valueAttrib2.ulValueLen == 32);

	// Verify secrets match
	CPPUNIT_ASSERT(memcmp(secret1, secret2, 32) == 0);

	// Clean up
	CRYPTOKI_F_PTR( C_DestroyObject(hSession, hSharedSecret1) );
	CRYPTOKI_F_PTR( C_DestroyObject(hSession, hSharedSecret2) );
}

// Test ML-KEM-512 key generation
void MLKEMVariantsTests::testMLKEM512KeyGen()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;
	CK_OBJECT_HANDLE hPuk = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hPrk = CK_INVALID_HANDLE;

	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = generateMLKEMKeyPair(hSession, 512, CK_FALSE, CK_FALSE, CK_FALSE, CK_FALSE, hPuk, hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(hPuk != CK_INVALID_HANDLE);
	CPPUNIT_ASSERT(hPrk != CK_INVALID_HANDLE);

	// Verify key type and parameter set
	CK_KEY_TYPE keyType;
	CK_ULONG valueLen;
	CK_ATTRIBUTE attribs[] = {
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_VALUE_LEN, &valueLen, sizeof(valueLen) }
	};

	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hPuk, attribs, 2) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(keyType == CKK_ML_KEM);
	CPPUNIT_ASSERT(valueLen == 512);

	// Clean up
	CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPuk) );
	CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPrk) );
	CRYPTOKI_F_PTR( C_CloseSession(hSession) );
}

// Test ML-KEM-768 key generation
void MLKEMVariantsTests::testMLKEM768KeyGen()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;
	CK_OBJECT_HANDLE hPuk = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hPrk = CK_INVALID_HANDLE;

	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = generateMLKEMKeyPair(hSession, 768, CK_FALSE, CK_FALSE, CK_FALSE, CK_FALSE, hPuk, hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(hPuk != CK_INVALID_HANDLE);
	CPPUNIT_ASSERT(hPrk != CK_INVALID_HANDLE);

	// Verify key type and parameter set
	CK_KEY_TYPE keyType;
	CK_ULONG valueLen;
	CK_ATTRIBUTE attribs[] = {
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_VALUE_LEN, &valueLen, sizeof(valueLen) }
	};

	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hPuk, attribs, 2) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(keyType == CKK_ML_KEM);
	CPPUNIT_ASSERT(valueLen == 768);

	// Clean up
	CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPuk) );
	CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPrk) );
	CRYPTOKI_F_PTR( C_CloseSession(hSession) );
}

// Test ML-KEM-1024 key generation
void MLKEMVariantsTests::testMLKEM1024KeyGen()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;
	CK_OBJECT_HANDLE hPuk = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hPrk = CK_INVALID_HANDLE;

	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = generateMLKEMKeyPair(hSession, 1024, CK_FALSE, CK_FALSE, CK_FALSE, CK_FALSE, hPuk, hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(hPuk != CK_INVALID_HANDLE);
	CPPUNIT_ASSERT(hPrk != CK_INVALID_HANDLE);

	// Verify key type and parameter set
	CK_KEY_TYPE keyType;
	CK_ULONG valueLen;
	CK_ATTRIBUTE attribs[] = {
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_VALUE_LEN, &valueLen, sizeof(valueLen) }
	};

	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hPuk, attribs, 2) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(keyType == CKK_ML_KEM);
	CPPUNIT_ASSERT(valueLen == 1024);

	// Clean up
	CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPuk) );
	CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPrk) );
	CRYPTOKI_F_PTR( C_CloseSession(hSession) );
}

// Test ML-KEM-512 encapsulation and decapsulation with CKM_MLKEM_512
void MLKEMVariantsTests::testMLKEM512EncapDecap()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;
	CK_OBJECT_HANDLE hPuk = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hPrk = CK_INVALID_HANDLE;

	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = generateMLKEMKeyPair(hSession, 512, CK_FALSE, CK_FALSE, CK_FALSE, CK_FALSE, hPuk, hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Test with variant-specific mechanism CKM_MLKEM_512
	// ML-KEM-512 ciphertext size is 768 bytes
	mlkemEncapDecap(CKM_MLKEM_512, hSession, hPuk, hPrk, 768);

	// Clean up
	CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPuk) );
	CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPrk) );
	CRYPTOKI_F_PTR( C_CloseSession(hSession) );
}

// Test ML-KEM-768 encapsulation and decapsulation with CKM_MLKEM_768
void MLKEMVariantsTests::testMLKEM768EncapDecap()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;
	CK_OBJECT_HANDLE hPuk = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hPrk = CK_INVALID_HANDLE;

	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = generateMLKEMKeyPair(hSession, 768, CK_FALSE, CK_FALSE, CK_FALSE, CK_FALSE, hPuk, hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Test with variant-specific mechanism CKM_MLKEM_768
	// ML-KEM-768 ciphertext size is 1088 bytes
	mlkemEncapDecap(CKM_MLKEM_768, hSession, hPuk, hPrk, 1088);

	// Clean up
	CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPuk) );
	CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPrk) );
	CRYPTOKI_F_PTR( C_CloseSession(hSession) );
}

// Test ML-KEM-1024 encapsulation and decapsulation with CKM_MLKEM_1024
void MLKEMVariantsTests::testMLKEM1024EncapDecap()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;
	CK_OBJECT_HANDLE hPuk = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hPrk = CK_INVALID_HANDLE;

	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = generateMLKEMKeyPair(hSession, 1024, CK_FALSE, CK_FALSE, CK_FALSE, CK_FALSE, hPuk, hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Test with variant-specific mechanism CKM_MLKEM_1024
	// ML-KEM-1024 ciphertext size is 1568 bytes
	mlkemEncapDecap(CKM_MLKEM_1024, hSession, hPuk, hPrk, 1568);

	// Clean up
	CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPuk) );
	CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPrk) );
	CRYPTOKI_F_PTR( C_CloseSession(hSession) );
}

// Test that generic CKM_ML_KEM mechanism also works
void MLKEMVariantsTests::testMLKEMGenericMechanism()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;
	CK_OBJECT_HANDLE hPuk = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hPrk = CK_INVALID_HANDLE;

	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Generate ML-KEM-768 key pair (default)
	rv = generateMLKEMKeyPair(hSession, 768, CK_FALSE, CK_FALSE, CK_FALSE, CK_FALSE, hPuk, hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Test with generic mechanism CKM_ML_KEM
	// ML-KEM-768 ciphertext size is 1088 bytes
	mlkemEncapDecap(CKM_ML_KEM, hSession, hPuk, hPrk, 1088);

	// Clean up
	CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPuk) );
	CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPrk) );
	CRYPTOKI_F_PTR( C_CloseSession(hSession) );
}

// Test that all three variants produce correct ciphertext sizes
void MLKEMVariantsTests::testMLKEMCiphertextSizes()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;

	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Test ML-KEM-512: ciphertext should be 768 bytes
	{
		CK_OBJECT_HANDLE hPuk = CK_INVALID_HANDLE;
		CK_OBJECT_HANDLE hPrk = CK_INVALID_HANDLE;
		rv = generateMLKEMKeyPair(hSession, 512, CK_FALSE, CK_FALSE, CK_FALSE, CK_FALSE, hPuk, hPrk);
		CPPUNIT_ASSERT(rv == CKR_OK);
		mlkemEncapDecap(CKM_MLKEM_512, hSession, hPuk, hPrk, 768);
		CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPuk) );
		CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPrk) );
	}

	// Test ML-KEM-768: ciphertext should be 1088 bytes
	{
		CK_OBJECT_HANDLE hPuk = CK_INVALID_HANDLE;
		CK_OBJECT_HANDLE hPrk = CK_INVALID_HANDLE;
		rv = generateMLKEMKeyPair(hSession, 768, CK_FALSE, CK_FALSE, CK_FALSE, CK_FALSE, hPuk, hPrk);
		CPPUNIT_ASSERT(rv == CKR_OK);
		mlkemEncapDecap(CKM_MLKEM_768, hSession, hPuk, hPrk, 1088);
		CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPuk) );
		CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPrk) );
	}

	// Test ML-KEM-1024: ciphertext should be 1568 bytes
	{
		CK_OBJECT_HANDLE hPuk = CK_INVALID_HANDLE;
		CK_OBJECT_HANDLE hPrk = CK_INVALID_HANDLE;
		rv = generateMLKEMKeyPair(hSession, 1024, CK_FALSE, CK_FALSE, CK_FALSE, CK_FALSE, hPuk, hPrk);
		CPPUNIT_ASSERT(rv == CKR_OK);
		mlkemEncapDecap(CKM_MLKEM_1024, hSession, hPuk, hPrk, 1568);
		CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPuk) );
		CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPrk) );
	}

	CRYPTOKI_F_PTR( C_CloseSession(hSession) );
}

// Test that using wrong variant mechanism with a key fails
// For example, using CKM_MLKEM_768 with a ML-KEM-512 key should fail
void MLKEMVariantsTests::testMLKEMWrongMechanismFails()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;
	CK_OBJECT_HANDLE hPuk512 = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hPrk512 = CK_INVALID_HANDLE;

	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Generate ML-KEM-512 key pair
	rv = generateMLKEMKeyPair(hSession, 512, CK_FALSE, CK_FALSE, CK_FALSE, CK_FALSE, hPuk512, hPrk512);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Try to use CKM_MLKEM_768 with ML-KEM-512 key - should fail
	CK_MECHANISM mech = { CKM_MLKEM_768, NULL_PTR, 0 };
	CK_BYTE ciphertext[2048];
	CK_ULONG ulCiphertextLen = sizeof(ciphertext);
	CK_OBJECT_HANDLE hSharedSecret = CK_INVALID_HANDLE;

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

	// This should fail with CKR_KEY_SIZE_RANGE or similar error
	rv = CRYPTOKI_F_PTR( C_EncapsulateKey(hSession, &mech, hPuk512,
	                                       secretTemplate, sizeof(secretTemplate)/sizeof(CK_ATTRIBUTE),
	                                       ciphertext, &ulCiphertextLen,
	                                       &hSharedSecret) );

	// The exact error code may vary, but it should NOT succeed
	CPPUNIT_ASSERT(rv != CKR_OK);

	// Clean up
	CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPuk512) );
	CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPrk512) );
	CRYPTOKI_F_PTR( C_CloseSession(hSession) );
}

#endif // WITH_PQC
