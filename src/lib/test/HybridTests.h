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
 HybridTests.h

 Contains test cases for hybrid cryptography:
 - C_GenerateKeyPair for hybrid KEMs and signatures
 - C_Encapsulate/C_Decapsulate for hybrid KEMs
 - C_SignInit/C_Sign/C_VerifyInit/C_Verify for hybrid signatures
 *****************************************************************************/

#ifndef _SOFTHSM_V2_HYBRIDTESTS_H
#define _SOFTHSM_V2_HYBRIDTESTS_H

#include "TestsBase.h"
#include <cppunit/extensions/HelperMacros.h>

class HybridTests : public TestsBase
{
	CPPUNIT_TEST_SUITE(HybridTests);
	CPPUNIT_TEST(testHybridKEMKeyGen);
	CPPUNIT_TEST(testHybridKEMEncapDecap);
	CPPUNIT_TEST(testHybridKEMKeyAttributes);
	// TODO: Token and error tests need infrastructure fixes
	//CPPUNIT_TEST(testHybridKEMTokenKeys);
	//CPPUNIT_TEST(testHybridKEMErrorCases);
	CPPUNIT_TEST(testHybridSignatureKeyGen);
	CPPUNIT_TEST(testHybridSignatureSignVerify);
	CPPUNIT_TEST_SUITE_END();

public:
	void testHybridKEMKeyGen();
	void testHybridKEMEncapDecap();
	void testHybridKEMKeyAttributes();
	void testHybridKEMTokenKeys();
	void testHybridKEMErrorCases();
	void testHybridSignatureKeyGen();
	void testHybridSignatureSignVerify();

protected:
	CK_RV generateHybridKEMKeyPair(CK_SESSION_HANDLE hSession,
	                                CK_MECHANISM_TYPE mechanism,
	                                CK_BBOOL bTokenPuk,
	                                CK_BBOOL bPrivatePuk,
	                                CK_BBOOL bTokenPrk,
	                                CK_BBOOL bPrivatePrk,
	                                CK_OBJECT_HANDLE &hPuk,
	                                CK_OBJECT_HANDLE &hPrk);

	CK_RV generateHybridSignatureKeyPair(CK_SESSION_HANDLE hSession,
	                                      CK_MECHANISM_TYPE mechanism,
	                                      CK_BBOOL bTokenPuk,
	                                      CK_BBOOL bPrivatePuk,
	                                      CK_BBOOL bTokenPrk,
	                                      CK_BBOOL bPrivatePrk,
	                                      CK_OBJECT_HANDLE &hPuk,
	                                      CK_OBJECT_HANDLE &hPrk);

	void hybridKEMEncapDecap(CK_MECHANISM_TYPE mechanism,
	                         CK_SESSION_HANDLE hSession,
	                         CK_OBJECT_HANDLE hPublicKey,
	                         CK_OBJECT_HANDLE hPrivateKey);

	void hybridSignatureSignVerify(CK_MECHANISM_TYPE mechanism,
	                                CK_SESSION_HANDLE hSession,
	                                CK_OBJECT_HANDLE hPublicKey,
	                                CK_OBJECT_HANDLE hPrivateKey);
};

#endif // !_SOFTHSM_V2_HYBRIDTESTS_H
