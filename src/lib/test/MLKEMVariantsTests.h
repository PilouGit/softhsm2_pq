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
 MLKEMVariantsTests.h

 Contains test cases for ML-KEM variant-specific mechanisms:
 - CKM_MLKEM_512, CKM_MLKEM_768, CKM_MLKEM_1024
 - C_EncapsulateKey/C_DecapsulateKey with variant mechanisms
 - Verification that variant mechanisms properly match key parameter sets
 *****************************************************************************/

#ifndef _SOFTHSM_V2_MLKEMVARIANTSTESTS_H
#define _SOFTHSM_V2_MLKEMVARIANTSTESTS_H

#include "TestsBase.h"
#include <cppunit/extensions/HelperMacros.h>

class MLKEMVariantsTests : public TestsBase
{
	CPPUNIT_TEST_SUITE(MLKEMVariantsTests);
	CPPUNIT_TEST(testMLKEM512KeyGen);
	CPPUNIT_TEST(testMLKEM768KeyGen);
	CPPUNIT_TEST(testMLKEM1024KeyGen);
	CPPUNIT_TEST(testMLKEM512EncapDecap);
	CPPUNIT_TEST(testMLKEM768EncapDecap);
	CPPUNIT_TEST(testMLKEM1024EncapDecap);
	CPPUNIT_TEST(testMLKEMGenericMechanism);
	CPPUNIT_TEST(testMLKEMCiphertextSizes);
	CPPUNIT_TEST(testMLKEMWrongMechanismFails);
	CPPUNIT_TEST_SUITE_END();

public:
	void testMLKEM512KeyGen();
	void testMLKEM768KeyGen();
	void testMLKEM1024KeyGen();
	void testMLKEM512EncapDecap();
	void testMLKEM768EncapDecap();
	void testMLKEM1024EncapDecap();
	void testMLKEMGenericMechanism();
	void testMLKEMCiphertextSizes();
	void testMLKEMWrongMechanismFails();

protected:
	CK_RV generateMLKEMKeyPair(CK_SESSION_HANDLE hSession,
	                           CK_ULONG parameterSet,
	                           CK_BBOOL bTokenPuk,
	                           CK_BBOOL bPrivatePuk,
	                           CK_BBOOL bTokenPrk,
	                           CK_BBOOL bPrivatePrk,
	                           CK_OBJECT_HANDLE &hPuk,
	                           CK_OBJECT_HANDLE &hPrk);

	void mlkemEncapDecap(CK_MECHANISM_TYPE mechanism,
	                     CK_SESSION_HANDLE hSession,
	                     CK_OBJECT_HANDLE hPublicKey,
	                     CK_OBJECT_HANDLE hPrivateKey,
	                     CK_ULONG expectedCiphertextLen);
};

#endif // !_SOFTHSM_V2_MLKEMVARIANTSTESTS_H
