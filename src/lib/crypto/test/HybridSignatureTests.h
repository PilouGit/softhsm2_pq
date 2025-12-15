/*
 * Copyright (c) 2024 SoftHSM Project
 * All rights reserved.
 */

#ifndef _SOFTHSM_V2_HYBRIDSIGNATURETESTS_H
#define _SOFTHSM_V2_HYBRIDSIGNATURETESTS_H

#include <cppunit/extensions/HelperMacros.h>

class HybridSignatureTests : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(HybridSignatureTests);
	CPPUNIT_TEST(testKeyGeneration);
	CPPUNIT_TEST(testSerialisation);
	CPPUNIT_TEST(testSigningVerifying);
	CPPUNIT_TEST_SUITE_END();

public:
	void testKeyGeneration();
	void testSerialisation();
	void testSigningVerifying();

	void setUp();
	void tearDown();
};

#endif // !_SOFTHSM_V2_HYBRIDSIGNATURETESTS_H
