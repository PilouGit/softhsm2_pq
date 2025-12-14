/*
 * Copyright (c) 2024 SoftHSM Project
 * All rights reserved.
 */

#ifndef _SOFTHSM_V2_HYBRIDKEMTESTS_H
#define _SOFTHSM_V2_HYBRIDKEMTESTS_H

#include <cppunit/extensions/HelperMacros.h>

class HybridKEMTests : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(HybridKEMTests);
	CPPUNIT_TEST(testKeyGeneration);
	CPPUNIT_TEST(testSerialisation);
	CPPUNIT_TEST(testEncapsulateDecapsulate);
	CPPUNIT_TEST_SUITE_END();

public:
	void testKeyGeneration();
	void testSerialisation();
	void testEncapsulateDecapsulate();

	void setUp();
	void tearDown();
};

#endif // !_SOFTHSM_V2_HYBRIDKEMTESTS_H
