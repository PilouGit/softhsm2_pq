/*
 * Copyright (c) 2024 SoftHSM Project
 * All rights reserved.
 */

/*****************************************************************************
 HybridPerformanceTests.h

 Performance benchmarks for hybrid cryptography
 *****************************************************************************/

#ifndef _SOFTHSM_V2_HYBRIDPERFORMANCETESTS_H
#define _SOFTHSM_V2_HYBRIDPERFORMANCETESTS_H

#include "TestsNoPINInitBase.h"
#include <cppunit/extensions/HelperMacros.h>
#include <chrono>
#include <vector>

class HybridPerformanceTests : public TestsNoPINInitBase
{
	CPPUNIT_TEST_SUITE(HybridPerformanceTests);
	CPPUNIT_TEST(testPerformanceComparison);
	CPPUNIT_TEST_SUITE_END();

public:
	void testPerformanceComparison();

protected:
	// Performance measurement structures
	struct PerformanceMetrics {
		std::string variant_name;
		CK_MECHANISM_TYPE mechanism;

		// Times in microseconds
		std::vector<double> keygen_times;
		std::vector<double> encapsulate_times;
		std::vector<double> decapsulate_times;
		std::vector<double> roundtrip_times;

		// Key sizes in bytes
		size_t public_key_size;
		size_t private_key_size;
		size_t ciphertext_size;
		size_t shared_secret_size;
	};

	struct Statistics {
		double mean;
		double min;
		double max;
		double stddev;
		double median;
	};

	// Helper functions
	Statistics calculateStats(const std::vector<double>& data);
	void printMetrics(const PerformanceMetrics& metrics);
	void printComparison(const std::vector<PerformanceMetrics>& all_metrics);

	CK_RV benchmarkVariant(CK_SESSION_HANDLE hSession,
	                       CK_MECHANISM_TYPE mechanism,
	                       const char* name,
	                       int iterations,
	                       PerformanceMetrics& metrics);

	double getTimeInMicroseconds(
		std::chrono::high_resolution_clock::time_point start,
		std::chrono::high_resolution_clock::time_point end);
};

#endif // !_SOFTHSM_V2_HYBRIDPERFORMANCETESTS_H
