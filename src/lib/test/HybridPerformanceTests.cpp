/*
 * Copyright (c) 2024 SoftHSM Project
 * All rights reserved.
 */

/*****************************************************************************
 HybridPerformanceTests.cpp

 Performance benchmarks for hybrid cryptography
 *****************************************************************************/

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include <cmath>
#include <algorithm>
#include <iomanip>
#include <iostream>
#include "HybridPerformanceTests.h"
#include "../pkcs11/vendor_defines.h"

CPPUNIT_TEST_SUITE_REGISTRATION(HybridPerformanceTests);

// Number of iterations for benchmarking
#define BENCHMARK_ITERATIONS 100

double HybridPerformanceTests::getTimeInMicroseconds(
	std::chrono::high_resolution_clock::time_point start,
	std::chrono::high_resolution_clock::time_point end)
{
	return std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
}

HybridPerformanceTests::Statistics HybridPerformanceTests::calculateStats(
	const std::vector<double>& data)
{
	Statistics stats;

	if (data.empty()) {
		stats.mean = stats.min = stats.max = stats.stddev = stats.median = 0.0;
		return stats;
	}

	// Calculate mean
	double sum = 0.0;
	for (double val : data) {
		sum += val;
	}
	stats.mean = sum / data.size();

	// Calculate min and max
	stats.min = *std::min_element(data.begin(), data.end());
	stats.max = *std::max_element(data.begin(), data.end());

	// Calculate standard deviation
	double variance = 0.0;
	for (double val : data) {
		variance += (val - stats.mean) * (val - stats.mean);
	}
	stats.stddev = std::sqrt(variance / data.size());

	// Calculate median
	std::vector<double> sorted_data = data;
	std::sort(sorted_data.begin(), sorted_data.end());
	size_t mid = sorted_data.size() / 2;
	if (sorted_data.size() % 2 == 0) {
		stats.median = (sorted_data[mid - 1] + sorted_data[mid]) / 2.0;
	} else {
		stats.median = sorted_data[mid];
	}

	return stats;
}

CK_RV HybridPerformanceTests::benchmarkVariant(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_TYPE mechanism,
	const char* name,
	int iterations,
	PerformanceMetrics& metrics)
{
	metrics.variant_name = name;
	metrics.mechanism = mechanism;

	CK_RV rv;
	CK_MECHANISM mech = { mechanism, NULL_PTR, 0 };
	CK_BBOOL bTrue = CK_TRUE;
	CK_BBOOL bFalse = CK_FALSE;
	CK_KEY_TYPE keyType = CKK_VENDOR_HYBRID_KEM;
	CK_OBJECT_CLASS publicKeyClass = CKO_PUBLIC_KEY;
	CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY;

	// Template for key generation
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

	// Template for shared secret
	CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
	CK_KEY_TYPE secretType = CKK_GENERIC_SECRET;
	CK_ATTRIBUTE secretTemplate[] = {
		{ CKA_CLASS, &secretClass, sizeof(secretClass) },
		{ CKA_KEY_TYPE, &secretType, sizeof(secretType) },
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
		{ CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }
	};

	std::cout << "\n=== Benchmarking " << name << " ===" << std::endl;
	std::cout << "Running " << iterations << " iterations..." << std::endl;

	for (int i = 0; i < iterations; i++) {
		if (i % 10 == 0) {
			std::cout << "." << std::flush;
		}

		CK_OBJECT_HANDLE hPuk = CK_INVALID_HANDLE;
		CK_OBJECT_HANDLE hPrk = CK_INVALID_HANDLE;

		// Benchmark key generation
		auto start = std::chrono::high_resolution_clock::now();
		rv = CRYPTOKI_F_PTR( C_GenerateKeyPair(hSession, &mech,
		                                       pukAttribs, sizeof(pukAttribs)/sizeof(CK_ATTRIBUTE),
		                                       prkAttribs, sizeof(prkAttribs)/sizeof(CK_ATTRIBUTE),
		                                       &hPuk, &hPrk) );
		auto end = std::chrono::high_resolution_clock::now();

		if (rv != CKR_OK) {
			std::cerr << "\nKey generation failed with rv=" << std::hex << rv << std::endl;
			return rv;
		}

		double keygen_time = getTimeInMicroseconds(start, end);
		metrics.keygen_times.push_back(keygen_time);

		// Get key sizes (only once)
		if (i == 0) {
			// Get public key size
			CK_ATTRIBUTE sizeAttr = { CKA_VALUE, NULL_PTR, 0 };
			rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hPuk, &sizeAttr, 1) );
			if (rv == CKR_OK) {
				metrics.public_key_size = sizeAttr.ulValueLen;
			}

			// Get private key size
			sizeAttr.type = CKA_VALUE;
			sizeAttr.pValue = NULL_PTR;
			sizeAttr.ulValueLen = 0;
			rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hPrk, &sizeAttr, 1) );
			if (rv == CKR_OK || rv == CKR_ATTRIBUTE_SENSITIVE) {
				// Private key value might be sensitive, estimate size
				metrics.private_key_size = sizeAttr.ulValueLen;
			}
		}

		// Benchmark encapsulation
		CK_BYTE ciphertext[2048];
		CK_ULONG ciphertextLen = sizeof(ciphertext);
		CK_OBJECT_HANDLE hSharedSecret1 = CK_INVALID_HANDLE;

		start = std::chrono::high_resolution_clock::now();
		rv = CRYPTOKI_F_PTR( C_EncapsulateKey(hSession, &mech, hPuk,
		                                      secretTemplate, sizeof(secretTemplate)/sizeof(CK_ATTRIBUTE),
		                                      ciphertext, &ciphertextLen,
		                                      &hSharedSecret1) );
		end = std::chrono::high_resolution_clock::now();

		if (rv != CKR_OK) {
			std::cerr << "\nEncapsulation failed with rv=" << std::hex << rv << std::endl;
			return rv;
		}

		double encap_time = getTimeInMicroseconds(start, end);
		metrics.encapsulate_times.push_back(encap_time);

		// Store ciphertext size (only once)
		if (i == 0) {
			metrics.ciphertext_size = ciphertextLen;
		}

		// Benchmark decapsulation
		CK_OBJECT_HANDLE hSharedSecret2 = CK_INVALID_HANDLE;

		start = std::chrono::high_resolution_clock::now();
		rv = CRYPTOKI_F_PTR( C_DecapsulateKey(hSession, &mech, hPrk,
		                                      secretTemplate, sizeof(secretTemplate)/sizeof(CK_ATTRIBUTE),
		                                      ciphertext, ciphertextLen,
		                                      &hSharedSecret2) );
		end = std::chrono::high_resolution_clock::now();

		if (rv != CKR_OK) {
			std::cerr << "\nDecapsulation failed with rv=" << std::hex << rv << std::endl;
			return rv;
		}

		double decap_time = getTimeInMicroseconds(start, end);
		metrics.decapsulate_times.push_back(decap_time);

		// Calculate round-trip time (encapsulation + decapsulation)
		metrics.roundtrip_times.push_back(encap_time + decap_time);

		// Get shared secret size (only once)
		if (i == 0) {
			CK_ATTRIBUTE secretSizeAttr = { CKA_VALUE_LEN, NULL_PTR, 0 };
			rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hSharedSecret1, &secretSizeAttr, 1) );
			if (rv == CKR_OK && secretSizeAttr.ulValueLen == sizeof(CK_ULONG)) {
				CK_ULONG secretLen = 0;
				secretSizeAttr.pValue = &secretLen;
				rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hSharedSecret1, &secretSizeAttr, 1) );
				if (rv == CKR_OK) {
					metrics.shared_secret_size = secretLen;
				}
			}
			// Default to 32 bytes if we can't get it
			if (metrics.shared_secret_size == 0) {
				metrics.shared_secret_size = 32;
			}
		}

		// Verify shared secrets match
		CK_BYTE secret1[256], secret2[256];
		CK_ATTRIBUTE attr1 = { CKA_VALUE, secret1, sizeof(secret1) };
		CK_ATTRIBUTE attr2 = { CKA_VALUE, secret2, sizeof(secret2) };

		rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hSharedSecret1, &attr1, 1) );
		if (rv != CKR_OK) {
			std::cerr << "\nFailed to get shared secret 1" << std::endl;
			return rv;
		}

		rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hSharedSecret2, &attr2, 1) );
		if (rv != CKR_OK) {
			std::cerr << "\nFailed to get shared secret 2" << std::endl;
			return rv;
		}

		if (attr1.ulValueLen != attr2.ulValueLen ||
		    memcmp(secret1, secret2, attr1.ulValueLen) != 0) {
			std::cerr << "\nShared secrets don't match!" << std::endl;
			return CKR_GENERAL_ERROR;
		}

		// Cleanup
		CRYPTOKI_F_PTR( C_DestroyObject(hSession, hSharedSecret1) );
		CRYPTOKI_F_PTR( C_DestroyObject(hSession, hSharedSecret2) );
		CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPuk) );
		CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPrk) );
	}

	std::cout << " Done!" << std::endl;
	return CKR_OK;
}

void HybridPerformanceTests::printMetrics(const PerformanceMetrics& metrics)
{
	Statistics keygen_stats = calculateStats(metrics.keygen_times);
	Statistics encap_stats = calculateStats(metrics.encapsulate_times);
	Statistics decap_stats = calculateStats(metrics.decapsulate_times);
	Statistics roundtrip_stats = calculateStats(metrics.roundtrip_times);

	std::cout << "\n" << std::string(80, '=') << std::endl;
	std::cout << "Performance Results: " << metrics.variant_name << std::endl;
	std::cout << std::string(80, '=') << std::endl;

	// Key sizes
	std::cout << "\nKey/Data Sizes:" << std::endl;
	std::cout << "  Public Key Size:    " << std::setw(6) << metrics.public_key_size << " bytes" << std::endl;
	std::cout << "  Private Key Size:   " << std::setw(6) << metrics.private_key_size << " bytes" << std::endl;
	std::cout << "  Ciphertext Size:    " << std::setw(6) << metrics.ciphertext_size << " bytes" << std::endl;
	std::cout << "  Shared Secret Size: " << std::setw(6) << metrics.shared_secret_size << " bytes" << std::endl;

	// Timing results
	std::cout << "\nTiming Results (microseconds):" << std::endl;
	std::cout << std::fixed << std::setprecision(2);

	std::cout << "\nKey Generation:" << std::endl;
	std::cout << "  Mean:   " << std::setw(10) << keygen_stats.mean << " μs" << std::endl;
	std::cout << "  Median: " << std::setw(10) << keygen_stats.median << " μs" << std::endl;
	std::cout << "  Min:    " << std::setw(10) << keygen_stats.min << " μs" << std::endl;
	std::cout << "  Max:    " << std::setw(10) << keygen_stats.max << " μs" << std::endl;
	std::cout << "  StdDev: " << std::setw(10) << keygen_stats.stddev << " μs" << std::endl;

	std::cout << "\nEncapsulation:" << std::endl;
	std::cout << "  Mean:   " << std::setw(10) << encap_stats.mean << " μs" << std::endl;
	std::cout << "  Median: " << std::setw(10) << encap_stats.median << " μs" << std::endl;
	std::cout << "  Min:    " << std::setw(10) << encap_stats.min << " μs" << std::endl;
	std::cout << "  Max:    " << std::setw(10) << encap_stats.max << " μs" << std::endl;
	std::cout << "  StdDev: " << std::setw(10) << encap_stats.stddev << " μs" << std::endl;

	std::cout << "\nDecapsulation:" << std::endl;
	std::cout << "  Mean:   " << std::setw(10) << decap_stats.mean << " μs" << std::endl;
	std::cout << "  Median: " << std::setw(10) << decap_stats.median << " μs" << std::endl;
	std::cout << "  Min:    " << std::setw(10) << decap_stats.min << " μs" << std::endl;
	std::cout << "  Max:    " << std::setw(10) << decap_stats.max << " μs" << std::endl;
	std::cout << "  StdDev: " << std::setw(10) << decap_stats.stddev << " μs" << std::endl;

	std::cout << "\nRound-trip (Encap + Decap):" << std::endl;
	std::cout << "  Mean:   " << std::setw(10) << roundtrip_stats.mean << " μs" << std::endl;
	std::cout << "  Median: " << std::setw(10) << roundtrip_stats.median << " μs" << std::endl;
	std::cout << "  Min:    " << std::setw(10) << roundtrip_stats.min << " μs" << std::endl;
	std::cout << "  Max:    " << std::setw(10) << roundtrip_stats.max << " μs" << std::endl;
	std::cout << "  StdDev: " << std::setw(10) << roundtrip_stats.stddev << " μs" << std::endl;

	// Throughput calculations
	std::cout << "\nThroughput:" << std::endl;
	std::cout << "  Key Generation:  " << std::setw(8)
	          << (1000000.0 / keygen_stats.mean) << " ops/sec" << std::endl;
	std::cout << "  Encapsulation:   " << std::setw(8)
	          << (1000000.0 / encap_stats.mean) << " ops/sec" << std::endl;
	std::cout << "  Decapsulation:   " << std::setw(8)
	          << (1000000.0 / decap_stats.mean) << " ops/sec" << std::endl;
	std::cout << "  Round-trip:      " << std::setw(8)
	          << (1000000.0 / roundtrip_stats.mean) << " ops/sec" << std::endl;
}

void HybridPerformanceTests::printComparison(
	const std::vector<PerformanceMetrics>& all_metrics)
{
	std::cout << "\n" << std::string(120, '=') << std::endl;
	std::cout << "COMPARATIVE ANALYSIS" << std::endl;
	std::cout << std::string(120, '=') << std::endl;

	// Header
	std::cout << "\n" << std::left << std::setw(25) << "Variant"
	          << std::right
	          << std::setw(15) << "KeyGen (μs)"
	          << std::setw(15) << "Encap (μs)"
	          << std::setw(15) << "Decap (μs)"
	          << std::setw(15) << "Round-trip (μs)"
	          << std::setw(18) << "Ciphertext (B)"
	          << std::endl;
	std::cout << std::string(120, '-') << std::endl;

	// Data rows
	std::cout << std::fixed << std::setprecision(2);
	for (const auto& m : all_metrics) {
		Statistics keygen = calculateStats(m.keygen_times);
		Statistics encap = calculateStats(m.encapsulate_times);
		Statistics decap = calculateStats(m.decapsulate_times);
		Statistics roundtrip = calculateStats(m.roundtrip_times);

		std::cout << std::left << std::setw(25) << m.variant_name
		          << std::right
		          << std::setw(15) << keygen.mean
		          << std::setw(15) << encap.mean
		          << std::setw(15) << decap.mean
		          << std::setw(15) << roundtrip.mean
		          << std::setw(18) << m.ciphertext_size
		          << std::endl;
	}

	// Find fastest variant for each operation
	std::cout << "\n" << std::string(120, '=') << std::endl;
	std::cout << "PERFORMANCE RANKING" << std::endl;
	std::cout << std::string(120, '=') << std::endl;

	if (!all_metrics.empty()) {
		size_t fastest_keygen = 0, fastest_encap = 0, fastest_decap = 0, fastest_roundtrip = 0;
		size_t smallest_ct = 0;

		for (size_t i = 1; i < all_metrics.size(); i++) {
			if (calculateStats(all_metrics[i].keygen_times).mean <
			    calculateStats(all_metrics[fastest_keygen].keygen_times).mean) {
				fastest_keygen = i;
			}
			if (calculateStats(all_metrics[i].encapsulate_times).mean <
			    calculateStats(all_metrics[fastest_encap].encapsulate_times).mean) {
				fastest_encap = i;
			}
			if (calculateStats(all_metrics[i].decapsulate_times).mean <
			    calculateStats(all_metrics[fastest_decap].decapsulate_times).mean) {
				fastest_decap = i;
			}
			if (calculateStats(all_metrics[i].roundtrip_times).mean <
			    calculateStats(all_metrics[fastest_roundtrip].roundtrip_times).mean) {
				fastest_roundtrip = i;
			}
			if (all_metrics[i].ciphertext_size < all_metrics[smallest_ct].ciphertext_size) {
				smallest_ct = i;
			}
		}

		std::cout << "\nFastest Key Generation:  " << all_metrics[fastest_keygen].variant_name << std::endl;
		std::cout << "Fastest Encapsulation:   " << all_metrics[fastest_encap].variant_name << std::endl;
		std::cout << "Fastest Decapsulation:   " << all_metrics[fastest_decap].variant_name << std::endl;
		std::cout << "Fastest Round-trip:      " << all_metrics[fastest_roundtrip].variant_name << std::endl;
		std::cout << "Smallest Ciphertext:     " << all_metrics[smallest_ct].variant_name
		          << " (" << all_metrics[smallest_ct].ciphertext_size << " bytes)" << std::endl;
	}

	std::cout << std::string(120, '=') << std::endl;
}

void HybridPerformanceTests::testPerformanceComparison()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;

	// Open session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID,
	                                   CKF_SERIAL_SESSION | CKF_RW_SESSION,
	                                   NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	std::vector<PerformanceMetrics> all_metrics;

	// Benchmark ML-KEM768 + ECDH P-256
	PerformanceMetrics p256_metrics;
	rv = benchmarkVariant(hSession, CKM_VENDOR_MLKEM768_ECDH_P256,
	                      "ML-KEM-768 + ECDH P-256",
	                      BENCHMARK_ITERATIONS, p256_metrics);
	CPPUNIT_ASSERT(rv == CKR_OK);
	all_metrics.push_back(p256_metrics);
	printMetrics(p256_metrics);

	// Benchmark ML-KEM1024 + ECDH P-384
	PerformanceMetrics p384_metrics;
	rv = benchmarkVariant(hSession, CKM_VENDOR_MLKEM1024_ECDH_P384,
	                      "ML-KEM-1024 + ECDH P-384",
	                      BENCHMARK_ITERATIONS, p384_metrics);
	CPPUNIT_ASSERT(rv == CKR_OK);
	all_metrics.push_back(p384_metrics);
	printMetrics(p384_metrics);

	// Benchmark ML-KEM768 + X25519
	PerformanceMetrics x25519_metrics;
	rv = benchmarkVariant(hSession, CKM_VENDOR_MLKEM768_X25519,
	                      "ML-KEM-768 + X25519",
	                      BENCHMARK_ITERATIONS, x25519_metrics);
	CPPUNIT_ASSERT(rv == CKR_OK);
	all_metrics.push_back(x25519_metrics);
	printMetrics(x25519_metrics);

	// Print comparative analysis
	printComparison(all_metrics);

	// Close session
	CRYPTOKI_F_PTR( C_CloseSession(hSession) );

	std::cout << "\n✅ Performance testing completed successfully!" << std::endl;
}
