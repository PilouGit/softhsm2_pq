/*
 * Copyright (c) 2024 SoftHSM Project
 * All rights reserved.
 */

#ifndef _SOFTHSM_V2_HYBRIDCOMBINER_H
#define _SOFTHSM_V2_HYBRIDCOMBINER_H

#include "config.h"
#include "ByteString.h"
#include "../pkcs11/vendor_defines.h"

#ifdef WITH_PQC

/**
 * HybridCombiner - KDF for combining PQC and classical shared secrets
 *
 * Implements the combiner function from:
 * draft-ounsworth-cfrg-kem-combiners
 *
 * The combiner must be collision-resistant and second pre-image resistant
 * with respect to each of its inputs independently (dual-PRF property).
 */
class HybridCombiner
{
public:
	/**
	 * Combine two shared secrets using SHA-256 based KDF
	 *
	 * Based on IETF specification:
	 * KDF(ss1, ss2, label) = SHA-256(counter || ss1 || ss2 || label)
	 *
	 * @param ss1 First shared secret (PQC)
	 * @param ss2 Second shared secret (classical)
	 * @param label Context label (mechanism identifier)
	 * @param outputLen Desired output length in bytes
	 * @return Combined shared secret
	 */
	static ByteString combineSHA256(
		const ByteString& ss1,
		const ByteString& ss2,
		const ByteString& label,
		size_t outputLen = 32
	);

	/**
	 * Combine two shared secrets using SHA-512 based KDF
	 *
	 * @param ss1 First shared secret (PQC)
	 * @param ss2 Second shared secret (classical)
	 * @param label Context label (mechanism identifier)
	 * @param outputLen Desired output length in bytes
	 * @return Combined shared secret
	 */
	static ByteString combineSHA512(
		const ByteString& ss1,
		const ByteString& ss2,
		const ByteString& label,
		size_t outputLen = 64
	);

	/**
	 * Simple concatenation combiner
	 *
	 * Combined = ss1 || ss2
	 *
	 * Note: This is simpler but provides less security properties
	 * than hash-based combiners.
	 *
	 * @param ss1 First shared secret (PQC)
	 * @param ss2 Second shared secret (classical)
	 * @return Concatenated shared secrets
	 */
	static ByteString combineConcat(
		const ByteString& ss1,
		const ByteString& ss2
	);

	/**
	 * Generic combiner that dispatches to appropriate function
	 *
	 * @param ss1 First shared secret (PQC)
	 * @param ss2 Second shared secret (classical)
	 * @param label Context label
	 * @param combinerType Type of combiner to use
	 * @param outputLen Desired output length
	 * @return Combined shared secret
	 */
	static ByteString combine(
		const ByteString& ss1,
		const ByteString& ss2,
		const ByteString& label,
		HybridCombinerType combinerType = HYBRID_COMBINER_SHA256,
		size_t outputLen = 32
	);

private:
	/**
	 * Helper: Convert uint32_t to big-endian byte string
	 */
	static ByteString uint32ToBigEndian(uint32_t value);
};

#endif /* WITH_PQC */

#endif /* !_SOFTHSM_V2_HYBRIDCOMBINER_H */
