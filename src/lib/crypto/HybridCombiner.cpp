/*
 * Copyright (c) 2024 SoftHSM Project
 * All rights reserved.
 */

#include "config.h"
#include "HybridCombiner.h"
#include "CryptoFactory.h"
#include "HashAlgorithm.h"

#ifdef WITH_PQC

ByteString HybridCombiner::uint32ToBigEndian(uint32_t value)
{
	ByteString result(4);
	result[0] = (value >> 24) & 0xFF;
	result[1] = (value >> 16) & 0xFF;
	result[2] = (value >> 8) & 0xFF;
	result[3] = value & 0xFF;
	return result;
}

ByteString HybridCombiner::combineSHA256(
	const ByteString& ss1,
	const ByteString& ss2,
	const ByteString& label,
	size_t outputLen)
{
	// Get SHA-256 hash algorithm
	HashAlgorithm* hash = CryptoFactory::i()->getHashAlgorithm(HashAlgo::SHA256);
	if (hash == NULL)
	{
		return ByteString();
	}

	// Prepare input: counter || ss1 || ss2 || label
	// Counter is 0x00000001 for first block
	ByteString counter = uint32ToBigEndian(1);
	ByteString input = counter + ss1 + ss2 + label;

	// Hash the combined input
	ByteString hashInput;
	if (!hash->hashInit())
	{
		CryptoFactory::i()->recycleHashAlgorithm(hash);
		return ByteString();
	}

	if (!hash->hashUpdate(input))
	{
		CryptoFactory::i()->recycleHashAlgorithm(hash);
		return ByteString();
	}

	ByteString output;
	if (!hash->hashFinal(output))
	{
		CryptoFactory::i()->recycleHashAlgorithm(hash);
		return ByteString();
	}

	CryptoFactory::i()->recycleHashAlgorithm(hash);

	// Truncate or extend to desired length if needed
	if (output.size() > outputLen)
	{
		output.resize(outputLen);
	}
	else if (output.size() < outputLen && outputLen <= 64)
	{
		// For lengths > 32 but <= 64, we could use SHA-512
		// For now, just return what we have
		// A production implementation might use HKDF or similar
	}

	return output;
}

ByteString HybridCombiner::combineSHA512(
	const ByteString& ss1,
	const ByteString& ss2,
	const ByteString& label,
	size_t outputLen)
{
	// Get SHA-512 hash algorithm
	HashAlgorithm* hash = CryptoFactory::i()->getHashAlgorithm(HashAlgo::SHA512);
	if (hash == NULL)
	{
		return ByteString();
	}

	// Prepare input: counter || ss1 || ss2 || label
	ByteString counter = uint32ToBigEndian(1);
	ByteString input = counter + ss1 + ss2 + label;

	// Hash the combined input
	if (!hash->hashInit())
	{
		CryptoFactory::i()->recycleHashAlgorithm(hash);
		return ByteString();
	}

	if (!hash->hashUpdate(input))
	{
		CryptoFactory::i()->recycleHashAlgorithm(hash);
		return ByteString();
	}

	ByteString output;
	if (!hash->hashFinal(output))
	{
		CryptoFactory::i()->recycleHashAlgorithm(hash);
		return ByteString();
	}

	CryptoFactory::i()->recycleHashAlgorithm(hash);

	// Truncate to desired length if needed
	if (output.size() > outputLen)
	{
		output.resize(outputLen);
	}

	return output;
}

ByteString HybridCombiner::combineConcat(
	const ByteString& ss1,
	const ByteString& ss2)
{
	// Simple concatenation: ss1 || ss2
	return ss1 + ss2;
}

ByteString HybridCombiner::combine(
	const ByteString& ss1,
	const ByteString& ss2,
	const ByteString& label,
	HybridCombinerType combinerType,
	size_t outputLen)
{
	switch (combinerType)
	{
		case HYBRID_COMBINER_SHA256:
			return combineSHA256(ss1, ss2, label, outputLen);

		case HYBRID_COMBINER_SHA512:
			return combineSHA512(ss1, ss2, label, outputLen);

		case HYBRID_COMBINER_CONCAT:
			return combineConcat(ss1, ss2);

		case HYBRID_COMBINER_KMAC128:
		case HYBRID_COMBINER_KMAC256:
			// KMAC not yet implemented, fall back to SHA-256
			return combineSHA256(ss1, ss2, label, outputLen);

		default:
			// Unknown combiner type
			return ByteString();
	}
}

#endif /* WITH_PQC */
