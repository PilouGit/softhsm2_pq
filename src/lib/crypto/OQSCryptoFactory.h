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
 OQSCryptoFactory.h

 This is a liboqs (Open Quantum Safe) based cryptographic algorithm factory
 for post-quantum cryptography algorithms
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OQSCRYPTOFACTORY_H
#define _SOFTHSM_V2_OQSCRYPTOFACTORY_H

#include "config.h"
#include "CryptoFactory.h"
#include "SymmetricAlgorithm.h"
#include "AsymmetricAlgorithm.h"
#include "HashAlgorithm.h"
#include "MacAlgorithm.h"
#include "RNG.h"
#include <memory>

class OQSCryptoFactory : public CryptoFactory
{
public:
	// Return the one-and-only instance
	static OQSCryptoFactory* i();

	// This will destroy the one-and-only instance.
	static void reset();

	// Create a concrete instance of a symmetric algorithm
	// PQC does not provide symmetric algorithms, returns NULL
	SymmetricAlgorithm* getSymmetricAlgorithm(SymAlgo::Type algorithm);

	// Create a concrete instance of an asymmetric algorithm
	AsymmetricAlgorithm* getAsymmetricAlgorithm(AsymAlgo::Type algorithm);

	// Create a concrete instance of a hash algorithm
	// PQC does not provide hash algorithms, returns NULL
	HashAlgorithm* getHashAlgorithm(HashAlgo::Type algorithm);

	// Create a concrete instance of a MAC algorithm
	// PQC does not provide MAC algorithms, returns NULL
	MacAlgorithm* getMacAlgorithm(MacAlgo::Type algorithm);

	// Get the global RNG (uses system RNG)
	RNG* getRNG(RNGImpl::Type name = RNGImpl::Default);

	// Destructor
	~OQSCryptoFactory();

private:
	// Constructor
	OQSCryptoFactory();

	// The one-and-only instance
#ifdef HAVE_CXX11
	static std::unique_ptr<OQSCryptoFactory> instance;
#else
	static std::auto_ptr<OQSCryptoFactory> instance;
#endif

	// RNG instance
	RNG* rng;
};

#endif // !_SOFTHSM_V2_OQSCRYPTOFACTORY_H
