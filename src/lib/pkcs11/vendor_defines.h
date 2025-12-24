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
 vendor_defines.h

 SoftHSM vendor-specific definitions for PKCS#11
 *****************************************************************************/

#ifndef _SOFTHSM_V2_VENDOR_DEFINES_H
#define _SOFTHSM_V2_VENDOR_DEFINES_H

#include "cryptoki.h"

#ifdef WITH_PQC

/* Vendor-specific mechanism types for PQC Hybrid schemes */

/* Hybrid KEM mechanisms (0x80000001 - 0x800000FF) */
#define CKM_VENDOR_MLKEM768_ECDH_P256      0x80000001UL  /* ML-KEM-768 + ECDH P-256 */
#define CKM_VENDOR_MLKEM1024_ECDH_P384     0x80000002UL  /* ML-KEM-1024 + ECDH P-384 */
#define CKM_VENDOR_MLKEM768_X25519         0x80000003UL  /* ML-KEM-768 + X25519 */

/* Hybrid Signature mechanisms */
#define CKM_VENDOR_MLDSA65_ECDSA_P256      0x80000010UL  /* ML-DSA-65 + ECDSA P-256 */
#define CKM_VENDOR_MLDSA87_ECDSA_P384      0x80000011UL  /* ML-DSA-87 + ECDSA P-384 */

/* Vendor-specific key types for PQC Hybrid schemes (0x80000100 - 0x800001FF) */
#define CKK_VENDOR_HYBRID_KEM              0x80000100UL
#define CKK_VENDOR_HYBRID_SIGNATURE        0x80000101UL

/* Vendor-specific attributes for Hybrid keys (0x80000200 - 0x800002FF) */
#define CKA_VENDOR_PQC_PUBLIC_KEY          0x80000200UL
#define CKA_VENDOR_PQC_PRIVATE_KEY         0x80000201UL
#define CKA_VENDOR_CLASSICAL_PUBLIC_KEY    0x80000202UL
#define CKA_VENDOR_CLASSICAL_PRIVATE_KEY   0x80000203UL
#define CKA_VENDOR_HYBRID_MECHANISM        0x80000204UL

/* Hybrid KEM combiner function identifiers */
typedef enum {
	HYBRID_COMBINER_CONCAT = 0,      /* Simple concatenation */
	HYBRID_COMBINER_SHA256 = 1,      /* SHA-256 based KDF */
	HYBRID_COMBINER_SHA512 = 2,      /* SHA-512 based KDF */
	HYBRID_COMBINER_KMAC128 = 3,     /* KMAC128 based KDF */
	HYBRID_COMBINER_KMAC256 = 4      /* KMAC256 based KDF */
} HybridCombinerType;

/* Hybrid mechanism info structure */
typedef struct CK_HYBRID_MECHANISM_INFO {
	CK_MECHANISM_TYPE pqcMechanism;       /* PQC mechanism (e.g., CKM_ML_KEM) */
	CK_MECHANISM_TYPE classicalMechanism; /* Classical mechanism (e.g., CKM_ECDH) */
	HybridCombinerType combinerType;      /* KDF combiner function */
	CK_ULONG outputLength;                /* Combined secret length */
} CK_HYBRID_MECHANISM_INFO;

typedef CK_HYBRID_MECHANISM_INFO CK_PTR CK_HYBRID_MECHANISM_INFO_PTR;

/* Helper macros for hybrid mechanisms */
#define IS_HYBRID_KEM_MECHANISM(mech) \
	((mech) == CKM_VENDOR_MLKEM768_ECDH_P256 || \
	 (mech) == CKM_VENDOR_MLKEM1024_ECDH_P384 || \
	 (mech) == CKM_VENDOR_MLKEM768_X25519)

#define IS_HYBRID_SIGNATURE_MECHANISM(mech) \
	((mech) == CKM_VENDOR_MLDSA65_ECDSA_P256 || \
	 (mech) == CKM_VENDOR_MLDSA87_ECDSA_P384)

/* Helper macro for ML-KEM specific mechanisms */
#define IS_MLKEM_SPECIFIC_MECHANISM(mech) \
	((mech) == CKM_MLKEM_512 || \
	 (mech) == CKM_MLKEM_768 || \
	 (mech) == CKM_MLKEM_1024)

#define IS_HYBRID_MECHANISM(mech) \
	(IS_HYBRID_KEM_MECHANISM(mech) || IS_HYBRID_SIGNATURE_MECHANISM(mech))

#endif /* WITH_PQC */

#endif /* !_SOFTHSM_V2_VENDOR_DEFINES_H */
