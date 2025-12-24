#include <stdio.h>
#include "../pkcs11/cryptoki.h"

// Function pointer type for PKCS#11 functions
typedef CK_RV (*C_GetFunctionListPtr)(CK_FUNCTION_LIST_PTR_PTR);

extern "C" CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);

int main() {
    CK_FUNCTION_LIST_PTR pFunctionList = NULL;
    CK_RV rv;

    // Get function list
    rv = C_GetFunctionList(&pFunctionList);
    if (rv != CKR_OK) {
        printf("C_GetFunctionList failed: 0x%lX\n", rv);
        return 1;
    }

    // Initialize
    rv = pFunctionList->C_Initialize(NULL);
    if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
        printf("C_Initialize failed: 0x%lX\n", rv);
        return 1;
    }

    // Get first slot
    CK_ULONG slotCount;
    rv = pFunctionList->C_GetSlotList(CK_TRUE, NULL, &slotCount);
    if (rv != CKR_OK || slotCount == 0) {
        printf("No slots found\n");
        return 1;
    }

    CK_SLOT_ID slotID;
    rv = pFunctionList->C_GetSlotList(CK_TRUE, &slotID, &slotCount);
    if (rv != CKR_OK) {
        printf("C_GetSlotList failed: 0x%lX\n", rv);
        return 1;
    }

    // Open session
    CK_SESSION_HANDLE hSession;
    rv = pFunctionList->C_OpenSession(slotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &hSession);
    if (rv != CKR_OK) {
        printf("C_OpenSession failed: 0x%lX\n", rv);
        return 1;
    }

    printf("Session opened successfully\n");

    // Try to generate ML-KEM key pair
    CK_MECHANISM mech = { CKM_ML_KEM_KEY_PAIR_GEN, NULL, 0 };
    CK_OBJECT_HANDLE hPub, hPriv;

    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;
    CK_KEY_TYPE keyType = CKK_ML_KEM;
    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_ULONG paramSet = 768;

    CK_ATTRIBUTE pubTemplate[] = {
        { CKA_CLASS, &pubClass, sizeof(pubClass) },
        { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_PRIVATE, &bFalse, sizeof(bFalse) },
        { CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
        { CKA_VALUE_LEN, &paramSet, sizeof(paramSet) }
    };

    CK_ATTRIBUTE privTemplate[] = {
        { CKA_CLASS, &privClass, sizeof(privClass) },
        { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_PRIVATE, &bFalse, sizeof(bFalse) },
        { CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
        { CKA_DECRYPT, &bTrue, sizeof(bTrue) },
        { CKA_EXTRACTABLE, &bFalse, sizeof(bFalse) },
        { CKA_VALUE_LEN, &paramSet, sizeof(paramSet) }
    };

    printf("Attempting to generate ML-KEM-768 key pair...\n");
    rv = pFunctionList->C_GenerateKeyPair(hSession, &mech,
                                           pubTemplate, 6,
                                           privTemplate, 8,
                                           &hPub, &hPriv);

    if (rv == CKR_OK) {
        printf("SUCCESS! ML-KEM key pair generated\n");
        printf("Public key handle: %lu\n", hPub);
        printf("Private key handle: %lu\n", hPriv);
    } else {
        printf("FAILED: C_GenerateKeyPair returned 0x%lX\n", rv);

        // Try to decode the error
        switch(rv) {
            case 0xD0: printf("  -> CKR_TEMPLATE_INCOMPLETE\n"); break;
            case 0x12: printf("  -> CKR_ATTRIBUTE_VALUE_INVALID\n"); break;
            case 0x70: printf("  -> CKR_MECHANISM_INVALID\n"); break;
            default: printf("  -> Unknown error\n"); break;
        }
    }

    pFunctionList->C_CloseSession(hSession);
    pFunctionList->C_Finalize(NULL);

    return (rv == CKR_OK) ? 0 : 1;
}
