/*
 * Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include <stddef.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <stdbool.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

/* Third party headers */
#include "azure_c_shared_utility/strings.h"
#include "azure_c_shared_utility/xlogging.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"

/* Public headers */
#include "kvs/errors.h"

/* Internal headers */
#include "os/allocator.h"
#include "restful/aws_signer_v4.h"

LOG_MODULE_REGISTER(aws_signer_v4, LOG_LEVEL_NONE);

#define HTTP_METHOD_GET "GET"
#define HTTP_METHOD_PUT "PUT"
#define HTTP_METHOD_POST "POST"

/* The buffer length used for doing SHA256 hash check. */
#define SHA256_DIGEST_LENGTH 32

/* The buffer length used for ASCII Hex encoded SHA256 result. */
#define HEX_ENCODED_SHA_256_STRING_SIZE 65

/* The string length of "date" format defined by AWS Signature V4. */
#define SIGNATURE_DATE_STRING_LEN 8

/* The signature start described by AWS Signature V4. */
#define AWS_SIG_V4_SIGNATURE_START "AWS4"

/* The signature end described by AWS Signature V4. */
#define AWS_SIG_V4_SIGNATURE_END "aws4_request"

/* The signed algorithm. */
#define AWS_SIG_V4_ALGORITHM "AWS4-HMAC-SHA256"

/* The length of oct string for SHA256 hash buffer. */
#define AWS_SIG_V4_MAX_HMAC_SIZE (SHA256_DIGEST_LENGTH * 2 + 1)

/* Template of canonical scope: <DATE>/<REGION>/<SERVICE>/<SIGNATURE_END>*/
#define TEMPLATE_CANONICAL_SCOPE "%.*s/%s/%s/%s"

/* Template of canonical signed string: <ALGO>\n<DATE_TIME>\n<SCOPE>\n<HEX_SHA_CANONICAL_REQ> */
#define TEMPLATE_CANONICAL_SIGNED_STRING "%s\n%s\n%s\n%s"

#define TEMPLATE_SIGNATURE_START "%s%s"

typedef struct AwsSigV4
{
    STRING_HANDLE xStCanonicalRequest;
    STRING_HANDLE xStSignedHeaders;
    STRING_HANDLE xStScope;
    STRING_HANDLE xStHmacHexEncoded;
    STRING_HANDLE xStAuthorization;
} AwsSigV4_t;


bool othernonreserved(char c)
{
    char valid[] = "-_.~";
    for (int i=0; i<strlen(valid); i++) {
        if (c == valid[i]) 
            return true;
    }
    return false;
}

char* uri_escape(const char* str) {
    size_t len = strlen(str);
    size_t new_len = 0;

    // First, calculate the length needed for the escaped string
    for (size_t i = 0; i < len; i++) {
        if (isalnum((unsigned char)str[i])) {
            new_len += 1;  // Alphanumeric characters are kept as-is
        } else {
            new_len += 3;  // Special characters are replaced by '%xx'
        }
    }

    // Allocate space for the new string (+1 for null terminator)
    char* escaped_str = k_malloc(new_len + 1);
    if (!escaped_str) {
        return NULL; // Allocation failed
    }

    // Populate the new string with escaped characters
    char* ptr = escaped_str;
    for (size_t i = 0; i < len; i++) {
        if (isalnum((unsigned char)str[i]) || othernonreserved(str[i])) {
            *ptr++ = str[i];  // Copy alphanumeric characters as-is
        } else {
            sprintf(ptr, "%%%02X", (unsigned char)str[i]);  // Escape special characters
            ptr += 3;
        }
    }

    *ptr = '\0';  // Null-terminate the new string
    return escaped_str;
}

static int prvValidateHttpMethod(const char *pcHttpMethod)
{
    if (pcHttpMethod == NULL)
    {
        return KVS_ERROR_INVALID_ARGUMENT;
    }
    else if (!strcmp(pcHttpMethod, HTTP_METHOD_POST) && !strcmp(pcHttpMethod, HTTP_METHOD_GET) && !strcmp(pcHttpMethod, HTTP_METHOD_PUT))
    {
        return KVS_ERROR_INVALID_ARGUMENT;
    }
    else
    {
        return KVS_ERRNO_NONE;
    }
}

static int prvValidateUri(const char *pcUri)
{
    /* TODO: Add lexical verification. */

    if (pcUri == NULL)
    {
        return KVS_ERROR_INVALID_ARGUMENT;
    }
    else
    {
        return KVS_ERRNO_NONE;
    }
}

static int prvValidateHttpHeader(const char *pcHeader, const char *pcValue)
{
    /* TODO: Add lexical verification. */

    if (pcHeader == NULL || pcValue == NULL)
    {
        return KVS_ERROR_INVALID_ARGUMENT;
    }
    else
    {
        return KVS_ERRNO_NONE;
    }
}

static int prvHexEncodedSha256(const unsigned char *pMsg, size_t uMsgLen, char pcHexEncodedHash[HEX_ENCODED_SHA_256_STRING_SIZE])
{
    int res = KVS_ERRNO_NONE;
    int retVal = 0;
    int i = 0;
    char *p = NULL;
    unsigned char pHashBuf[SHA256_DIGEST_LENGTH] = {0};

    LOG_DBG("Input: %s, %d", pMsg, uMsgLen);

    if (pMsg == NULL)
    {
        res = KVS_ERROR_INVALID_ARGUMENT;
    }
    else if ((retVal = mbedtls_sha256(pMsg, uMsgLen, pHashBuf, 0)) != 0)
    {
        res = KVS_GENERATE_MBEDTLS_ERROR(retVal);
    }
    else
    {
        p = pcHexEncodedHash;
        for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
        {
            p += snprintf(p, 3, "%02x", pHashBuf[i]);
        }
    }

    LOG_DBG("Output: %s", pcHexEncodedHash);

    return res;
}

AwsSigV4Handle AwsSigV4_Create(char *pcHttpMethod, char *pcUri, char *pcQuery)
{
    int res = KVS_ERRNO_NONE;
    AwsSigV4_t *pxAwsSigV4 = NULL;

    if ((res = prvValidateHttpMethod(pcHttpMethod) == KVS_ERRNO_NONE && prvValidateUri(pcUri)) == KVS_ERRNO_NONE)
    {
        do
        {
            pxAwsSigV4 = (AwsSigV4_t *)k_malloc(sizeof(AwsSigV4_t));
            if (pxAwsSigV4 == NULL)
            {
                res = KVS_ERROR_OUT_OF_MEMORY;
                break;
            }
            memset(pxAwsSigV4, 0, sizeof(AwsSigV4_t));

            pxAwsSigV4->xStCanonicalRequest = STRING_construct_sprintf("%s\n%s\n%s\n", pcHttpMethod, pcUri, (pcQuery == NULL) ? "" : pcQuery);
            pxAwsSigV4->xStSignedHeaders = STRING_new();
            pxAwsSigV4->xStScope = STRING_new();
            pxAwsSigV4->xStHmacHexEncoded = STRING_new();
            pxAwsSigV4->xStAuthorization = STRING_new();

            if (pxAwsSigV4->xStCanonicalRequest == NULL || pxAwsSigV4->xStSignedHeaders == NULL || pxAwsSigV4->xStHmacHexEncoded == NULL)
            {
                res = KVS_ERROR_OUT_OF_MEMORY;
                break;
            }
        } while (0);

        if (res != KVS_ERRNO_NONE)
        {
            LogError("Failed to init canonical request");
            AwsSigV4_Terminate(pxAwsSigV4);
            pxAwsSigV4 = NULL;
        }
    }

    return (AwsSigV4Handle)pxAwsSigV4;
}

void AwsSigV4_Terminate(AwsSigV4Handle xSigV4Handle)
{
    AwsSigV4_t *pxAwsSigV4 = (AwsSigV4_t *)xSigV4Handle;

    if (pxAwsSigV4 != NULL)
    {
        STRING_delete(pxAwsSigV4->xStCanonicalRequest);
        STRING_delete(pxAwsSigV4->xStSignedHeaders);
        STRING_delete(pxAwsSigV4->xStScope);
        STRING_delete(pxAwsSigV4->xStHmacHexEncoded);
        STRING_delete(pxAwsSigV4->xStAuthorization);
        k_free(pxAwsSigV4);
    }
}

int AwsSigV4_AddCanonicalHeader(AwsSigV4Handle xSigV4Handle, const char *pcHeader, const char *pcValue)
{
    int res = KVS_ERRNO_NONE;
    AwsSigV4_t *pxAwsSigV4 = (AwsSigV4_t *)xSigV4Handle;

    if (pxAwsSigV4 == NULL)
    {
        res = KVS_ERROR_INVALID_ARGUMENT;
    }
    else if ((res = prvValidateHttpHeader(pcHeader, pcValue)) != KVS_ERRNO_NONE)
    {
        /* Propagate the res error */
    }
    else if (STRING_sprintf(pxAwsSigV4->xStCanonicalRequest, "%s:%s\n", pcHeader, pcValue) != 0)
    {
        res = KVS_ERROR_C_UTIL_STRING_ERROR;
    }
    else if (STRING_length(pxAwsSigV4->xStSignedHeaders) > 0 && STRING_concat(pxAwsSigV4->xStSignedHeaders, ";") != 0)
    {
        res = KVS_ERROR_C_UTIL_STRING_ERROR;
    }
    else if (STRING_concat(pxAwsSigV4->xStSignedHeaders, pcHeader) != 0)
    {
        res = KVS_ERROR_C_UTIL_STRING_ERROR;
    }
    else
    {
        /* nop */
    }

    // LOG_DBG("Add- Canonical headers: %s", STRING_c_str(pxAwsSigV4->xStCanonicalRequest));

    return res;
}

int AwsSigV4_AddCanonicalBody(AwsSigV4Handle xSigV4Handle, const char *pBody, size_t uBodyLen)
{
    int res = KVS_ERRNO_NONE;
    AwsSigV4_t *pxAwsSigV4 = (AwsSigV4_t *)xSigV4Handle;
    char pcBodyHexEncodedSha256[HEX_ENCODED_SHA_256_STRING_SIZE] = {0};

    if (pxAwsSigV4 == NULL || pBody == NULL)
    {
        res = KVS_ERROR_INVALID_ARGUMENT;
    }
    else if (STRING_sprintf(pxAwsSigV4->xStCanonicalRequest, "\n%s\n", STRING_c_str(pxAwsSigV4->xStSignedHeaders)) != 0)
    {
        res = KVS_ERROR_C_UTIL_STRING_ERROR;
    }
    else if (prvHexEncodedSha256((const unsigned char *)pBody, uBodyLen, pcBodyHexEncodedSha256) != 0)
    {
        res = KVS_ERROR_C_UTIL_STRING_ERROR;
    }
    else if (STRING_concat(pxAwsSigV4->xStCanonicalRequest, pcBodyHexEncodedSha256) != 0)
    {
        res = KVS_ERROR_C_UTIL_STRING_ERROR;
    }
    else
    {
        /* nop */
    }

    // LOG_DBG("Add- Canonical request: %s", STRING_c_str(pxAwsSigV4->xStCanonicalRequest));

    return res;
}

int AwsSigV4_Sign(AwsSigV4Handle xSigV4Handle, char *pcAccessKey, char *pcSecretKey, char *pcRegion, char *pcService, const char *pcXAmzDate)
{
    int res = KVS_ERRNO_NONE;
    int retVal = 0;
    AwsSigV4_t *pxAwsSigV4 = (AwsSigV4_t *)xSigV4Handle;
    char pcCanonicalReqHexEncSha256[HEX_ENCODED_SHA_256_STRING_SIZE] = {0};
    const mbedtls_md_info_t *pxMdInfo = NULL;
    mbedtls_md_context_t xMdCtx;
    STRING_HANDLE xStSignedStr = NULL;
    size_t uHmacSize = 0;
    char pHmac[AWS_SIG_V4_MAX_HMAC_SIZE] = {0};
    char pHmac2[AWS_SIG_V4_MAX_HMAC_SIZE] = {0};
    int i = 0;

    if (pxAwsSigV4 == NULL || pcSecretKey == NULL || pcRegion == NULL || pcService == NULL || pcXAmzDate == NULL)
    {
        res = KVS_ERROR_INVALID_ARGUMENT;
    }
    

    /* Do SHA256 on canonical request and then hex encode it. */
    if (
        (res = prvHexEncodedSha256((const unsigned char *)STRING_c_str(pxAwsSigV4->xStCanonicalRequest), STRING_length(pxAwsSigV4->xStCanonicalRequest), pcCanonicalReqHexEncSha256)) !=
        KVS_ERRNO_NONE){
            /* Propagate the res error */
        }


    if ((pxMdInfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256)) == NULL) {
        res = KVS_ERROR_UNKNOWN_MBEDTLS_MESSAGE_DIGEST;
    }
    /* HMAC size of SHA256 should be 32. */
    else if ((uHmacSize = mbedtls_md_get_size(pxMdInfo)) == 0) {
        res = KVS_ERROR_INVALID_MBEDTLS_MESSAGE_DIGEST_SIZE;
    }
    LOG_DBG("HMAC size: %d", uHmacSize);
    mbedtls_md_init(&xMdCtx);
    if ((retVal = mbedtls_md_setup(&xMdCtx, pxMdInfo, 1)) != 0) {
        res = KVS_GENERATE_MBEDTLS_ERROR(retVal);
    }


    LOG_DBG("Scope before: %s", STRING_c_str(pxAwsSigV4->xStScope));
    /* Generate the scope string. */
    if (STRING_sprintf(pxAwsSigV4->xStScope, TEMPLATE_CANONICAL_SCOPE, SIGNATURE_DATE_STRING_LEN, pcXAmzDate, pcRegion, pcService, AWS_SIG_V4_SIGNATURE_END) != 0)
    {
        res = KVS_ERROR_C_UTIL_STRING_ERROR;
    }
    LOG_DBG("Scope after: %s", STRING_c_str(pxAwsSigV4->xStScope));
    
    /* Generate the signed string. */
    if (
        (xStSignedStr =
             STRING_construct_sprintf(TEMPLATE_CANONICAL_SIGNED_STRING, AWS_SIG_V4_ALGORITHM, pcXAmzDate, STRING_c_str(pxAwsSigV4->xStScope), pcCanonicalReqHexEncSha256)) == NULL)
    {   /* TODO Monday/ASAP - remove the above line */
        res = KVS_ERROR_C_UTIL_STRING_ERROR;
    }
    LOG_DBG("String to sign: %s", STRING_c_str(xStSignedStr));
    
    /* Generate the beginning of the signature. */
    // pcSecretKey = uri_escape(pcSecretKey);
    if (pcSecretKey == NULL)
    {
        res = KVS_ERROR_OUT_OF_MEMORY;
    }
    if (snprintf(pHmac, AWS_SIG_V4_MAX_HMAC_SIZE, TEMPLATE_SIGNATURE_START, AWS_SIG_V4_SIGNATURE_START, pcSecretKey) == 0)
    {
        res = KVS_ERROR_C_UTIL_STRING_ERROR;
    }

    /* Calculate the HMAC of date, region, service, signature end, and signed string*/
    LOG_DBG("HMAC 0.0: %s, len: %d, date: %s", pHmac, strlen(pHmac), pcXAmzDate);
    //LOG_HEXDUMP_DBG(pHmac, strlen(pHmac), "PecretKy");
    if ((retVal = mbedtls_md_hmac(pxMdInfo, (const unsigned char *)pHmac, strlen(pHmac), (const unsigned char *)pcXAmzDate, SIGNATURE_DATE_STRING_LEN, (unsigned char *)pHmac2)) != 0 ) {
        res = KVS_GENERATE_MBEDTLS_ERROR(retVal);
    }

    LOG_HEXDUMP_DBG(pHmac2, strlen(pHmac2), "DateKey");
    memset(pHmac, 0, sizeof(pHmac));
    if ((retVal = mbedtls_md_hmac(pxMdInfo, (const unsigned char *)pHmac2, uHmacSize, (const unsigned char *)pcRegion, strlen(pcRegion), (unsigned char *)pHmac)) != 0 ) {
        res = KVS_GENERATE_MBEDTLS_ERROR(retVal);
    }
    
    LOG_HEXDUMP_DBG(pHmac, strlen(pHmac), "RegionKey");
    memset(pHmac2, 0, sizeof(pHmac2));
    if ((retVal = mbedtls_md_hmac(pxMdInfo, (const unsigned char *)pHmac, uHmacSize, (const unsigned char *)pcService, strlen(pcService), (unsigned char *)pHmac2)) != 0 ) {
        res = KVS_GENERATE_MBEDTLS_ERROR(retVal);
    }

    LOG_HEXDUMP_DBG(pHmac2, strlen(pHmac2), "ServiceKey");
    memset(pHmac, 0, sizeof(pHmac));
    if ((retVal = mbedtls_md_hmac(pxMdInfo, (const unsigned char *)pHmac2, uHmacSize, (const unsigned char *)AWS_SIG_V4_SIGNATURE_END, sizeof(AWS_SIG_V4_SIGNATURE_END) - 1, (unsigned char *)pHmac)) != 0 ) {
        res = KVS_GENERATE_MBEDTLS_ERROR(retVal);
    }
    
    LOG_HEXDUMP_DBG(pHmac, strlen(pHmac), "SigningKey");
    memset(pHmac2, 0, sizeof(pHmac2));
    if ((retVal = mbedtls_md_hmac(pxMdInfo, (const unsigned char *)pHmac, uHmacSize, (const unsigned char *)STRING_c_str(xStSignedStr), STRING_length(xStSignedStr), (unsigned char *)pHmac2)) != 0)
    {
        res = KVS_GENERATE_MBEDTLS_ERROR(retVal);
    }
    LOG_HEXDUMP_DBG(pHmac2, strlen(pHmac2), "Signature");


    if (res == KVS_ERRNO_NONE) {
        for (i = 0; i < uHmacSize; i++) {
            if (STRING_sprintf(pxAwsSigV4->xStHmacHexEncoded, "%02x", pHmac2[i] & 0xFF) != 0)
            {
                res = KVS_ERROR_C_UTIL_STRING_ERROR;
                break;
            }
        }

        if (res == 0) {
            if (STRING_sprintf(
                    pxAwsSigV4->xStAuthorization,
                    "AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
                    pcAccessKey,
                    STRING_c_str(pxAwsSigV4->xStScope),
                    STRING_c_str(pxAwsSigV4->xStSignedHeaders),
                    STRING_c_str(pxAwsSigV4->xStHmacHexEncoded)) != 0)
            {
                res = KVS_ERROR_C_UTIL_STRING_ERROR;
            }
        }
    } else {
        LogError("Failed to sign the request");
    }
    
    LOG_DBG("Access key: %s", pcAccessKey);
    LOG_DBG("Secret key: %s", pcSecretKey);
    LOG_DBG("Region: %s", pcRegion);
    LOG_DBG("Service: %s", pcService);
    LOG_DBG("X-Amz-Date: %s", pcXAmzDate);
    LOG_DBG("Canonical request: %s", STRING_c_str(pxAwsSigV4->xStCanonicalRequest));
    LOG_DBG("Signed headers: %s", STRING_c_str(pxAwsSigV4->xStSignedHeaders));
    LOG_DBG("Scope: %s", STRING_c_str(pxAwsSigV4->xStScope));
    LOG_DBG("HMAC: %s", STRING_c_str(pxAwsSigV4->xStHmacHexEncoded));
    LOG_DBG("Authorization: %s", STRING_c_str(pxAwsSigV4->xStAuthorization));

    STRING_delete(xStSignedStr);
    // k_free(pcAccessKey);
    // k_free(pcSecretKey);

    mbedtls_md_free(&xMdCtx);

    return res;
}

const char *AwsSigV4_GetAuthorization(AwsSigV4Handle xSigV4Handle)
{
    AwsSigV4_t *pxAwsSigV4 = (AwsSigV4_t *)xSigV4Handle;

    if (pxAwsSigV4 != NULL)
    {
        return STRING_c_str(pxAwsSigV4->xStAuthorization);
    }
    else
    {
        return NULL;
    }
}