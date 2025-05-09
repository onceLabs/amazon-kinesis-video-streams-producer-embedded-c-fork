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

#include <inttypes.h>
#include <stddef.h>

/* Third party headers */
#include "azure_c_shared_utility/buffer_.h"
#include "azure_c_shared_utility/httpheaders.h"
#include "azure_c_shared_utility/strings.h"
#include "azure_c_shared_utility/xlogging.h"

/* Public headers */
#include "kvs/errors.h"

/* Internal headers */
#include "os/allocator.h"
#include "net/http_helper.h"
#include "net/netio.h"
#include "net/http_parser_adapter.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(http_helper, LOG_LEVEL_WRN);

#define DEFAULT_HTTP_RECV_BUFSIZE 2048

// TODO task/BNCC-79 remove
// static void *k_realloc(void *ptr, size_t new_size) {
//     if (ptr == NULL) {
//         return k_malloc(new_size);
//     }

//     if (new_size == 0) {
//         k_free(ptr);
//         return NULL;
//     }

//     void *new_ptr = k_malloc(new_size);
//     if (new_ptr == NULL) {
//         return NULL;
//     }

//     // Copy the old data to the new block of memory
//     memcpy(new_ptr, ptr, new_size);
//     k_free(ptr);

//     return new_ptr;
// }

static int prvGenerateHttpReq(const char *pcHttpMethod, const char *pcUri, HTTP_HEADERS_HANDLE xHttpReqHeaders, const char *pcBody, char **pStringHandle)
{
    int res = KVS_ERRNO_NONE;
    size_t uHeadersCnt = 0;
    size_t i = 0;
    char *pcHeader = NULL;
    size_t reqSize = 0;
    char *xStHttpReq = NULL;

    LOG_DBG("Generating HTTP request");

    if (HTTPHeaders_GetHeaderCount(xHttpReqHeaders, &uHeadersCnt) != HTTP_HEADERS_OK)
    {
        res = KVS_ERROR_UNABLE_TO_GET_HTTP_HEADER_COUNT;
    }
    else
    {
        // Calculate initial size for the HTTP request string (method + URI + HTTP version + CRLF + CRLF)
        //reqSize = strlen(pcHttpMethod) + strlen(pcUri) + strlen(" HTTP/1.1\r\n\r\n") + 1;
        reqSize = strlen(pcHttpMethod) + strlen(pcUri) + strlen(" HTTP/1.1\r\n") + 2;
        xStHttpReq = (char *)k_malloc(reqSize);
        
        if (xStHttpReq == NULL)
        {
            res = KVS_ERROR_C_UTIL_STRING_ERROR;
        }
        else
        {
            // Format the initial HTTP request line
            snprintf(xStHttpReq, reqSize, "%s %s HTTP/1.1\r\n", pcHttpMethod, pcUri);
            LOG_DBG("Initial HTTP request line: %s", xStHttpReq);

            for (i = 0; i < uHeadersCnt && res == KVS_ERRNO_NONE; i++)
            {
                if (HTTPHeaders_GetHeader(xHttpReqHeaders, i, &pcHeader) != HTTP_HEADERS_OK)
                {
                    res = KVS_ERROR_UNABLE_TO_GET_HTTP_HEADER;
                }
                else
                {
                    size_t headerLen = strlen(pcHeader) + strlen("\r\n") + 1;
                    reqSize += headerLen;

                    // Reallocate memory for the growing request string
                    char *newReq = (char *)k_realloc(xStHttpReq, reqSize);
                    if (newReq == NULL)
                    {
                        res = KVS_ERROR_C_UTIL_STRING_ERROR;
                        k_free(pcHeader);
                        break;
                    }

                    xStHttpReq = newReq;
                    strcat(xStHttpReq, pcHeader);
                    strcat(xStHttpReq, "\r\n");

                    /* pcHeader was created by HTTPHeaders_GetHeader via malloc */
                    k_free(pcHeader);
                }
            }

            if (res == KVS_ERRNO_NONE)
            {
                reqSize += strlen("\r\n") + 2;
                char *newReq = (char *)k_realloc(xStHttpReq, reqSize);
                if (newReq == NULL)
                {
                    res = KVS_ERROR_C_UTIL_STRING_ERROR;
                }
                else
                {
                    xStHttpReq = newReq;
                    strcat(xStHttpReq, "\r\n");

                    if (strlen(pcBody) > 0)
                    {
                        reqSize += strlen(pcBody) + 1;
                        newReq = (char *)k_realloc(xStHttpReq, reqSize);
                        if (newReq == NULL)
                        {
                            res = KVS_ERROR_C_UTIL_STRING_ERROR;
                        }
                        else
                        {
                            xStHttpReq = newReq;
                            strcat(xStHttpReq, pcBody);
                        }
                    }
                }
            }
        }
    }

    if (res == KVS_ERRNO_NONE)
    {
      // Print out the generated HTTP request
      LOG_DBG("Generated HTTP request");
      LOG_DBG("\r\n%s", xStHttpReq);
      //LOG_HEXDUMP_DBG(xStHttpReq, strlen(xStHttpReq), "HTTP Request");
      *pStringHandle = xStHttpReq;
    }
    else
    {
      LOG_ERR("Failed to generate HTTP request");
        k_free(xStHttpReq);
        xStHttpReq = NULL;
    }

    return res;
}

// static int prvGenerateHttpReq(const char *pcHttpMethod, const char *pcUri, HTTP_HEADERS_HANDLE xHttpReqHeaders, const char *pcBody, STRING_HANDLE *pStringHandle)
// {
//     int res = KVS_ERRNO_NONE;
//     STRING_HANDLE xStHttpReq = NULL;
//     size_t uHeadersCnt = 0;
//     size_t i = 0;
//     char *pcHeader = NULL;

//     if (HTTPHeaders_GetHeaderCount(xHttpReqHeaders, &uHeadersCnt) != HTTP_HEADERS_OK)
//     {
//         res = KVS_ERROR_UNABLE_TO_GET_HTTP_HEADER_COUNT;
//     }
//     else if ((xStHttpReq = STRING_new()) == NULL || STRING_sprintf(xStHttpReq, "%s %s HTTP/1.1\r\n", pcHttpMethod, pcUri) != 0)
//     {
//         res = KVS_ERROR_C_UTIL_STRING_ERROR;
//     }
//     else
//     {
//         for (i = 0; i < uHeadersCnt && res == KVS_ERRNO_NONE; i++)
//         {
//             if (HTTPHeaders_GetHeader(xHttpReqHeaders, i, &pcHeader) != HTTP_HEADERS_OK)
//             {
//                 res = KVS_ERROR_UNABLE_TO_GET_HTTP_HEADER;
//             }
//             else
//             {
//                 if (STRING_sprintf(xStHttpReq, "%s\r\n", pcHeader) != 0)
//                 {
//                     res = KVS_ERROR_C_UTIL_STRING_ERROR;
//                 }
//                 /* pcHeader was created by HTTPHeaders_GetHeader via malloc */
//                 free(pcHeader);
//             }
//         }

//         if (res == KVS_ERRNO_NONE)
//         {
//             if (STRING_sprintf(xStHttpReq, "\r\n") != 0)
//             {
//                 res = KVS_ERROR_C_UTIL_STRING_ERROR;
//             }
//             else if (strlen(pcBody) > 0 && STRING_sprintf(xStHttpReq, "%s", pcBody) != 0)
//             {
//                 res = KVS_ERROR_C_UTIL_STRING_ERROR;
//             }
//             else
//             {
//                 /* nop */
//             }
//         }
//     }

//     if (res == KVS_ERRNO_NONE)
//     {
//         *pStringHandle = xStHttpReq;
//     }
//     else
//     {
//         STRING_delete(xStHttpReq);
//         xStHttpReq = NULL;
//     }

//     return res;
// }

int Http_executeHttpReq(NetIoHandle xNetIoHandle, const char *pcHttpMethod, const char *pcUri, HTTP_HEADERS_HANDLE xHttpReqHeaders, const char *pcBody)
{
    int res = KVS_ERRNO_NONE;
    char *xStHttpReq = NULL;
    const char *test_uri = "/role-aliases/KvsCameraIoTRoleAlias/credentials";

    // Log the pcuri
    LOG_DBG("HTTP request URI: %s", pcUri);

    if (xNetIoHandle == NULL || pcHttpMethod == NULL || pcUri == NULL || xHttpReqHeaders == NULL || pcBody == NULL)
    {
        res = KVS_ERROR_INVALID_ARGUMENT;
    }
    else if ((res = prvGenerateHttpReq(pcHttpMethod, pcUri, xHttpReqHeaders, pcBody, &xStHttpReq)) != KVS_ERRNO_NONE)
    {
        /* Propagate the res error */
    }
    else if ((res = NetIo_send(xNetIoHandle, (const unsigned char *)xStHttpReq,  strlen(xStHttpReq))) != KVS_ERRNO_NONE)
    {
      LOG_ERR("Failed to send HTTP request with error %d", res);
      /* Propagate the res error */
    }
    else
    {
        /* nop */
    }

    k_free(xStHttpReq);
    //STRING_delete(xStHttpReq); // TODO is this needed? fix if so

    return res;
}

int Http_recvHttpRsp(NetIoHandle xNetIoHandle, unsigned int *puHttpStatus, char **ppRspBody, size_t *puRspBodyLen)
{
    int res = KVS_ERRNO_NONE;
    BUFFER_HANDLE xBufRecv = NULL;
    size_t uBytesReceived = 0;
    size_t uBytesTotalReceived = 0;
    unsigned int uHttpStatusCode = 0;
    const char *pBodyLoc = NULL;
    size_t uBodyLen = 0;
    char *pRspBody = NULL;

    if (xNetIoHandle == NULL || puHttpStatus == NULL || ppRspBody == NULL || puRspBodyLen == NULL)
    {
        res = KVS_ERROR_INVALID_ARGUMENT;
    }
    else if ((xBufRecv = BUFFER_create_with_size(DEFAULT_HTTP_RECV_BUFSIZE)) == NULL)
    {
        res = KVS_ERROR_C_UTIL_UNABLE_TO_CREATE_BUFFER;
    }
    else
    {
        do
        {
            /* TODO: Add timeout checking here */

            if (uBytesTotalReceived == BUFFER_length(xBufRecv))
            {
                /* If buffer is full, then we double the size of buffer. */
                if (BUFFER_enlarge(xBufRecv, uBytesTotalReceived) != 0)
                {
                    res = KVS_ERROR_C_UTIL_UNABLE_TO_ENLARGE_BUFFER;
                    LogError("OOM: xBufRecv");
                    break;
                }
            }
            if ((res = NetIo_recv(xNetIoHandle, BUFFER_u_char(xBufRecv) + uBytesTotalReceived, BUFFER_length(xBufRecv) - uBytesTotalReceived, &uBytesReceived)) != KVS_ERRNO_NONE)
            {
                /* Propagate the res error */
            }
            /* It should be a timeout case. */
            else if (uBytesReceived == 0)
            {
                res = KVS_ERROR_RECV_ZERO_SIZED_HTTP_DATA;
                break;
            }
            else
            {
                uBytesTotalReceived += uBytesReceived;
                if ((res = HttpParser_parseHttpResponse((const char *)BUFFER_u_char(xBufRecv), uBytesTotalReceived, &uHttpStatusCode, &pBodyLoc, &uBodyLen)) != KVS_ERRNO_NONE)
                {
                    /* Propagate the res error */
                }
                /* If it's 100-continue, then we need to discard previous result and do it again. */
                else if (uHttpStatusCode / 100 == 1)
                {
                    LogInfo("100-continue");
                    uBytesTotalReceived = 0;
                    res = KVS_ERROR_HTTP_100_CONTINUE_EXPECT_MORE;
                }
                else
                {
                    res = KVS_ERRNO_NONE;
                    *puHttpStatus = uHttpStatusCode;

                    if ((pRspBody = (char *)k_malloc(uBodyLen + 1)) == NULL)
                    {
                        res = KVS_ERROR_OUT_OF_MEMORY;
                        LogError("OOM pRspBody");
                        break;
                    }
                    memcpy(pRspBody, pBodyLoc, uBodyLen);
                    pRspBody[uBodyLen] = '\0';
                    *ppRspBody = pRspBody;
                    *puRspBodyLen = uBodyLen;
                }
            }
        } while (res != KVS_ERRNO_NONE);
    }

    BUFFER_delete(xBufRecv);

    return res;
}