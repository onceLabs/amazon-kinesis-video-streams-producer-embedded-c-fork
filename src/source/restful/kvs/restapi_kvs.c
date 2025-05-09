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

#include <ctype.h>
#include <inttypes.h>
#include <stddef.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
/* Thirdparty headers */
#include "azure_c_shared_utility/buffer_.h"
#include "azure_c_shared_utility/doublylinkedlist.h"
#include "azure_c_shared_utility/httpheaders.h"
#include "azure_c_shared_utility/lock.h"
#include "azure_c_shared_utility/strings.h"
#include "azure_c_shared_utility/xlogging.h"
#include "parson.h"

/* Public headers */
#include "kvs/errors.h"
#include "kvs/restapi.h"

/* Platform dependent headers */
#include "kvs/port.h"

/* Internal headers */
#include "os/allocator.h"
#include "restful/aws_signer_v4.h"
#include "misc/json_helper.h"
#include "net/http_helper.h"
#include "net/netio.h"

#include "kvs/zephyr_fixes.h"

LOG_MODULE_REGISTER(restapi, LOG_LEVEL_DBG);

#ifndef SAFE_FREE
#define SAFE_FREE(a) \
    do               \
    {                \
        k_free(a);  \
        a = NULL;    \
    } while (0)
#endif /* SAFE_FREE */

#define DEFAULT_RECV_BUFSIZE (1024)

#define PORT_HTTPS "443"

/*-----------------------------------------------------------*/

#define KVS_URI_CREATE_STREAM "/createStream"
#define KVS_URI_DESCRIBE_STREAM "/describeStream"
#define KVS_URI_GET_DATA_ENDPOINT "/getDataEndpoint"
#define KVS_URI_PUT_MEDIA "/putMedia"

/*-----------------------------------------------------------*/

#define DESCRIBE_STREAM_HTTP_BODY_TEMPLATE "{\"StreamName\": \"%s\"}"

#define CREATE_STREAM_HTTP_BODY_TEMPLATE "{\"StreamName\": \"%s\",\"DataRetentionInHours\": %d}"

#define GET_DATA_ENDPOINT_HTTP_BODY_TEMPLATE "{\"StreamName\": \"%s\",\"APIName\":\"PUT_MEDIA\"}"

/*-----------------------------------------------------------*/

typedef struct
{
    ePutMediaFragmentAckEventType eventType;
    uint64_t uFragmentTimecode;
    unsigned int uErrorId;

    DLIST_ENTRY xAckEntry;
} FragmentAck_t;

typedef struct PutMedia
{
    //LOCK_HANDLE xLock;
    struct k_mutex *xLockMutex;

    NetIoHandle xNetIoHandle;
    DLIST_ENTRY xPendingFragmentAcks;
} PutMedia_t;

#define JSON_KEY_EVENT_TYPE "EventType"
#define JSON_KEY_FRAGMENT_TIMECODE "FragmentTimecode"
#define JSON_KEY_ERROR_ID "ErrorId"

#define EVENT_TYPE_BUFFERING "\"BUFFERING\""
#define EVENT_TYPE_RECEIVED "\"RECEIVED\""
#define EVENT_TYPE_PERSISTED "\"PERSISTED\""
#define EVENT_TYPE_ERROR "\"ERROR\""
#define EVENT_TYPE_IDLE "\"IDLE\""

static struct k_mutex wrapper_mutex;
/*-----------------------------------------------------------*/

static int prvValidateServiceParameter(KvsServiceParameter_t *pServPara)
{
    if (pServPara == NULL || pServPara->pcAccessKey == NULL || pServPara->pcSecretKey == NULL || pServPara->pcRegion == NULL || pServPara->pcService == NULL ||
        pServPara->pcHost == NULL)
    {
        return KVS_ERROR_INVALID_ARGUMENT;
    }
    else
    {
        return KVS_ERRNO_NONE;
    }
}

static int prvValidateDescribeStreamParameter(KvsDescribeStreamParameter_t *pDescPara)
{
    if (pDescPara == NULL || pDescPara->pcStreamName == NULL)
    {
        return KVS_ERROR_INVALID_ARGUMENT;
    }
    else
    {
        return KVS_ERRNO_NONE;
    }
}

static int prvValidateCreateStreamParameter(KvsCreateStreamParameter_t *pCreatePara)
{
    if (pCreatePara == NULL || pCreatePara->pcStreamName == NULL)
    {
        return KVS_ERROR_INVALID_ARGUMENT;
    }
    else
    {
        return KVS_ERRNO_NONE;
    }
}

static int prvValidateGetDataEndpointParameter(KvsGetDataEndpointParameter_t *pGetDataEpPara)
{
    if (pGetDataEpPara == NULL || pGetDataEpPara->pcStreamName == NULL)
    {
        return KVS_ERROR_INVALID_ARGUMENT;
    }
    else
    {
        return KVS_ERRNO_NONE;
    }
}

static int prvValidatePutMediaParameter(KvsPutMediaParameter_t *pPutMediaPara)
{
    if (pPutMediaPara == NULL || pPutMediaPara->pcStreamName == NULL)
    {
        return KVS_ERROR_INVALID_ARGUMENT;
    }
    else
    {
        return KVS_ERRNO_NONE;
    }
}

static AwsSigV4Handle prvSign(KvsServiceParameter_t *pServPara, char *pcUri, char *pcQuery, HTTP_HEADERS_HANDLE xHeadersToSign, const char *pcHttpBody)
{
    int res = KVS_ERRNO_NONE;

    AwsSigV4Handle xAwsSigV4Handle = NULL;
    const char *pcVal;
    const char *pcXAmzDate;

    // Create empty canonical request
    if ((xAwsSigV4Handle = AwsSigV4_Create(HTTP_METHOD_POST, pcUri, pcQuery)) == NULL) {
        res = KVS_ERROR_FAIL_TO_CREATE_SIGV4_HANDLE;
    }

    // Connection header
    if (
      (pcVal = HTTPHeaders_FindHeaderValue(xHeadersToSign, HDR_CONNECTION)) != NULL && 
      AwsSigV4_AddCanonicalHeader(xAwsSigV4Handle, HDR_CONNECTION, pcVal) != KVS_ERRNO_NONE
    ) {
        res = KVS_ERROR_FAIL_TO_ADD_CANONICAL_HEADER;
    }

    // Host header
    if (
      (pcVal = HTTPHeaders_FindHeaderValue(xHeadersToSign, HDR_HOST)) != NULL && 
      AwsSigV4_AddCanonicalHeader(xAwsSigV4Handle, HDR_HOST, pcVal) != KVS_ERRNO_NONE
    ) {
        res = KVS_ERROR_FAIL_TO_ADD_CANONICAL_HEADER;
    }

    // transfer-encoding header
    if (
      (pcVal = HTTPHeaders_FindHeaderValue(xHeadersToSign, HDR_TRANSFER_ENCODING)) != NULL &&
      AwsSigV4_AddCanonicalHeader(xAwsSigV4Handle, HDR_TRANSFER_ENCODING, pcVal) != KVS_ERRNO_NONE
    ) {
        res = KVS_ERROR_FAIL_TO_ADD_CANONICAL_HEADER;
    }

    // user-agent header
    if (
      (pcVal = HTTPHeaders_FindHeaderValue(xHeadersToSign, HDR_USER_AGENT)) != NULL && 
      AwsSigV4_AddCanonicalHeader(xAwsSigV4Handle, HDR_USER_AGENT, pcVal) != KVS_ERRNO_NONE
    ) {
        res = KVS_ERROR_FAIL_TO_ADD_CANONICAL_HEADER;
    }

    // range header - for testing
    #define HDR_RANGE "range"
    if (
      (pcVal = HTTPHeaders_FindHeaderValue(xHeadersToSign, HDR_RANGE)) != NULL && 
      AwsSigV4_AddCanonicalHeader(xAwsSigV4Handle, HDR_RANGE, pcVal) != KVS_ERRNO_NONE
    ) {
        res = KVS_ERROR_FAIL_TO_ADD_CANONICAL_HEADER;
    }

    // x-amz-content-sha256 header
    #define HDR_X_AMZ_CONTENT_SHA256 "x-amz-content-sha256"
    if (
      (pcVal = HTTPHeaders_FindHeaderValue(xHeadersToSign, HDR_X_AMZ_CONTENT_SHA256)) != NULL && 
      AwsSigV4_AddCanonicalHeader(xAwsSigV4Handle, HDR_X_AMZ_CONTENT_SHA256, pcVal) != KVS_ERRNO_NONE
    ) {
        res = KVS_ERROR_FAIL_TO_ADD_CANONICAL_HEADER;
    }

    // x-amz-date header
    if (
      (pcXAmzDate = HTTPHeaders_FindHeaderValue(xHeadersToSign, HDR_X_AMZ_DATE)) != NULL &&  
      AwsSigV4_AddCanonicalHeader(xAwsSigV4Handle, HDR_X_AMZ_DATE, pcXAmzDate) != KVS_ERRNO_NONE
    ) {
        res = KVS_ERROR_FAIL_TO_ADD_CANONICAL_HEADER;
    }

    memset((void *)&pcVal, 0, sizeof(pcVal));
    // x-amz-security-token header
    if (
      (pcVal = HTTPHeaders_FindHeaderValue(xHeadersToSign, HDR_X_AMZ_SECURITY_TOKEN)) != NULL &&
      AwsSigV4_AddCanonicalHeader(xAwsSigV4Handle, HDR_X_AMZ_SECURITY_TOKEN, pcVal) != KVS_ERRNO_NONE
    ) {
        res = KVS_ERROR_FAIL_TO_ADD_CANONICAL_HEADER;
    }
    LOG_DBG("pcVal session-token: %s", pcVal);

    // x-amzn-fragment-acknowledgment-required header
    if (
      (pcVal = HTTPHeaders_FindHeaderValue(xHeadersToSign, HDR_X_AMZN_FRAG_ACK_REQUIRED)) != NULL &&
      AwsSigV4_AddCanonicalHeader(xAwsSigV4Handle, HDR_X_AMZN_FRAG_ACK_REQUIRED, pcVal) != KVS_ERRNO_NONE
    ) {
        res = KVS_ERROR_FAIL_TO_ADD_CANONICAL_HEADER;
    }

    // x-amzn-fragment-timecode-type header
    if (
      (pcVal = HTTPHeaders_FindHeaderValue(xHeadersToSign, HDR_X_AMZN_FRAG_T_TYPE)) != NULL &&
      AwsSigV4_AddCanonicalHeader(xAwsSigV4Handle, HDR_X_AMZN_FRAG_T_TYPE, pcVal) != KVS_ERRNO_NONE
    ) {
        res = KVS_ERROR_FAIL_TO_ADD_CANONICAL_HEADER;
    }

    // x-amzn-producer-start-timestamp header
    if (
      (pcVal = HTTPHeaders_FindHeaderValue(xHeadersToSign, HDR_X_AMZN_PRODUCER_START_T)) != NULL &&
      AwsSigV4_AddCanonicalHeader(xAwsSigV4Handle, HDR_X_AMZN_PRODUCER_START_T, pcVal) != KVS_ERRNO_NONE
    ) {
        res = KVS_ERROR_FAIL_TO_ADD_CANONICAL_HEADER;
    }

    // x-amzn-stream-name header
    if (
      (pcVal = HTTPHeaders_FindHeaderValue(xHeadersToSign, HDR_X_AMZN_STREAM_NAME)) != NULL &&
      AwsSigV4_AddCanonicalHeader(xAwsSigV4Handle, HDR_X_AMZN_STREAM_NAME, pcVal) != KVS_ERRNO_NONE
    ) {
        res = KVS_ERROR_FAIL_TO_ADD_CANONICAL_HEADER;
    }

    // Add body to canonical request
    if (
      AwsSigV4_AddCanonicalBody(xAwsSigV4Handle, pcHttpBody, strlen(pcHttpBody)) != KVS_ERRNO_NONE
    ) {
        res = KVS_ERRNO_FAIL;
    }

    // Sign the request
    LOG_DBG("Signing the request: pcAccessKey: %s", pServPara->pcAccessKey);
    if (
      (res = AwsSigV4_Sign(xAwsSigV4Handle, pServPara->pcAccessKey, pServPara->pcSecretKey, pServPara->pcRegion, pServPara->pcService, pcXAmzDate)) != KVS_ERRNO_NONE) {
        /* Propagate the res error */
    }

    if (res != KVS_ERRNO_NONE)
    {
        AwsSigV4_Terminate(xAwsSigV4Handle);
        xAwsSigV4Handle = NULL;
    }

    return xAwsSigV4Handle;
}

static int prvParseDataEndpoint(const char *pcJsonSrc, size_t uJsonSrcLen, char **ppcEndpoint)
{
    int res = KVS_ERRNO_NONE;
    STRING_HANDLE xStJson = NULL;
    JSON_Value *pxRootValue = NULL;
    JSON_Object *pxRootObject = NULL;
    char *pcDataEndpoint = NULL;
    size_t uEndpointLen = 0;

    json_set_escape_slashes(0);

    if (pcJsonSrc == NULL || uJsonSrcLen == 0 || ppcEndpoint == NULL)
    {
        res = KVS_ERROR_INVALID_ARGUMENT;
        LogError("Invalid argument");
    }
    else if ((xStJson = STRING_construct_n(pcJsonSrc, uJsonSrcLen)) == NULL)
    {
        res = KVS_ERROR_OUT_OF_MEMORY;
        LogError("OOM: parse data endpoint");
    }
    else if (
        (pxRootValue = json_parse_string(STRING_c_str(xStJson))) == NULL || (pxRootObject = json_value_get_object(pxRootValue)) == NULL ||
        (pcDataEndpoint = json_object_dotget_serialize_to_string(pxRootObject, "DataEndpoint", true)) == NULL)
    {
        res = KVS_ERROR_FAIL_TO_PARSE_DATA_ENDPOINT;
        LogError("Failed to parse data endpoint");
    }
    else
    {
        /* Please note that the memory of pcDataEndpoint is from malloc and we tranfer the ownership to caller here. */
        uEndpointLen = strlen(pcDataEndpoint);
        if (uEndpointLen > 8)
        {
            uEndpointLen -= 8;
            *ppcEndpoint = (char *)kvsMalloc(uEndpointLen + 1);
            if (*ppcEndpoint != NULL)
            {
                memcpy(*ppcEndpoint, pcDataEndpoint + 8, uEndpointLen);
                (*ppcEndpoint)[uEndpointLen] = '\0';
            }
        }
        kvsFree(pcDataEndpoint);
    }

    if (pxRootValue != NULL)
    {
        json_value_free(pxRootValue);
    }

    STRING_delete(xStJson);

    return res;
}

static char *prvGetTimecodeValue(FragmentTimecodeType_t xTimecodeType)
{
    if (xTimecodeType == TIMECODE_TYPE_ABSOLUTE)
    {
        return "ABSOLUTE";
    }
    else if (xTimecodeType == TIMECODE_TYPE_RELATIVE)
    {
        return "RELATIVE";
    }
    else
    {
        LogError("Invalid timecode type:%d", xTimecodeType);
        return "";
    }
}

static int prvGetEpochTimestampInStr(uint64_t uProducerStartTimestampMs, STRING_HANDLE *pxStProducerStartTimestamp)
{
    int res = KVS_ERRNO_NONE;
    uint64_t uProducerStartTimestamp = 0;
    STRING_HANDLE xStProducerStartTimestamp = NULL;

    uProducerStartTimestamp = (uProducerStartTimestampMs == 0) ? getEpochTimestampInMs() : uProducerStartTimestampMs;
    xStProducerStartTimestamp = STRING_construct_sprintf("%." PRIu64 ".%03d", uProducerStartTimestamp / 1000, uProducerStartTimestamp % 1000);

    if (xStProducerStartTimestamp == NULL)
    {
        res = KVS_ERROR_C_UTIL_STRING_ERROR;
    }
    else
    {
        *pxStProducerStartTimestamp = xStProducerStartTimestamp;
    }

    return res;
}

static int prvParseFragmentAckLength(char *pcSrc, size_t uLen, size_t *puMsgLen, size_t *puBytesRead)
{
    int res = KVS_ERRNO_NONE;
    size_t uMsgLen = 0;
    size_t uBytesRead = 0;
    size_t i = 0;
    char c = 0;

    if (pcSrc == NULL || uLen == 0 || puMsgLen == NULL || puBytesRead == NULL)
    {
        res = KVS_ERROR_INVALID_ARGUMENT;
    }
    else
    {
        for (i = 0; i < uLen - 1; i++)
        {
            c = toupper(pcSrc[i]);
            if (isxdigit(c))
            {
                if (c >= '0' && c <= '9')
                {
                    uMsgLen = uMsgLen * 16 + (c - '0');
                }
                else
                {
                    uMsgLen = uMsgLen * 16 + (c - 'A') + 10;
                }
            }
            else if (c == '\r')
            {
                if (pcSrc[i + 1] == '\n')
                {
                    uBytesRead = i + 2;
                    break;
                }
            }
            else
            {
                res = KVS_ERROR_FAIL_TO_PARSE_FRAGMENT_ACK_LENGTH;
            }
        }
    }

    if (res == KVS_ERRNO_NONE)
    {
        if (uBytesRead < 3 || (uBytesRead + uMsgLen + 2) > uLen || pcSrc[uBytesRead + uMsgLen] != '\r' || pcSrc[uBytesRead + uMsgLen + 1] != '\n')
        {
            res = KVS_ERROR_FAIL_TO_PARSE_FRAGMENT_ACK_LENGTH;
        }
        else
        {
            *puMsgLen = uMsgLen;
            *puBytesRead = uBytesRead;
        }
    }

    return res;
}

static ePutMediaFragmentAckEventType prvGetEventType(char *pcEventType)
{
    ePutMediaFragmentAckEventType ev = eUnknown;

    if (pcEventType != NULL)
    {
        if (strncmp(pcEventType, EVENT_TYPE_BUFFERING, sizeof(EVENT_TYPE_BUFFERING) - 1) == 0)
        {
            ev = eBuffering;
        }
        else if (strncmp(pcEventType, EVENT_TYPE_RECEIVED, sizeof(EVENT_TYPE_RECEIVED) - 1) == 0)
        {
            ev = eReceived;
        }
        else if (strncmp(pcEventType, EVENT_TYPE_PERSISTED, sizeof(EVENT_TYPE_PERSISTED) - 1) == 0)
        {
            ev = ePersisted;
        }
        else if (strncmp(pcEventType, EVENT_TYPE_ERROR, sizeof(EVENT_TYPE_ERROR) - 1) == 0)
        {
            ev = eError;
        }
        else if (strncmp(pcEventType, EVENT_TYPE_IDLE, sizeof(EVENT_TYPE_IDLE) - 1) == 0)
        {
            ev = eIdle;
        }
    }

    return ev;
}

static int parseFragmentMsg(const char *pcFragmentMsg, FragmentAck_t *pxFragmentAck)
{
    int res = KVS_ERRNO_NONE;
    JSON_Value *pxRootValue = NULL;
    JSON_Object *pxRootObject = NULL;
    char *pcEventType = NULL;

    json_set_escape_slashes(0);

    if (pcFragmentMsg == NULL || pxFragmentAck == NULL)
    {
        res = KVS_ERROR_INVALID_ARGUMENT;
        LogError("Invalid argument");
    }
    else if ((pxRootValue = json_parse_string(pcFragmentMsg)) == NULL || (pxRootObject = json_value_get_object(pxRootValue)) == NULL)
    {
        res = KVS_ERROR_FAIL_TO_PARSE_FRAGMENT_ACK_MSG;
        LogInfo("Failed to parse fragment msg:%s", pcFragmentMsg);
    }
    else if ((pcEventType = json_object_dotget_serialize_to_string(pxRootObject, JSON_KEY_EVENT_TYPE, false)) == NULL)
    {
        res = KVS_ERROR_UNKNOWN_FRAGMENT_ACK_TYPE;
        LogInfo("Unknown fragment ack:%s", pcFragmentMsg);
    }
    else
    {
        pxFragmentAck->eventType = prvGetEventType(pcEventType);
        kvsFree(pcEventType);

        if (pxFragmentAck->eventType == eBuffering || pxFragmentAck->eventType == eReceived || pxFragmentAck->eventType == ePersisted ||
            pxFragmentAck->eventType == eError)
        {
            pxFragmentAck->uFragmentTimecode = json_object_dotget_uint64(pxRootObject, JSON_KEY_FRAGMENT_TIMECODE, 10);
            if (pxFragmentAck->eventType == eError)
            {
                pxFragmentAck->uErrorId = (unsigned int)json_object_dotget_uint64(pxRootObject, JSON_KEY_ERROR_ID, 10);
            }
        }
    }

    if (pxRootValue != NULL)
    {
        json_value_free(pxRootValue);
    }

    return res;
}

static int prvParseFragmentAck(char *pcSrc, size_t uLen, FragmentAck_t *pxFragAck, size_t *puFragAckLen)
{
    int res = KVS_ERRNO_NONE;
    size_t uMsgLen = 0;
    size_t uBytesRead = 0;
    STRING_HANDLE xStFragMsg = NULL;

    if (pcSrc == NULL || uLen == 0 || pxFragAck == NULL || puFragAckLen == NULL)
    {
        res = KVS_ERROR_INVALID_ARGUMENT;
        LogError("Invalid argument");
    }
    else if ((res = prvParseFragmentAckLength(pcSrc, uLen, &uMsgLen, &uBytesRead)) != KVS_ERRNO_NONE)
    {
        LogInfo("Unknown fragment ack:%.*s", (int)uLen, pcSrc);
        /* Propagate the res error */
    }
    else if ((xStFragMsg = STRING_construct_n(pcSrc + uBytesRead, uMsgLen)) == NULL ||
             parseFragmentMsg(STRING_c_str(xStFragMsg), pxFragAck) != KVS_ERRNO_NONE)
    {
        res = KVS_ERROR_FAIL_TO_PARSE_FRAGMENT_ACK_MSG;
        LogInfo("Failed to parse fragment ack");
    }
    else
    {
        *puFragAckLen = uBytesRead + uMsgLen + 2;
    }

    STRING_delete(xStFragMsg);

    return res;
}

static void prvLogFragmentAck(FragmentAck_t *pFragmentAck)
{
    if (pFragmentAck != NULL)
    {
        if (pFragmentAck->eventType == eBuffering)
        {
            LogInfo("Fragment buffering, timecode:%" PRIu64 "", pFragmentAck->uFragmentTimecode);
        }
        else if (pFragmentAck->eventType == eReceived)
        {
            LogInfo("Fragment received, timecode:%" PRIu64 "", pFragmentAck->uFragmentTimecode);
        }
        else if (pFragmentAck->eventType == ePersisted)
        {
            LogInfo("Fragment persisted, timecode:%" PRIu64 "", pFragmentAck->uFragmentTimecode);
        }
        else if (pFragmentAck->eventType == eError)
        {
            LogError("PutMedia session error id:%d", pFragmentAck->uErrorId);
        }
        else if (pFragmentAck->eventType == eIdle)
        {
            LogInfo("PutMedia session Idle");
        }
        else
        {
            LogInfo("Unknown Fragment Ack");
        }
    }
}

static void prvLogPendingFragmentAcks(PutMedia_t *pPutMedia)
{
    PDLIST_ENTRY pxListHead = NULL;
    PDLIST_ENTRY pxListItem = NULL;
    FragmentAck_t *pFragmentAck = NULL;
    int ret = 0;

    if (pPutMedia != NULL && !(ret = k_mutex_lock(pPutMedia->xLockMutex, K_FOREVER)))//Lock(pPutMedia->xLock) == LOCK_OK)
    {
        pxListHead = &(pPutMedia->xPendingFragmentAcks);
        pxListItem = pxListHead->Flink;
        while (pxListItem != pxListHead)
        {
            pFragmentAck = containingRecord(pxListItem, FragmentAck_t, xAckEntry);
            prvLogFragmentAck(pFragmentAck);

            pxListItem = pxListItem->Flink;
        }

        //Unlock(pPutMedia->xLock);
        k_mutex_unlock((pPutMedia->xLockMutex));
    }
    if (ret == -EBUSY || ret == -EAGAIN) {
        LogError("mutex failed to lock with valid response: %d", ret);
    } else if (ret != 0) {
        LogError("mutex failed to lock with error: %d", ret);
    }
}

static int prvPushFragmentAck(PutMedia_t *pPutMedia, FragmentAck_t *pFragmentAckSrc)
{
    int res = KVS_ERRNO_NONE;
    FragmentAck_t *pFragmentAck = NULL;
    int ret = 0;

    if (pPutMedia == NULL || pFragmentAckSrc == NULL)
    {
        res = KVS_ERROR_INVALID_ARGUMENT;
    }
    else if ((pFragmentAck = (FragmentAck_t *)kvsMalloc(sizeof(FragmentAck_t))) == NULL)
    {
        res = KVS_ERROR_OUT_OF_MEMORY;
    }
    else
    {
        memcpy(pFragmentAck, pFragmentAckSrc, sizeof(FragmentAck_t));
        DList_InitializeListHead(&(pFragmentAck->xAckEntry));

        if (ret = k_mutex_lock(pPutMedia->xLockMutex, K_FOREVER))//Lock(pPutMedia->xLock) != LOCK_OK)
        {
            LOG_ERR("Failed to lock mutex with error: %d", ret);
            res = KVS_ERROR_LOCK_ERROR;
        }
        else
        {
            DList_InsertTailList(&(pPutMedia->xPendingFragmentAcks), &(pFragmentAck->xAckEntry));

            //Unlock(pPutMedia->xLock);
            k_mutex_unlock((pPutMedia->xLockMutex));
        }
    }

    if (res != KVS_ERRNO_NONE)
    {
        if (pFragmentAck != NULL)
        {
            kvsFree(pFragmentAck);
        }
    }

    return res;
}

static PutMedia_t *prvCreateDefaultPutMediaHandle()
{
    int res = KVS_ERRNO_NONE;
    PutMedia_t *pPutMedia = NULL;

    if ((pPutMedia = (PutMedia_t *)kvsMalloc(sizeof(PutMedia_t))) == NULL)
    {
        res = KVS_ERROR_OUT_OF_MEMORY;
        LogError("OOM: pPutMedia");
    }
    else
    {
        memset(pPutMedia, 0, sizeof(PutMedia_t));
        pPutMedia->xLockMutex = &wrapper_mutex;

        if (k_mutex_init((pPutMedia->xLockMutex)))//(pPutMedia->xLock = Lock_Init()) == NULL)
        {
            res = KVS_ERROR_LOCK_ERROR;
            LogError("Failed to initialize lock");
        }
        else
        {
            DList_InitializeListHead(&(pPutMedia->xPendingFragmentAcks));
        }
    }

    if (res != KVS_ERRNO_NONE)
    {
        if (pPutMedia != NULL)
        {
            // if (pPutMedia->xLock != NULL)
            // {
            //     Lock_Deinit(pPutMedia->xLock);
            // }
            kvsFree(pPutMedia);
            pPutMedia = NULL;
        }
    }

    return pPutMedia;
}

static FragmentAck_t *prvReadFragmentAck(PutMedia_t *pPutMedia)
{
    int res = KVS_ERRNO_NONE;
    PDLIST_ENTRY pxListHead = NULL;
    PDLIST_ENTRY pxListItem = NULL;
    FragmentAck_t *pFragmentAck = NULL;
    int ret = 0;

    if (!(ret = k_mutex_lock(pPutMedia->xLockMutex, K_FOREVER)))//Lock(pPutMedia->xLock) == LOCK_OK)
    {
        if (!DList_IsListEmpty(&(pPutMedia->xPendingFragmentAcks)))
        {
            pxListHead = &(pPutMedia->xPendingFragmentAcks);
            pxListItem = DList_RemoveHeadList(pxListHead);
            pFragmentAck = containingRecord(pxListItem, FragmentAck_t, xAckEntry);
        }
        //Unlock(pPutMedia->xLock);
        k_mutex_unlock(pPutMedia->xLockMutex);
    } else {
        LogError("Failed to lock mutex with error: %d", ret);
    }

    return pFragmentAck;
}

static void prvFlushFragmentAck(PutMedia_t *pPutMedia)
{
    FragmentAck_t *pFragmentAck = NULL;
    while ((pFragmentAck = prvReadFragmentAck(pPutMedia)) != NULL)
    {
        kvsFree(pFragmentAck);
    }
}

int Kvs_describeStream(KvsServiceParameter_t *pServPara, KvsDescribeStreamParameter_t *pDescPara, unsigned int *puHttpStatusCode)
{
    int res = KVS_ERRNO_NONE;

    STRING_HANDLE xStHttpBody = NULL;
    STRING_HANDLE xStContentLength = NULL;
    char pcXAmzDate[DATE_TIME_ISO_8601_FORMAT_STRING_SIZE] = {0};

    AwsSigV4Handle xAwsSigV4Handle = NULL;

    unsigned int uHttpStatusCode = 0;
    HTTP_HEADERS_HANDLE xHttpReqHeaders = NULL;
    char *pRspBody = NULL;
    size_t uRspBodyLen = 0;

    NetIoHandle xNetIoHandle = NULL;

    LOG_DBG("token before describeStream: %s %d", pServPara->pcAccessKey, strlen(pServPara->pcAccessKey));

    if (puHttpStatusCode != NULL)
    {
        *puHttpStatusCode = 0; /* Set to zero to avoid misuse from the previous value. */
    }

    if ((res = prvValidateServiceParameter(pServPara)) != KVS_ERRNO_NONE ||
        (res = prvValidateDescribeStreamParameter(pDescPara)) != KVS_ERRNO_NONE)
    {
        LogError("Invalid argument");
        /* Propagate the res error */
    }
    else if ((res = getTimeInIso8601(pcXAmzDate, sizeof(pcXAmzDate))) != KVS_ERRNO_NONE)
    {
        LogError("Failed to get time");
        /* Propagate the res error */
    }
    else if (
        (xStHttpBody = STRING_construct_sprintf(DESCRIBE_STREAM_HTTP_BODY_TEMPLATE, pDescPara->pcStreamName)) == NULL ||
        (xStContentLength = STRING_construct_sprintf("%u", STRING_length(xStHttpBody))) == NULL)
    {
        res = KVS_ERROR_UNABLE_TO_ALLOCATE_HTTP_BODY;
        LogError("Failed to allocate HTTP body");
    }
    else if (
        (xHttpReqHeaders = HTTPHeaders_Alloc()) == NULL ||   
        HTTPHeaders_AddHeaderNameValuePair(xHttpReqHeaders, HDR_HOST, pServPara->pcHost) != HTTP_HEADERS_OK ||
        HTTPHeaders_AddHeaderNameValuePair(xHttpReqHeaders, HDR_ACCEPT, VAL_ACCEPT_ANY) != HTTP_HEADERS_OK ||
        HTTPHeaders_AddHeaderNameValuePair(xHttpReqHeaders, HDR_CONTENT_LENGTH, STRING_c_str(xStContentLength)) != HTTP_HEADERS_OK ||
        HTTPHeaders_AddHeaderNameValuePair(xHttpReqHeaders, HDR_CONTENT_TYPE, VAL_CONTENT_TYPE_APPLICATION_jSON) != HTTP_HEADERS_OK ||
        HTTPHeaders_AddHeaderNameValuePair(xHttpReqHeaders, HDR_USER_AGENT, VAL_USER_AGENT) != HTTP_HEADERS_OK ||
        HTTPHeaders_AddHeaderNameValuePair(xHttpReqHeaders, HDR_X_AMZ_DATE, pcXAmzDate) != HTTP_HEADERS_OK ||
        (pServPara->pcToken != NULL && (HTTPHeaders_AddHeaderNameValuePair(xHttpReqHeaders, HDR_X_AMZ_SECURITY_TOKEN, pServPara->pcToken) != HTTP_HEADERS_OK)))
    {
        res = KVS_ERROR_UNABLE_TO_GENERATE_HTTP_HEADER;
        LogError("Failed to generate HTTP headers");
    }
    else if (
        (xAwsSigV4Handle = prvSign(pServPara, KVS_URI_DESCRIBE_STREAM, URI_QUERY_EMPTY, xHttpReqHeaders, STRING_c_str(xStHttpBody))) == NULL ||
        HTTPHeaders_AddHeaderNameValuePair(xHttpReqHeaders, HDR_AUTHORIZATION, AwsSigV4_GetAuthorization(xAwsSigV4Handle)) != HTTP_HEADERS_OK)
    {
        res = KVS_ERROR_FAIL_TO_SIGN_HTTP_REQ;
        LogError("Failed to sign");
    }
    else if ((xNetIoHandle = NetIo_create()) == NULL)
    {
        res = KVS_ERROR_FAIL_TO_CREATE_NETIO_HANDLE;
        LogError("Failed to create NetIo handle");
    }
    // else if ((res = NetIo_setRecvTimeout(xNetIoHandle, pServPara->uRecvTimeoutMs)) != KVS_ERRNO_NONE)
    // {
    //     LogError("Failed to connect to %s", pServPara->pcHost);
    //     /* Propagate the res error */
    // }
    // else if ((res = NetIo_setSendTimeout(xNetIoHandle, pServPara->uSendTimeoutMs)) != KVS_ERRNO_NONE)
    // {
    //     LogError("Failed to connect to %s", pServPara->pcHost);
    //     /* Propagate the res error */
    // }
    else if ((res = NetIo_connect(xNetIoHandle, pServPara->pcHost, PORT_HTTPS)) != KVS_ERRNO_NONE)
    {
        LogError("Failed to connect to %s", pServPara->pcHost);
        /* Propagate the res error */
    }
    else if ((res = Http_executeHttpReq(xNetIoHandle, HTTP_METHOD_POST, KVS_URI_DESCRIBE_STREAM, xHttpReqHeaders, STRING_c_str(xStHttpBody))) != KVS_ERRNO_NONE)
    {
        LogError("Failed send http request to %s", pServPara->pcHost);
        /* Propagate the res error */
    }
    else if ((res = Http_recvHttpRsp(xNetIoHandle, &uHttpStatusCode, &pRspBody, &uRspBodyLen)) != KVS_ERRNO_NONE)
    {
        LogError("Failed recv http response from %s", pServPara->pcHost);
        /* Propagate the res error */
    }
    else
    {
        if (puHttpStatusCode != NULL)
        {
            *puHttpStatusCode = uHttpStatusCode;
        }

        if (uHttpStatusCode != 200)
        {
            res = KVS_ERRNO_FAIL; // TODO - need to define error code
            // LogInfo("Describe Stream failed, HTTP status code: %u", uHttpStatusCode);
            LOG_WRN("Describe Stream failed, HTTP status code: %u", uHttpStatusCode);
            LogInfo("HTTP response message:%.*s", (int)uRspBodyLen, pRspBody);
        } else {
            // LogInfo("Describe Stream success, HTTP status code: %u", uHttpStatusCode);
            LOG_INF("Describe Stream success, HTTP status code: %u", uHttpStatusCode);
            LogInfo("HTTP response message:%.*s", (int)uRspBodyLen, pRspBody);
        }
    }

    NetIo_disconnect(xNetIoHandle);
    NetIo_terminate(xNetIoHandle);
    SAFE_FREE(pRspBody);
    HTTPHeaders_Free(xHttpReqHeaders);
    AwsSigV4_Terminate(xAwsSigV4Handle);
    STRING_delete(xStContentLength);
    STRING_delete(xStHttpBody);

    return res;
}

int Kvs_createStream(KvsServiceParameter_t *pServPara, KvsCreateStreamParameter_t *pCreatePara, unsigned int *puHttpStatusCode)
{
    int res = KVS_ERRNO_NONE;

    STRING_HANDLE xStHttpBody = NULL;
    STRING_HANDLE xStContentLength = NULL;
    char pcXAmzDate[DATE_TIME_ISO_8601_FORMAT_STRING_SIZE] = {0};

    AwsSigV4Handle xAwsSigV4Handle = NULL;

    unsigned int uHttpStatusCode = 0;
    HTTP_HEADERS_HANDLE xHttpReqHeaders = NULL;
    char *pRspBody = NULL;
    size_t uRspBodyLen = 0;

    NetIoHandle xNetIoHandle = NULL;

    if (puHttpStatusCode != NULL)
    {
        *puHttpStatusCode = 0; /* Set to zero to avoid misuse from previous value. */
    }

    if ((res = prvValidateServiceParameter(pServPara)) != KVS_ERRNO_NONE ||
        (res = prvValidateCreateStreamParameter(pCreatePara)) != KVS_ERRNO_NONE)
    {
        LogError("Invalid argument");
        /* Propagate the res error */
    }
    else if ((res = getTimeInIso8601(pcXAmzDate, sizeof(pcXAmzDate))) != KVS_ERRNO_NONE)
    {
        LogError("Failed to get time");
        /* Propagate the res error */
    }
    else if (
        (xStHttpBody = STRING_construct_sprintf(CREATE_STREAM_HTTP_BODY_TEMPLATE, pCreatePara->pcStreamName, pCreatePara->uDataRetentionInHours)) == NULL ||
        (xStContentLength = STRING_construct_sprintf("%u", STRING_length(xStHttpBody))) == NULL)
    {
        res = KVS_ERROR_UNABLE_TO_ALLOCATE_HTTP_BODY;
        LogError("Failed to allocate HTTP body");
    }
    else if (
        (xHttpReqHeaders = HTTPHeaders_Alloc()) == NULL ||
        HTTPHeaders_AddHeaderNameValuePair(xHttpReqHeaders, HDR_HOST, pServPara->pcHost) != HTTP_HEADERS_OK ||
        HTTPHeaders_AddHeaderNameValuePair(xHttpReqHeaders, HDR_ACCEPT, VAL_ACCEPT_ANY) != HTTP_HEADERS_OK ||
        HTTPHeaders_AddHeaderNameValuePair(xHttpReqHeaders, HDR_CONTENT_LENGTH, STRING_c_str(xStContentLength)) != HTTP_HEADERS_OK ||
        HTTPHeaders_AddHeaderNameValuePair(xHttpReqHeaders, HDR_CONTENT_TYPE, VAL_CONTENT_TYPE_APPLICATION_jSON) != HTTP_HEADERS_OK ||
        HTTPHeaders_AddHeaderNameValuePair(xHttpReqHeaders, HDR_USER_AGENT, VAL_USER_AGENT) != HTTP_HEADERS_OK ||
        HTTPHeaders_AddHeaderNameValuePair(xHttpReqHeaders, HDR_X_AMZ_DATE, pcXAmzDate) != HTTP_HEADERS_OK ||
        (pServPara->pcToken != NULL && (HTTPHeaders_AddHeaderNameValuePair(xHttpReqHeaders, HDR_X_AMZ_SECURITY_TOKEN, pServPara->pcToken) != HTTP_HEADERS_OK)))
    {
        res = KVS_ERROR_UNABLE_TO_GENERATE_HTTP_HEADER;
        LogError("Failed to generate HTTP headers");
    }
    else if (
        (xAwsSigV4Handle = prvSign(pServPara, KVS_URI_CREATE_STREAM, URI_QUERY_EMPTY, xHttpReqHeaders, STRING_c_str(xStHttpBody))) == NULL ||
        HTTPHeaders_AddHeaderNameValuePair(xHttpReqHeaders, HDR_AUTHORIZATION, AwsSigV4_GetAuthorization(xAwsSigV4Handle)) != HTTP_HEADERS_OK)
    {
        LogError("Failed to sign");
        res = KVS_ERROR_FAIL_TO_SIGN_HTTP_REQ;
    }
    else if ((xNetIoHandle = NetIo_create()) == NULL)
    {
        res = KVS_ERROR_FAIL_TO_CREATE_NETIO_HANDLE;
        LogError("Failed to create NetIo handle");
    }
    else if (
        (res = NetIo_setRecvTimeout(xNetIoHandle, pServPara->uRecvTimeoutMs)) != KVS_ERRNO_NONE ||
        (res = NetIo_setSendTimeout(xNetIoHandle, pServPara->uSendTimeoutMs)) != KVS_ERRNO_NONE ||
        (res = NetIo_connect(xNetIoHandle, pServPara->pcHost, PORT_HTTPS)) != KVS_ERRNO_NONE)
    {
        LogError("Failed to connect to %s", pServPara->pcHost);
        /* Propagate the res error */
    }
    else if ((res = Http_executeHttpReq(xNetIoHandle, HTTP_METHOD_POST, KVS_URI_CREATE_STREAM, xHttpReqHeaders, STRING_c_str(xStHttpBody))) != KVS_ERRNO_NONE)
    {
        LogError("Failed send http request to %s", pServPara->pcHost);
        /* Propagate the res error */
    }
    else if ((res = Http_recvHttpRsp(xNetIoHandle, &uHttpStatusCode, &pRspBody, &uRspBodyLen)) != KVS_ERRNO_NONE)
    {
        LogError("Failed recv http response from %s", pServPara->pcHost);
        /* Propagate the res error */
    }
    else
    {
        if (puHttpStatusCode != NULL)
        {
            *puHttpStatusCode = uHttpStatusCode;
        }

        if (uHttpStatusCode != 200)
        {
            LogInfo("Create Stream failed, HTTP status code: %u", uHttpStatusCode);
            LogInfo("HTTP response message:%.*s", (int)uRspBodyLen, pRspBody);
        } else {
          LOG_DBG("Create Stream success, HTTP status code: %u", uHttpStatusCode);
          LOG_DBG("HTTP response message:%.*s", (int)uRspBodyLen, pRspBody);
        }
    }

    NetIo_disconnect(xNetIoHandle);
    NetIo_terminate(xNetIoHandle);
    SAFE_FREE(pRspBody);
    HTTPHeaders_Free(xHttpReqHeaders);
    AwsSigV4_Terminate(xAwsSigV4Handle);
    STRING_delete(xStContentLength);
    STRING_delete(xStHttpBody);

    return res;
}

int Kvs_getDataEndpoint(KvsServiceParameter_t *pServPara, KvsGetDataEndpointParameter_t *pGetDataEpPara, unsigned int *puHttpStatusCode, char **ppcDataEndpoint)
{
    int res = KVS_ERRNO_NONE;

    STRING_HANDLE xStHttpBody = NULL;
    STRING_HANDLE xStContentLength = NULL;
    char pcXAmzDate[DATE_TIME_ISO_8601_FORMAT_STRING_SIZE] = {0};

    AwsSigV4Handle xAwsSigV4Handle = NULL;

    unsigned int uHttpStatusCode = 0;
    HTTP_HEADERS_HANDLE xHttpReqHeaders = NULL;
    char *pRspBody = NULL;
    size_t uRspBodyLen = 0;

    NetIoHandle xNetIoHandle = NULL;

    LOG_DBG("token before getDataEndpoint: %s %d, %s %d", pServPara->pcAccessKey, strlen(pServPara->pcAccessKey), pServPara->pcToken, strlen(pServPara->pcToken));

    if (puHttpStatusCode != NULL)
    {
        *puHttpStatusCode = 0; /* Set to zero to avoid misuse from previous value. */
    }

    if ((res = prvValidateServiceParameter(pServPara)) != KVS_ERRNO_NONE ||
        (res = prvValidateGetDataEndpointParameter(pGetDataEpPara)) != KVS_ERRNO_NONE)
    {
        LogError("Invalid argument");
        /* Propagate the res error */
    }
    else if ((res = getTimeInIso8601(pcXAmzDate, sizeof(pcXAmzDate))) != KVS_ERRNO_NONE)
    {
        LogError("Failed to get time");
        /* Propagate the res error */
    }
    else if (
        (xStHttpBody = STRING_construct_sprintf(GET_DATA_ENDPOINT_HTTP_BODY_TEMPLATE, pGetDataEpPara->pcStreamName)) == NULL ||
        (xStContentLength = STRING_construct_sprintf("%u", STRING_length(xStHttpBody))) == NULL)
    {
        res = KVS_ERROR_UNABLE_TO_ALLOCATE_HTTP_BODY;
        LogError("Failed to allocate HTTP body");
    }
    else if (
        (xHttpReqHeaders = HTTPHeaders_Alloc()) == NULL ||
        HTTPHeaders_AddHeaderNameValuePair(xHttpReqHeaders, HDR_HOST, pServPara->pcHost) != HTTP_HEADERS_OK ||
        HTTPHeaders_AddHeaderNameValuePair(xHttpReqHeaders, HDR_ACCEPT, VAL_ACCEPT_ANY) != HTTP_HEADERS_OK ||
        HTTPHeaders_AddHeaderNameValuePair(xHttpReqHeaders, HDR_CONTENT_LENGTH, STRING_c_str(xStContentLength)) != HTTP_HEADERS_OK ||
        HTTPHeaders_AddHeaderNameValuePair(xHttpReqHeaders, HDR_CONTENT_TYPE, VAL_CONTENT_TYPE_APPLICATION_jSON) != HTTP_HEADERS_OK ||
        HTTPHeaders_AddHeaderNameValuePair(xHttpReqHeaders, HDR_USER_AGENT, VAL_USER_AGENT) != HTTP_HEADERS_OK ||
        HTTPHeaders_AddHeaderNameValuePair(xHttpReqHeaders, HDR_X_AMZ_DATE, pcXAmzDate) != HTTP_HEADERS_OK ||
        (pServPara->pcToken != NULL && (HTTPHeaders_AddHeaderNameValuePair(xHttpReqHeaders, HDR_X_AMZ_SECURITY_TOKEN, pServPara->pcToken) != HTTP_HEADERS_OK)))
    {
        res = KVS_ERROR_UNABLE_TO_GENERATE_HTTP_HEADER;
        LogError("Failed to generate HTTP headers");
    }
    else if (
        (xAwsSigV4Handle = prvSign(pServPara, KVS_URI_GET_DATA_ENDPOINT, URI_QUERY_EMPTY, xHttpReqHeaders, STRING_c_str(xStHttpBody))) == NULL ||
        HTTPHeaders_AddHeaderNameValuePair(xHttpReqHeaders, HDR_AUTHORIZATION, AwsSigV4_GetAuthorization(xAwsSigV4Handle)) != HTTP_HEADERS_OK)
    {
        res = KVS_ERROR_FAIL_TO_SIGN_HTTP_REQ;
        LogError("Failed to sign");
    }
    else if ((xNetIoHandle = NetIo_create()) == NULL)
    {
        res = KVS_ERROR_FAIL_TO_CREATE_NETIO_HANDLE;
        LogError("Failed to create NetIo handle");
    }
    else if (
        // (res = NetIo_setRecvTimeout(xNetIoHandle, pServPara->uRecvTimeoutMs)) != KVS_ERRNO_NONE ||
        // (res = NetIo_setSendTimeout(xNetIoHandle, pServPara->uSendTimeoutMs)) != KVS_ERRNO_NONE ||
        (res = NetIo_connect(xNetIoHandle, pServPara->pcHost, PORT_HTTPS)) != KVS_ERRNO_NONE)
    {
        LogError("Failed to connect to %s", pServPara->pcHost);
        /* Propagate the res error */
    }
    else if ((res = Http_executeHttpReq(xNetIoHandle, HTTP_METHOD_POST, KVS_URI_GET_DATA_ENDPOINT, xHttpReqHeaders, STRING_c_str(xStHttpBody))) != KVS_ERRNO_NONE)
    {
        LogError("Failed send http request to %s", pServPara->pcHost);
        /* Propagate the res error */
    }
    else if ((res = Http_recvHttpRsp(xNetIoHandle, &uHttpStatusCode, &pRspBody, &uRspBodyLen)) != KVS_ERRNO_NONE)
    {
        LogError("Failed recv http response from %s", pServPara->pcHost);
        /* Propagate the res error */
    }
    else
    {
        if (puHttpStatusCode != NULL)
        {
            *puHttpStatusCode = uHttpStatusCode;
        }

        if (uHttpStatusCode != 200)
        {
            LogError("Get Data Endpoint failed, HTTP status code: %u", uHttpStatusCode);
            LogInfo("HTTP response message:%.*s", (int)uRspBodyLen, pRspBody);
        }
        else
        {
            if ((res = prvParseDataEndpoint(pRspBody, uRspBodyLen, ppcDataEndpoint)) != KVS_ERRNO_NONE)
            {
                LogError("Failed to parse data endpoint");
                /* Propagate the res error */
            }
        }
    }

    NetIo_disconnect(xNetIoHandle);
    NetIo_terminate(xNetIoHandle);
    SAFE_FREE(pRspBody);
    HTTPHeaders_Free(xHttpReqHeaders);
    AwsSigV4_Terminate(xAwsSigV4Handle);
    STRING_delete(xStContentLength);
    STRING_delete(xStHttpBody);

    return res;
}

int Kvs_putMediaStart(KvsServiceParameter_t *pServPara, KvsPutMediaParameter_t *pPutMediaPara, unsigned int *puHttpStatusCode, PutMediaHandle *pPutMediaHandle)
{
    int res = KVS_ERRNO_NONE;
    PutMedia_t *pPutMedia = NULL;

    char pcXAmzDate[DATE_TIME_ISO_8601_FORMAT_STRING_SIZE] = {0};
    STRING_HANDLE xStProducerStartTimestamp = NULL;


    AwsSigV4Handle xAwsSigV4Handle = NULL;

    unsigned int uHttpStatusCode = 0;
    HTTP_HEADERS_HANDLE xHttpReqHeaders = NULL;
    char *pRspBody = NULL;
    size_t uRspBodyLen = 0;

    NetIoHandle xNetIoHandle = NULL;
    bool bKeepNetIo = false;

    if (puHttpStatusCode != NULL)
    {
        *puHttpStatusCode = 0; /* Set to zero to avoid misuse from previous value. */
    }

    if ((res = prvValidateServiceParameter(pServPara)) != KVS_ERRNO_NONE ||
        (res = prvValidatePutMediaParameter(pPutMediaPara)) != KVS_ERRNO_NONE)
    {
        LogError("Invalid argument - pServPara:%p, pPutMediaPara:%p", pServPara, pPutMediaPara);
        /* Propagate the res error */
    }
    else if (pPutMediaHandle == NULL)
    {
        res = KVS_ERROR_INVALID_ARGUMENT;
        LogError("Invalid argument - pPutMediaHandle is NULL");
    }
    else if ((res = getTimeInIso8601(pcXAmzDate, sizeof(pcXAmzDate))) != KVS_ERRNO_NONE)
    {
        LogError("Failed to get time");
        /* Propagate the res error */
    }
    else if ((res = prvGetEpochTimestampInStr(pPutMediaPara->uProducerStartTimestampMs, &xStProducerStartTimestamp)) != KVS_ERRNO_NONE)
    {
        LogError("Failed to get epoch time");
        /* Propagate the res error */
    }
    else if (
        (xHttpReqHeaders = HTTPHeaders_Alloc()) == NULL ||
        HTTPHeaders_AddHeaderNameValuePair(xHttpReqHeaders, HDR_HOST, pServPara->pcPutMediaEndpoint) != HTTP_HEADERS_OK ||
        HTTPHeaders_AddHeaderNameValuePair(xHttpReqHeaders, HDR_ACCEPT, VAL_ACCEPT_ANY) != HTTP_HEADERS_OK ||
        HTTPHeaders_AddHeaderNameValuePair(xHttpReqHeaders, HDR_CONNECTION, VAL_KEEP_ALIVE) != HTTP_HEADERS_OK ||
        HTTPHeaders_AddHeaderNameValuePair(xHttpReqHeaders, HDR_CONTENT_TYPE, VAL_CONTENT_TYPE_APPLICATION_jSON) != HTTP_HEADERS_OK ||
        HTTPHeaders_AddHeaderNameValuePair(xHttpReqHeaders, HDR_TRANSFER_ENCODING, VAL_TRANSFER_ENCODING_CHUNKED) != HTTP_HEADERS_OK ||
        HTTPHeaders_AddHeaderNameValuePair(xHttpReqHeaders, HDR_USER_AGENT, VAL_USER_AGENT) != HTTP_HEADERS_OK ||
        HTTPHeaders_AddHeaderNameValuePair(xHttpReqHeaders, HDR_X_AMZ_DATE, pcXAmzDate) != HTTP_HEADERS_OK ||
        (pServPara->pcToken != NULL && (HTTPHeaders_AddHeaderNameValuePair(xHttpReqHeaders, HDR_X_AMZ_SECURITY_TOKEN, pServPara->pcToken) != HTTP_HEADERS_OK)) ||
        HTTPHeaders_AddHeaderNameValuePair(xHttpReqHeaders, HDR_X_AMZN_FRAG_ACK_REQUIRED, VAL_FRAGMENT_ACK_REQUIRED_TRUE) != HTTP_HEADERS_OK ||
        HTTPHeaders_AddHeaderNameValuePair(xHttpReqHeaders, HDR_X_AMZN_FRAG_T_TYPE, prvGetTimecodeValue(pPutMediaPara->xTimecodeType)) != HTTP_HEADERS_OK ||
        HTTPHeaders_AddHeaderNameValuePair(xHttpReqHeaders, HDR_X_AMZN_PRODUCER_START_T, STRING_c_str(xStProducerStartTimestamp)) != HTTP_HEADERS_OK ||
        HTTPHeaders_AddHeaderNameValuePair(xHttpReqHeaders, HDR_X_AMZN_STREAM_NAME, pPutMediaPara->pcStreamName) != HTTP_HEADERS_OK ||
        HTTPHeaders_AddHeaderNameValuePair(xHttpReqHeaders, "expect", "100-continue") != HTTP_HEADERS_OK)
    {
        res = KVS_ERROR_UNABLE_TO_GENERATE_HTTP_HEADER;
        LogError("Failed to generate HTTP headers");
    }
    else if (
        (xAwsSigV4Handle = prvSign(pServPara, KVS_URI_PUT_MEDIA, URI_QUERY_EMPTY, xHttpReqHeaders, HTTP_BODY_EMPTY)) == NULL ||
        HTTPHeaders_AddHeaderNameValuePair(xHttpReqHeaders, HDR_AUTHORIZATION, AwsSigV4_GetAuthorization(xAwsSigV4Handle)) != HTTP_HEADERS_OK)
    {
        res = KVS_ERROR_FAIL_TO_SIGN_HTTP_REQ;
        LogError("Failed to sign");
    }
    else if ((xNetIoHandle = NetIo_create()) == NULL)
    {
        res = KVS_ERROR_FAIL_TO_CREATE_NETIO_HANDLE;
        LogError("Failed to create NetIo handle");
    }
    else if (
        (res = NetIo_setRecvTimeout(xNetIoHandle, pServPara->uRecvTimeoutMs)) != KVS_ERRNO_NONE ||
        (res = NetIo_setSendTimeout(xNetIoHandle, pServPara->uSendTimeoutMs)) != KVS_ERRNO_NONE ||
        (res = NetIo_connect(xNetIoHandle, pServPara->pcPutMediaEndpoint, PORT_HTTPS)) != KVS_ERRNO_NONE)
    {
        LogError("Failed to connect to %s", pServPara->pcPutMediaEndpoint);
        /* Propagate the res error */
    }
    else if ((res = Http_executeHttpReq(xNetIoHandle, HTTP_METHOD_POST, KVS_URI_PUT_MEDIA, xHttpReqHeaders, HTTP_BODY_EMPTY)) != KVS_ERRNO_NONE)
    {
        LogError("Failed send http request to %s", pServPara->pcHost);
        /* Propagate the res error */
    }
    else if ((res = Http_recvHttpRsp(xNetIoHandle, &uHttpStatusCode, &pRspBody, &uRspBodyLen)) != KVS_ERRNO_NONE)
    {
        LogError("Failed recv http response from %s", pServPara->pcHost);
        /* Propagate the res error */
    }
    else
    {
        if (puHttpStatusCode != NULL)
        {
            *puHttpStatusCode = uHttpStatusCode;
        }

        if (uHttpStatusCode != 200)
        {
            LogInfo("Put Media failed, HTTP status code: %u", uHttpStatusCode);
            LogInfo("HTTP response message:%.*s", (int)uRspBodyLen, pRspBody);
        }
        else
        {
            if ((pPutMedia = prvCreateDefaultPutMediaHandle()) == NULL)
            {
                res = KVS_ERROR_FAIL_TO_CREATE_PUT_MEDIA_HANDLE;
                LogError("Failed to create pPutMedia");
            }
            else
            {
                /* Change network I/O receiving timeout for streaming purpose. */
                NetIo_setRecvTimeout(xNetIoHandle, pPutMediaPara->uRecvTimeoutMs);
                NetIo_setSendTimeout(xNetIoHandle, pPutMediaPara->uSendTimeoutMs);

                pPutMedia->xNetIoHandle = xNetIoHandle;
                *pPutMediaHandle = pPutMedia;
                bKeepNetIo = true;
            }
        }
    }

    if (!bKeepNetIo)
    {
        NetIo_disconnect(xNetIoHandle);
        NetIo_terminate(xNetIoHandle);
    }
    SAFE_FREE(pRspBody);
    HTTPHeaders_Free(xHttpReqHeaders);
    AwsSigV4_Terminate(xAwsSigV4Handle);
    STRING_delete(xStProducerStartTimestamp);

    return res;
}

int Kvs_putMediaUpdate(PutMediaHandle xPutMediaHandle, uint8_t *pMkvHeader, size_t uMkvHeaderLen, uint8_t *pData, size_t uDataLen)
{
    int res = KVS_ERRNO_NONE;
    PutMedia_t *pPutMedia = xPutMediaHandle;
    int xChunkedHeaderLen = 0;
    char pcChunkedHeader[sizeof(size_t) * 2 + 3];
    const char *pcChunkedEnd = "\r\n";

    if (pData == NULL)
    {
        uDataLen = 0;
    }

    if (pPutMedia == NULL || pMkvHeader == NULL || uMkvHeaderLen == 0)
    {
        res = KVS_ERROR_INVALID_ARGUMENT;
        LogError("Invalid argument");
    }
    else
    {
        xChunkedHeaderLen = snprintf(pcChunkedHeader, sizeof(pcChunkedHeader), "%lx\r\n", (unsigned long)(uMkvHeaderLen + uDataLen));
        if (xChunkedHeaderLen <= 0)
        {
            res = KVS_ERROR_C_UTIL_STRING_ERROR;
            LogError("Failed to init chunk size");
        }
        else
        {
            if ((res = NetIo_send(pPutMedia->xNetIoHandle, (const unsigned char *)pcChunkedHeader, (size_t)xChunkedHeaderLen)) != KVS_ERRNO_NONE ||
                (res = NetIo_send(pPutMedia->xNetIoHandle, pMkvHeader, uMkvHeaderLen)) != KVS_ERRNO_NONE ||
                (pData != NULL && uDataLen > 0 && (res = NetIo_send(pPutMedia->xNetIoHandle, pData, uDataLen)) != KVS_ERRNO_NONE) ||
                (res = NetIo_send(pPutMedia->xNetIoHandle, (const unsigned char *)pcChunkedEnd, strlen(pcChunkedEnd))) != KVS_ERRNO_NONE)
            {
                LogError("Failed to send data frame");
                /* Propagate the res error */
            }
            else
            {
                /* nop */
            }
        }
    }

    return res;
}

int Kvs_putMediaUpdateRaw(PutMediaHandle xPutMediaHandle, uint8_t *pBuf, size_t uLen)
{
    int res = KVS_ERRNO_NONE;
    PutMedia_t *pPutMedia = xPutMediaHandle;
    int xChunkedHeaderLen = 0;
    char pcChunkedHeader[sizeof(size_t) * 2 + 3];
    const char *pcChunkedEnd = "\r\n";

    if (pPutMedia == NULL || pBuf == NULL || uLen == 0)
    {
        res = KVS_ERROR_INVALID_ARGUMENT;
        LogError("Invalid argument");
    }
    else
    {
        xChunkedHeaderLen = snprintf(pcChunkedHeader, sizeof(pcChunkedHeader), "%lx\r\n", (unsigned long)uLen);
        if (xChunkedHeaderLen <= 0)
        {
            res = KVS_ERROR_C_UTIL_STRING_ERROR;
            LogError("Failed to init chunk size");
        }
        else
        {
            if ((res = NetIo_send(pPutMedia->xNetIoHandle, (const unsigned char *)pcChunkedHeader, (size_t)xChunkedHeaderLen)) != KVS_ERRNO_NONE ||
                (res = NetIo_send(pPutMedia->xNetIoHandle, pBuf, uLen)) != KVS_ERRNO_NONE ||
                (res = NetIo_send(pPutMedia->xNetIoHandle, (const unsigned char *)pcChunkedEnd, strlen(pcChunkedEnd))) != KVS_ERRNO_NONE)
            {
                LogError("Failed to send data frame");
                /* Propagate the res error */
            }
            else
            {
                /* nop */
            }
        }
    }

    return res;
}

int Kvs_putMediaDoWork(PutMediaHandle xPutMediaHandle)
{
    int res = KVS_ERRNO_NONE;
    PutMedia_t *pPutMedia = xPutMediaHandle;
    BUFFER_HANDLE xBufRecv = NULL;
    size_t uBytesTotalReceived = 0;
    size_t uBytesReceived = 0;
    FragmentAck_t xFragmentAck = {0};
    size_t uFragAckLen = 0;

    if (pPutMedia == NULL)
    {
        res = KVS_ERROR_INVALID_ARGUMENT;
        LogError("Invalid argument");
    }
    else
    {
        if (NetIo_isDataAvailable(pPutMedia->xNetIoHandle))
        {
            if ((xBufRecv = BUFFER_create_with_size(DEFAULT_RECV_BUFSIZE)) == NULL)
            {
                res = KVS_ERROR_C_UTIL_UNABLE_TO_CREATE_BUFFER;
                LogError("OOM: xBufRecv");
            }
            else
            {
                prvFlushFragmentAck(pPutMedia);
                while (NetIo_isDataAvailable(pPutMedia->xNetIoHandle))
                {
                    if (BUFFER_length(xBufRecv) == uBytesTotalReceived && BUFFER_enlarge(xBufRecv, BUFFER_length(xBufRecv) * 2) != 0)
                    {
                        res = KVS_ERROR_C_UTIL_UNABLE_TO_ENLARGE_BUFFER;
                        LogError("OOM: xBufRecv");
                        break;
                    }

                    if ((res = NetIo_recv(pPutMedia->xNetIoHandle, BUFFER_u_char(xBufRecv) + uBytesTotalReceived, BUFFER_length(xBufRecv) - uBytesTotalReceived, &uBytesReceived)) !=KVS_ERRNO_NONE)
                    {
                        LogError("Failed to receive");
                        /* Propagate the res error */
                        break;
                    }

                    uBytesTotalReceived += uBytesReceived;
                }

                if (res == KVS_ERRNO_NONE && uBytesTotalReceived > 0)
                {
                    uBytesReceived = 0;
                    while (uBytesReceived < uBytesTotalReceived)
                    {
                        memset(&xFragmentAck, 0, sizeof(FragmentAck_t));
                        if (prvParseFragmentAck((char *)BUFFER_u_char(xBufRecv) + uBytesReceived, uBytesTotalReceived - uBytesReceived, &xFragmentAck, &uFragAckLen) != KVS_ERRNO_NONE ||
                            uFragAckLen == 0)
                        {
                            break;
                        }
                        else
                        {
                            // prvLogFragmentAck(&xFragmentAck);
                            prvPushFragmentAck(pPutMedia, &xFragmentAck);
                            if (xFragmentAck.eventType == eError)
                            {
                                res = KVS_GENERATE_PUTMEDIA_ERROR(xFragmentAck.uErrorId);
                                break;
                            }
                        }
                        uBytesReceived += uFragAckLen;
                    }
                    prvLogPendingFragmentAcks(pPutMedia);
                }
            }
        }
    }

    BUFFER_delete(xBufRecv);

    return res;
}

void Kvs_putMediaFinish(PutMediaHandle xPutMediaHandle)
{
    PutMedia_t *pPutMedia = xPutMediaHandle;

    if (pPutMedia != NULL)
    {
        prvFlushFragmentAck(pPutMedia);
        //Lock_Deinit(pPutMedia->xLock);
        if (pPutMedia->xNetIoHandle != NULL)
        {
            NetIo_disconnect(pPutMedia->xNetIoHandle);
            NetIo_terminate(pPutMedia->xNetIoHandle);
        }
        kvsFree(pPutMedia);
    }
}

void Kvs_putMediaFinish_theia(PutMediaHandle xPutMediaHandle)
{
    PutMedia_t *pPutMedia = xPutMediaHandle;

    if (pPutMedia != NULL)
    {
        prvFlushFragmentAck(pPutMedia);
        //Lock_Deinit(pPutMedia->xLock);
        if (pPutMedia->xNetIoHandle != NULL)
        {
            NetIo_disconnect(pPutMedia->xNetIoHandle);
            // NetIo_terminate(pPutMedia->xNetIoHandle);
        }
        // kvsFree(pPutMedia);
    }
}

int Kvs_putMediaUpdateRecvTimeout(PutMediaHandle xPutMediaHandle, unsigned int uRecvTimeoutMs)
{
    int res = KVS_ERRNO_NONE;
    PutMedia_t *pPutMedia = xPutMediaHandle;

    if (pPutMedia == NULL || pPutMedia->xNetIoHandle == NULL)
    {
        res = KVS_ERROR_INVALID_ARGUMENT;
    }
    else if ((res = NetIo_setRecvTimeout(pPutMedia->xNetIoHandle, uRecvTimeoutMs)) != KVS_ERRNO_NONE)
    {
        /* Propagate the res error */
    }
    else
    {
        /* nop */
    }

    return res;
}

int Kvs_putMediaUpdateSendTimeout(PutMediaHandle xPutMediaHandle, unsigned int uSendTimeoutMs)
{
    int res = KVS_ERRNO_NONE;
    PutMedia_t *pPutMedia = xPutMediaHandle;

    if (pPutMedia == NULL || pPutMedia->xNetIoHandle == NULL)
    {
        res = KVS_ERROR_INVALID_ARGUMENT;
    }
    else if ((res = NetIo_setSendTimeout(pPutMedia->xNetIoHandle, uSendTimeoutMs)) != KVS_ERRNO_NONE)
    {
        /* Propagate the res error */
    }
    else
    {
        /* nop */
    }

    return res;
}

int Kvs_putMediaReadFragmentAck(PutMediaHandle xPutMediaHandle, ePutMediaFragmentAckEventType *peAckEventType, uint64_t *puFragmentTimecode, unsigned int *puErrorId)
{
    int res = KVS_ERRNO_NONE;
    PutMedia_t *pPutMedia = xPutMediaHandle;
    FragmentAck_t *pFragmentAck = NULL;

    if (pPutMedia == NULL)
    {
        res = KVS_ERROR_INVALID_ARGUMENT;
    }
    else if ((pFragmentAck = prvReadFragmentAck(pPutMedia)) == NULL)
    {
        res = KVS_ERROR_NO_PUTMEDIA_FRAGMENT_ACK_AVAILABLE;
    }
    else
    {
        if (peAckEventType != NULL)
        {
            *peAckEventType = pFragmentAck->eventType;
        }
        if (puFragmentTimecode != NULL)
        {
            *puFragmentTimecode = pFragmentAck->uFragmentTimecode;
        }
        if (puErrorId != NULL)
        {
            *puErrorId = pFragmentAck->uErrorId;
        }
        kvsFree(pFragmentAck);
    }

    return res;
}

/** Testing situation from https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
 * 
 *  Canonical Request:      ---------------------------------------------------------------|----------------------------
 *  GET                                                                                     VERB
 *  /test.txt                                                                               URI
 * 
 *  host:examplebucket.s3.amazonaws.com                                                     host
 *  range:bytes=0-9                                                                         range
 *  x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855   empty body sha256
 *  x-amz-date:20130524T000000Z                                                             x-amz-date
 *
 *  host;range;x-amz-content-sha256;x-amz-date                                              signed headers
 *  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855                        hashed payload
 * ----------------------------------------------------------------------------------------|----------------------------
 *  Canonical Request Hash given:       7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972
 *  Canonical Request Hash ours:        7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972
 * 
 *  String To Sign:         ---------------------------------------------------------------|----------------------------
 *  AWS4-HMAC-SHA256                                                                        Algorithm
 *  20130524T000000Z                                                                        Request date
 *  20130524/us-east-1/s3/aws4_request                                                      Scope
 *  7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972                        Hashed Canonical Request
 * ----------------------------------------------------------------------------------------|----------------------------
 * 
 *  Signing Key:            ---------------------------------------------------------------|----------------------------
 *  DateKey               = HMAC-SHA256("AWS4" + "<SecretAccessKey>", "20130524")         = 4fe8c47cd276b4c7e04c1e8a7f5923062e61ba0399dc89c93998486a3dc0bc9f    1859675a70a0a0eedaf980cedb4ca37b8d1fe596b0ea3c21fe8729d5148d03fc    68896419206d6240ad4cd7dc8ba658efbf3b43b53041950083a10833824fcfbb
 *  DateRegionKey         = HMAC-SHA256(<DateKey>, "us-east-1")                           = 36568e2661f2b80f63df5e8a366b318f3df8959d968c4c27ccf1ead86c66b929    10c2b5b2a694f813134bf67e29cf4860a19c9ba855f0f9d66d5041897d258674    b1d69b01d01fbfab62ce62e2b354dc81fa797232685c3de02919930c87f3db5d
 *  DateRegionServiceKey  = HMAC-SHA256(<DateRegionKey>, "s3")                            = ad7e51781a15ef9302d0ad6e012b8c75de2c7f3a67f23c51e99026570219db71    0752acc01880b845bc697bb359de3f186f21c78498a0f6f2cd392d382a9f5f06    ec603b02e46102b2c2563dd47216472c5c0aba27edeb8308255e4c60bb07bda0
 *  SigningKey            = HMAC-SHA256(<DateRegionServiceKey>, "aws4_request")           = f0964526f1f568b2b0d4b9f98eafe032297dcff14dfecadf740a143ff3a7dcc4    d949da6fe2897897d73557446db35c06dc34feb7f74e7d949c6fe9d674a02103
 * ----------------------------------------------------------------------------------------|----------------------------
 *                                                                                          ff560d1d0fb1bfe972844b2029d69193db4ff13add26e9c5fbd2dae52ffd65ac    7553b766519d7713ec5cea28f8d295a6f5b5a98df23365363ef8183296c74071
 *  Signature:              ---------------------------------------------------------------|----------------------------
 *  Signature             = HexEncode(HMAC-SHA256(<SigningKey>, <StringToSign>))          = f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41
 *  Signature             = HexEncode(HMAC-SHA256(<SigningKey>, <StringToSign>))          = <Signature>
 */

#include "kvs/test_sigv4.h"
#define EMPTY_BODY_SHA265 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
#define TEST_AWS_ACCESS_KEY "AKIAIOSFODNN7EXAMPLE"
#define TEST_AWS_SECRET_KEY "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

void test_check_signature()
{
    char pcRegion[] = "us-east-1";
    char pcService[] = "s3";
    char pcStreamName[] = "exampleStreamName";  
    char pcHost[] = "examplebucket.s3.amazonaws.com";
    char *pcToken = NULL;
    char pcHttpMethod[] = "GET";
    char pcUri[] = "/test.txt";
    char pcBody[] = "";
    
    char pcXAmzDate[DATE_TIME_ISO_8601_FORMAT_STRING_SIZE] = "20130524T000000Z";

    AwsSigV4Handle xAwsSigV4Handle = NULL;

    HTTP_HEADERS_HANDLE xHttpReqHeaders = NULL;
    
    STRING_HANDLE xStHttpBody = NULL;
    STRING_HANDLE xStContentLength = NULL;

    KvsServiceParameter_t xServPara = {
        .pcHost = pcHost,
        .pcRegion = pcRegion,
        .pcService = pcService,
        .pcAccessKey = TEST_AWS_ACCESS_KEY,
        .pcSecretKey = TEST_AWS_SECRET_KEY,
        .pcToken = pcToken,
        .uRecvTimeoutMs = 1000,
        .uSendTimeoutMs = 1000
    };

    int res = KVS_ERRNO_NONE;

    if (
        (xStHttpBody = STRING_construct_sprintf(DESCRIBE_STREAM_HTTP_BODY_TEMPLATE, pcStreamName)) == NULL ||
        (xStContentLength = STRING_construct_sprintf("%u", STRING_length(xStHttpBody))) == NULL)
    {
        res = KVS_ERROR_UNABLE_TO_ALLOCATE_HTTP_BODY;
        LogError("Failed to allocate HTTP body");
    }
    else if (
        (xHttpReqHeaders = HTTPHeaders_Alloc()) == NULL || 
        HTTPHeaders_AddHeaderNameValuePair(xHttpReqHeaders, HDR_HOST, pcHost) != HTTP_HEADERS_OK ||
        //HTTPHeaders_AddHeaderNameValuePair(xHttpReqHeaders, HDR_ACCEPT, VAL_ACCEPT_ANY) != HTTP_HEADERS_OK ||
        //HTTPHeaders_AddHeaderNameValuePair(xHttpReqHeaders, HDR_CONTENT_LENGTH, STRING_c_str(xStContentLength)) != HTTP_HEADERS_OK ||
        //HTTPHeaders_AddHeaderNameValuePair(xHttpReqHeaders, HDR_CONTENT_TYPE, VAL_CONTENT_TYPE_APPLICATION_jSON) != HTTP_HEADERS_OK ||
        //HTTPHeaders_AddHeaderNameValuePair(xHttpReqHeaders, HDR_USER_AGENT, VAL_USER_AGENT) != HTTP_HEADERS_OK ||
        HTTPHeaders_AddHeaderNameValuePair(xHttpReqHeaders, "range", "bytes=0-9") != HTTP_HEADERS_OK ||
        HTTPHeaders_AddHeaderNameValuePair(xHttpReqHeaders, "x-amz-content-sha256", EMPTY_BODY_SHA265) != HTTP_HEADERS_OK ||
        HTTPHeaders_AddHeaderNameValuePair(xHttpReqHeaders, HDR_X_AMZ_DATE, pcXAmzDate) != HTTP_HEADERS_OK ||
        (pcToken != NULL && (HTTPHeaders_AddHeaderNameValuePair(xHttpReqHeaders, HDR_X_AMZ_SECURITY_TOKEN, pcToken) != HTTP_HEADERS_OK)))
    {
        res = KVS_ERROR_UNABLE_TO_GENERATE_HTTP_HEADER;
        LogError("Failed to generate HTTP headers");
    }
    else if (
        (xAwsSigV4Handle = prvSign(&xServPara, pcUri, URI_QUERY_EMPTY, xHttpReqHeaders, STRING_c_str(xStHttpBody))) == NULL ||
        HTTPHeaders_AddHeaderNameValuePair(xHttpReqHeaders, HDR_AUTHORIZATION, AwsSigV4_GetAuthorization(xAwsSigV4Handle)) != HTTP_HEADERS_OK)
    {
        res = KVS_ERROR_FAIL_TO_SIGN_HTTP_REQ;
        LogError("Failed to sign");
    }

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
                        free(pcHeader);
                        break;
                    }

                    xStHttpReq = newReq;
                    strcat(xStHttpReq, pcHeader);
                    strcat(xStHttpReq, "\r\n");

                    /* pcHeader was created by HTTPHeaders_GetHeader via malloc */
                    free(pcHeader);
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
      LOG_INF("String Handle: %s", xStHttpReq);
    }
    else
    {
      LOG_ERR("Failed to generate HTTP request");
        k_free(xStHttpReq);
        xStHttpReq = NULL;
    }
}