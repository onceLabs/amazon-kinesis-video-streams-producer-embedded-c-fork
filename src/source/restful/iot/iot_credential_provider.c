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
#include <string.h>
#include <time.h>

/* Thirdparty headers */
#include "azure_c_shared_utility/httpheaders.h"
#include "azure_c_shared_utility/strings.h"
#include "azure_c_shared_utility/xlogging.h"
#include "parson.h"

/* Public headers */
#include "kvs/errors.h"
#include "kvs/iot_credential_provider.h"

/* Internal headers */
#include "os/allocator.h"
#include "net/http_helper.h"
#include "misc/json_helper.h"
#include "net/netio.h"

#include <zephyr/data/json.h>

#define IOT_URI_ROLE_ALIASES_BEGIN  "/role-aliases"
#define IOT_URI_ROLE_ALIASES_END    "/credentials"

struct iot_credentials_s {
  char *accessKeyId;
  char *secretAccessKey;
  char *sessionToken;
  char *expiration;
};

static const struct json_obj_descr iot_credentials_descr[] = {
  JSON_OBJ_DESCR_PRIM(struct iot_credentials_s, accessKeyId, JSON_TOK_STRING),
  JSON_OBJ_DESCR_PRIM(struct iot_credentials_s, secretAccessKey, JSON_TOK_STRING),
  JSON_OBJ_DESCR_PRIM(struct iot_credentials_s, sessionToken, JSON_TOK_STRING),
  JSON_OBJ_DESCR_PRIM(struct iot_credentials_s, expiration, JSON_TOK_STRING),
};

struct iot_credential_response_s {
  struct iot_credentials_s credentials;
};

static const struct json_obj_descr iot_credential_response_descr[] = {
  JSON_OBJ_DESCR_OBJECT(struct iot_credential_response_s, credentials, iot_credentials_descr),
};

static int parseIoTCredential(const char *pcJsonSrc, size_t uJsonSrcLen, IotCredentialToken_t *pToken)
{
    int err = 0;
    struct iot_credential_response_s iot_credential_response;

    LogInfo("pcJsonSrc: %s\n", pcJsonSrc);

    err = 
      json_obj_parse(
        pcJsonSrc, 
        uJsonSrcLen, 
        iot_credential_response_descr, 
        ARRAY_SIZE(iot_credential_response_descr), 
        &iot_credential_response);

    if (err > 0) {
      // Log out the parsed values
      LogInfo("\r\naccessKeyId: %s %u\n", iot_credential_response.credentials.accessKeyId, strlen(iot_credential_response.credentials.accessKeyId));
      LogInfo("\r\nsecretAccessKey: %s %u\n", iot_credential_response.credentials.secretAccessKey, strlen(iot_credential_response.credentials.secretAccessKey));
      LogInfo("\r\nsessionToken: %s %u\n", iot_credential_response.credentials.sessionToken, strlen(iot_credential_response.credentials.sessionToken));
      LogInfo("\r\nexpiration: %s %u\n", iot_credential_response.credentials.expiration, strlen(iot_credential_response.credentials.expiration));

      // Copy the parsed values to the token
      pToken->pAccessKeyId = k_malloc(strlen(iot_credential_response.credentials.accessKeyId) + 1);
      if (pToken->pAccessKeyId == NULL) {
        return KVS_ERROR_OUT_OF_MEMORY;
      }
      strcpy(pToken->pAccessKeyId, iot_credential_response.credentials.accessKeyId);
      pToken->pSecretAccessKey = k_malloc(strlen(iot_credential_response.credentials.secretAccessKey) + 1);
      if (pToken->pSecretAccessKey == NULL) {
        return KVS_ERROR_OUT_OF_MEMORY;
      }
      strcpy(pToken->pSecretAccessKey, iot_credential_response.credentials.secretAccessKey);
      pToken->pSessionToken = k_malloc(strlen(iot_credential_response.credentials.sessionToken) + 1);
      if (pToken->pSessionToken == NULL) {
        return KVS_ERROR_OUT_OF_MEMORY;
      }
      strcpy(pToken->pSessionToken, iot_credential_response.credentials.sessionToken);

      // expiration
      char* ret = strptime(iot_credential_response.credentials.expiration, "%Y-%m-%dT%H:%M:%SZ", &pToken->expiration);
      if (ret == NULL) {
        LogError("Failed to parse expiration");
        return KVS_ERROR_FAIL_TO_PARSE_JSON_OF_IOT_CREDENTIAL;
      }

      return KVS_ERRNO_NONE;
    } else {
      return KVS_ERROR_FAIL_TO_PARSE_JSON_OF_IOT_CREDENTIAL;
    }

    // // Logu out the pcJsonSrc, uJsonSrcLen, pToken
    // LogInfo("pcJsonSrc: %s", pcJsonSrc);
    // LogInfo("uJsonSrcLen: %d", uJsonSrcLen);
    // LogInfo("pToken: %s", pToken);

    // int res = KVS_ERRNO_NONE;
    // STRING_HANDLE xStJson = NULL;
    // JSON_Value *pxRootValue = NULL;
    // JSON_Object *pxRootObject = NULL;

    // json_set_escape_slashes(0);

    // if (pcJsonSrc == NULL || uJsonSrcLen == 0 || pToken == NULL)
    // {
    //     res = KVS_ERROR_INVALID_ARGUMENT;
    //     LogError("Invalid argument");
    // }
    // else if ((xStJson = STRING_construct_n(pcJsonSrc, uJsonSrcLen)) == NULL)
    // {
    //     res = KVS_ERROR_OUT_OF_MEMORY;
    //     LogError("OOM: parse IoT credential");
    // }
    // else if (
    //     (pxRootValue = json_parse_string(STRING_c_str(xStJson))) == NULL || (pxRootObject = json_value_get_object(pxRootValue)) == NULL ||
    //     (pToken->pAccessKeyId = json_object_dotget_serialize_to_string(pxRootObject, "credentials.accessKeyId", true)) == NULL ||
    //     (pToken->pSecretAccessKey = json_object_dotget_serialize_to_string(pxRootObject, "credentials.secretAccessKey", true)) == NULL ||
    //     (pToken->pSessionToken = json_object_dotget_serialize_to_string(pxRootObject, "credentials.sessionToken", true)) == NULL)
    // {
    //     res = KVS_ERROR_FAIL_TO_PARSE_JSON_OF_IOT_CREDENTIAL;
    //     LogError("Failed to parse IoT credential");
    // }
    // else
    // {
    //     /* nop */
    // }

    // if (pxRootValue != NULL)
    // {
    //     json_value_free(pxRootValue);
    // }

    // STRING_delete(xStJson);

    // return res;
}

IotCredentialToken_t *Iot_getCredential(IotCredentialRequest_t *pReq)
{
    int res = KVS_ERRNO_NONE;
    IotCredentialToken_t *pToken = NULL;

    STRING_HANDLE xStUri = NULL;

    unsigned int uHttpStatusCode = 0;
    HTTP_HEADERS_HANDLE xHttpReqHeaders = NULL;
    char *pRspBody = NULL;
    size_t uRspBodyLen = 0;

    NetIoHandle xNetIoHandle = NULL;
    // Log out the pCredentialHost, pRoleAlias, pThingName, pRootCA, pCertificate, pPrivateKey
    LogInfo("pCredentialHost: %s", pReq->pCredentialHost);
    LogInfo("pRoleAlias: %s", pReq->pRoleAlias);
    LogInfo("pThingName: %s", pReq->pThingName);
    // LogInfo("pRootCA: %s", pReq->pRootCA);
    // LogInfo("pCertificate: %s", pReq->pCertificate);
    // LogInfo("pPrivateKey: %s", pReq->pPrivateKey);

    if (pReq == NULL || pReq->pCredentialHost == NULL || pReq->pRoleAlias == NULL || pReq->pThingName == NULL || pReq->pRootCA == NULL || pReq->pCertificate == NULL ||
        pReq->pPrivateKey == NULL)
    {
        res = KVS_ERROR_INVALID_ARGUMENT;
        LogError("Invalid argument");
    }
    else if ((xStUri = STRING_construct_sprintf("%s/%s%s", IOT_URI_ROLE_ALIASES_BEGIN, pReq->pRoleAlias, IOT_URI_ROLE_ALIASES_END)) == NULL)
    {
        res = KVS_ERROR_OUT_OF_MEMORY;
        LogError("OOM: Failed to allocate IoT URI");
    }
    else if (
        (xHttpReqHeaders = HTTPHeaders_Alloc()) == NULL || HTTPHeaders_AddHeaderNameValuePair(xHttpReqHeaders, HDR_HOST, pReq->pCredentialHost) != HTTP_HEADERS_OK ||
        HTTPHeaders_AddHeaderNameValuePair(xHttpReqHeaders, "accept", "*/*") != HTTP_HEADERS_OK ||
        HTTPHeaders_AddHeaderNameValuePair(xHttpReqHeaders, HDR_X_AMZN_IOT_THINGNAME, pReq->pThingName) != HTTP_HEADERS_OK)
    {
        res = KVS_ERROR_FAIL_TO_GENERATE_HTTP_HEADERS;
        LogError("Failed to generate HTTP headers");
    }
    else if ((xNetIoHandle = NetIo_create()) == NULL)
    {
        res = KVS_ERROR_FAIL_TO_CREATE_NETIO_HANDLE;
        LogError("Failed to create netio handle");
    }
    else if ((res = NetIo_connectWithX509(xNetIoHandle, pReq->pCredentialHost, "443", pReq->pRootCA, pReq->pCertificate, pReq->pPrivateKey)) != KVS_ERRNO_NONE)
    {
        LogError("Failed to connect to %s\r\n", pReq->pCredentialHost);
        /* Propagate the res error */
    }
    else if ((res = Http_executeHttpReq(xNetIoHandle, HTTP_METHOD_GET, STRING_c_str(xStUri), xHttpReqHeaders, HTTP_BODY_EMPTY)) != KVS_ERRNO_NONE)
    {
        LogError("Failed send http request to %s", pReq->pCredentialHost);
        /* Propagate the res error */
    }
    else if ((res = Http_recvHttpRsp(xNetIoHandle, &uHttpStatusCode, &pRspBody, &uRspBodyLen)) != KVS_ERRNO_NONE)
    {
        LogError("Failed recv http response from %s", pReq->pCredentialHost);
        /* Propagate the res error */
    }
    else
    {
        if (uHttpStatusCode != 200)
        {
            LogInfo("Get IoT credential failed, HTTP status code: %u", uHttpStatusCode);
            LogInfo("HTTP response message:%.*s", (int)uRspBodyLen, pRspBody);
        }
        else
        {
            if ((pToken = (IotCredentialToken_t *)k_malloc(sizeof(IotCredentialToken_t))) == NULL)
            {
                res = KVS_ERROR_OUT_OF_MEMORY;
                LogError("OOM: pToken");
            }
            else
            {
                memset(pToken, 0, sizeof(IotCredentialToken_t));
                if ((res = parseIoTCredential(pRspBody, uRspBodyLen, pToken)) != KVS_ERRNO_NONE)
                {
                    LogError("Failed to parse IoT credential token");
                    /* Propagate the res error */
                }
            }
        }
    }

    if (res != KVS_ERRNO_NONE)
    {
        Iot_credentialTerminate(pToken);
        pToken = NULL;
    }

    if (pRspBody != NULL)
    {
        kvsFree(pRspBody);
    }

    NetIo_disconnect(xNetIoHandle);
    NetIo_terminate(xNetIoHandle);
    HTTPHeaders_Free(xHttpReqHeaders);
    STRING_delete(xStUri);

    return pToken;
}

void Iot_credentialTerminate(IotCredentialToken_t *pToken)
{
    if (pToken != NULL)
    {
        if (pToken->pAccessKeyId != NULL)
        {
            k_free(pToken->pAccessKeyId);
        }
        if (pToken->pSecretAccessKey != NULL)
        {
            k_free(pToken->pSecretAccessKey);
        }
        if (pToken->pSessionToken != NULL)
        {
            k_free(pToken->pSessionToken);
        }
        k_free(pToken);
    }
}