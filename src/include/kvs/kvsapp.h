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

#ifndef KVSAPP_H
#define KVSAPP_H

#include "kvs/kvsapp_options.h"
#include "kvs/mkv_generator.h"
#include "kvs/restapi.h"
#include "kvs/errors.h"
#include <inttypes.h>

#include "kvs/iot_credential_provider.h"
#include "kvs/stream.h"

typedef struct KvsApp *KvsAppHandle;

/**
 * This callback is called when a data frame is about to be terminated. And this callback is responsible to return the control to application side.
 * The application can either just called free() or handle it in a proper way which depends on the way how this frame is created.
 *
 * @param[in] pData Pointer of data frame
 * @param[in] uDataLen Size of data frame
 * @param[in] uTimestamp Timestamp of data frame
 * @param[in] xTrackType Track type of data frame
 * @param[in] pAppData Pointer of application data that is assigned in function KvsApp_addFrameWithCallbacks()
 * @return 0 on success, non-zero value otherwise
 */
typedef int (*OnDataFrameTerminateCallback_t)(uint8_t *pData, size_t uDataLen, uint64_t uTimestamp, TrackType_t xTrackType, void *pAppData);

/**
 * This callback is called before a frame is about to be sent. Application can use this callback to decide whether or not to send out this frame.
 *
 * @param[in] pData Pointer of data frame
 * @param[in] uDataLen Size of data frame
 * @param[in] uTimestamp Timestamp of data frame
 * @param[in] xTrackType Track type of data frame
 * @param[in] pAppData Pointer of application data that is assigned in function KvsApp_addFrameWithCallbacks()
 */
typedef int (*OnDataFrameToBeSentCallback_t)(uint8_t *pData, size_t uDataLen, uint64_t uTimestamp, TrackType_t xTrackType, void *pAppData);

/**
 * This callback is called whenever a data has been sent to PUT MEDIA endpoint. All data sent to PUT MEDIA endpoint follow MKV format, so it could
 * help to debug which data has been sent.
 *
 * @param[in] pData Pointer of data
 * @param[in] uDataLen Size of data
 * @param[in] pAppData Pointer of application data that is assigned in function KvsApp_setOnMkvSentCallback()
 */
typedef int (*OnMkvSentCallback_t)(uint8_t *pData, size_t uDataLen, void *pAppData);

typedef struct OnDataFrameTerminateCallbackInfo
{
    OnDataFrameTerminateCallback_t onDataFrameTerminate;
    void *pAppData;
} OnDataFrameTerminateInfo_t;

typedef struct OnDataFrameToBeSentCallbackInfo
{
    OnDataFrameToBeSentCallback_t onDataFrameToBeSent;
    void *pAppData;
} OnDataFrameToBeSentInfo_t;

typedef struct DataFrameCallbacks
{
    OnDataFrameTerminateInfo_t onDataFrameTerminateInfo;
    OnDataFrameToBeSentInfo_t onDataFrameToBeSentInfo;
} DataFrameCallbacks_t;

typedef enum DoWorkExType
{
    /* The default behaviro is the same as KvsApp_doWork. */
    DO_WORK_DEFAULT = 0,

    /* It's similar to doWork, except that it also sends out the end of frames. */
    DO_WORK_SEND_END_OF_FRAMES = 1
} DoWorkExType_t;

typedef struct DoWorkExParamter
{
    DoWorkExType_t eType;
} DoWorkExParamter_t;

/**
 * Create a KVS application.
 *
 * @param[in] pcHost KVS hostname
 * @param[in] pcRegion Region to be used
 * @param[in] pcService Service name, it should always be "kinesisvideo"
 * @param[in] pcStreamName KVS stream name
 * @return KVS application handle
 */
//.KvsAppHandle KvsApp_create(const char *pcHost, const char *pcRegion, const char *pcService, const char *pcStreamName);
KvsAppHandle KvsApp_create(const char *pcHost, const char *pcRegion, const char *pcService, const char *pcStreamName, const char *secretKey, const char *accessKey);

/**
 * Terminate a KVS application.
 *
 * @param[in] handle KVS application handle
 */
void KvsApp_terminate(KvsAppHandle handle);

/**
 * Set option to KVS application.
 *
 * @param[in] handle KVS application handle
 * @param[in] pcOptionName Option name
 * @param[in] pValue Value
 * @return 0 on success, non-zero value otherwise
 */
int KvsApp_setoption(KvsAppHandle handle, const char *pcOptionName, const char *pValue);

/**
 * Open KVS application. It includes validating if stream exist, getting PUT_MEDIA data endpoint, and setup PUT_MEDIA
 * connection. It also tries to setup stream buffer if track info are already set.
 *
 * @param[in] handle KVS application handle.
 * @return 0 on success, non-zero value otherwise
 */
int KvsApp_open(KvsAppHandle handle);

/**
 * Close KVS application. It includes closing connection, flush stream buffer and terminate it.
 *
 * @param[in] handle KVS application handle
 * @return 0 on success, non-zero value otherwise
 */
int KvsApp_close(KvsAppHandle handle);

/**
 * Same as KvsApp_open() but with flushing the stream buffer from KvsApp_terminate().
 */
int KvsApp_close_and_terminate(KvsAppHandle handle);

/**
 * Add a frame to KVS application. If the stream buffer is not allocated yet, then it'll try to parse decode information
 * and then setup stream buffer.
 *
 * @param[in] handle KVS application handle
 * @param[in] pData Data buffer pointer
 * @param[in] uDataLen Data length
 * @param[in] uDataSize Data buffer size
 * @param[in] uTimestamp Frame absolution timestamp in milliseconds.
 * @param[in] xTrackType Track type, it could be TRACK_VIDEO or TRACK_AUDIO
 * @return 0 on success, non-zero value otherwise
 */
int KvsApp_addFrame(KvsAppHandle handle, uint8_t *pData, size_t uDataLen, size_t uDataSize, uint64_t uTimestamp, TrackType_t xTrackType);

/**
 * Add a frame to KVS application. If the stream buffer is not allocated yet, then it'll try to parse decode information
 * and then setup stream buffer.
 *
 * @param[in] handle KVS application handle
 * @param[in] pData Data buffer pointer
 * @param[in] uDataLen Data length
 * @param[in] uDataSize Data buffer size
 * @param[in] uTimestamp Frame absolution timestamp in milliseconds.
 * @param[in] xTrackType Track type, it could be TRACK_VIDEO or TRACK_AUDIO
 * @param[in] pCallbacks Callbacks
 * @return 0 on success, non-zero value otherwise
 */
int KvsApp_addFrameWithCallbacks(KvsAppHandle handle, uint8_t *pData, size_t uDataLen, size_t uDataSize, uint64_t uTimestamp, TrackType_t xTrackType, DataFrameCallbacks_t *pCallbacks);

/**
 * Let KVS application do works. It will try to send out frames, and check if any messages from server.
 *
 * @param[in] handle KVS application handle
 * @return 0 on success, non-zero value otherwise
 */
int KvsApp_doWork(KvsAppHandle handle);

/**
 * Let KVS application do works. It will try to send out frames, and check if any messages from server.
 *
 * @param[in] handle KVS application handle
 * @param[in] pPara Extra parameter. If pPara is NULL, the default behavior is DO_WORK_DEFAULT.
 * @return 0 on success, non-zero value otherwise
 */
int KvsApp_doWorkEx(KvsAppHandle handle, DoWorkExParamter_t *pPara);

/**
 * @brief Non-blocking read a fragment ACK if any.
 *
 * When KvsApp_doWork() is called, it will check if any incoming fragment ACKs, and clear fragment ACKs that buffered in the previous Kvs_putMediaDoWork() call.
 * Use KvsApp_readFragmentAck() to read one fragment ACK and the return value would be 0. If there is no fragment ACK available, then the return value would be non-zero value.
 *
 * @param[in] handle The handle of PUT MEDIA
 * @param[out] peAckEventType Pointer to the fragment ACK event type
 * @param[out] puFragmentTimecode Pointer to the fragment timecode
 * @param[out] puErrorId Pointer to the error ID
 * @return 0 on success, non-zero value otherwise
 */
int KvsApp_readFragmentAck(KvsAppHandle handle, ePutMediaFragmentAckEventType *peAckEventType, uint64_t *puFragmentTimecode, unsigned int *puErrorId);

/**
 * Get the memory used in the stream buffer.
 *
 * @param handle  KVS application handle
 * @return Memory used in current stream buffer, zero value otherwise
 */
size_t KvsApp_getStreamMemStatTotal(KvsAppHandle handle);

/**
 * Set onMkvSentCallback. Whenever a data has been sent to PUT MEDIA endpoint, it'll invoke this callback.
 *
 * @param handle KVS application handle
 * @param onMkvSentCallback Callback
 * @param pAppData The application data that will be passed in the argument of the callback
 * @return 0 on success, non-zero value otherwise
 */
int KvsApp_setOnMkvSentCallback(KvsAppHandle handle, OnMkvSentCallback_t onMkvSentCallback, void *pAppData);


typedef struct PolicyRingBufferParameter
{
    size_t uMemLimit;
} PolicyRingBufferParameter_t;

typedef struct StreamStrategy
{
    KvsApp_streamPolicy_t xPolicy;
    union
    {
        PolicyRingBufferParameter_t xRingBufferPara;
    };
} StreamStrategy_t;

typedef struct OnMkvSentCallbackInfo
{
    OnMkvSentCallback_t onMkvSentCallback;
    void *pAppData;
} OnMkvSentCallbackInfo_t;

typedef struct KvsApp
{
    //LOCK_HANDLE xLock;
    struct k_mutex *xLockMutex;

    char *pHost;
    char *pRegion;
    char *pService;
    char *pStreamName;
    char *pDataEndpoint;

    /* AWS access key, access secret and session token */
    char *pAwsAccessKeyId;
    char *pAwsSecretAccessKey;
    char *pAwsSessionToken;

    /* Iot certificates */
    char *pIotCredentialHost;
    char *pIotRoleAlias;
    char *pIotThingName;
    char *pIotX509RootCa;
    char *pIotX509Certificate;
    char *pIotX509PrivateKey;
    IotCredentialToken_t *pToken;

    /* Restful request parameters */
    KvsServiceParameter_t xServicePara;
    KvsDescribeStreamParameter_t xDescPara;
    KvsCreateStreamParameter_t xCreatePara;
    KvsGetDataEndpointParameter_t xGetDataEpPara;
    KvsPutMediaParameter_t xPutMediaPara;

    unsigned int uDataRetentionInHours;

    /* KVS streaming variables */
    uint64_t uEarliestTimestamp;
    StreamHandle xStreamHandle;
    PutMediaHandle xPutMediaHandle;
    bool isEbmlHeaderUpdated;
    StreamStrategy_t xStrategy;

    /* Track information */
    VideoTrackInfo_t *pVideoTrackInfo;
    uint8_t *pSps;
    size_t uSpsLen;
    uint8_t *pPps;
    size_t uPpsLen;

    bool isAudioTrackPresent;
    AudioTrackInfo_t *pAudioTrackInfo;

    /* Session scope callbacks */
    OnMkvSentCallbackInfo_t onMkvSentCallbackInfo;
} KvsApp_t;

typedef struct DataFrameUserData
{
    DataFrameCallbacks_t xCallbacks;
} DataFrameUserData_t;


#endif /* KVSAPP_H */
