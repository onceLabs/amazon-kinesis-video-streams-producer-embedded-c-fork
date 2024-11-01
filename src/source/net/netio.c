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
#include <stdint.h>
#include <string.h>

#include <sys/time.h>
#include <socket.h>
#include <zephyr/kernel.h>
#include <zephyr/net/socket.h>
/* Third party headers */
#include "azure_c_shared_utility/xlogging.h"
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/psa_util.h>
// #include <mbedtls/net.h>
#include <mbedtls/net_sockets.h>
#include <zephyr/posix/sys/select.h>
#include <zephyr/net/net_context.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/net_pkt.h>
/* Public headers */
#include "kvs/errors.h"

/* Internal headers */
#include "os/allocator.h"
#include "net/netio.h"
#include <zephyr/logging/log.h>
#include <kvs/transport/sockets_zephyr.h>
#include <zephyr_mbedtls_priv.h>

LOG_MODULE_REGISTER(netio, LOG_LEVEL_DBG);

#define DEFAULT_CONNECTION_TIMEOUT_MS       (10 * 1000)

typedef struct NetIo 
{
    /* Basic ssl connection parameters */
    int tcpSocket;
    mbedtls_ssl_context xSsl;
    mbedtls_ssl_config xConf;
    mbedtls_ctr_drbg_context xCtrDrbg;
    mbedtls_entropy_context xEntropy;

    /* Variables for IoT credential provider. It's optional feature so we declare them as pointers. */
    mbedtls_x509_crt *pRootCA;
    mbedtls_x509_crt *pCert;
    mbedtls_pk_context *pPrivKey;

    /* Options */
    uint32_t uRecvTimeoutMs;
    uint32_t uSendTimeoutMs;
} NetIo_t;

NetIo_t *_pxNet = NULL;

static int prvCreateX509Cert(NetIo_t *pxNet)
{
    int res = KVS_ERRNO_NONE;

    if (pxNet == NULL)
    {
        res = KVS_ERROR_INVALID_ARGUMENT;
    }
    else if ((pxNet->pRootCA = (mbedtls_x509_crt *)k_malloc(sizeof(mbedtls_x509_crt))) == NULL )
    {
        LOG_ERR("Failed to allocate memory ROOT for x509 cert");
        res = KVS_ERROR_OUT_OF_MEMORY;
    }
    else if ((pxNet->pCert = (mbedtls_x509_crt *)k_malloc(sizeof(mbedtls_x509_crt))) == NULL)
    {
        LOG_ERR("Failed to allocate memory DEVICE for x509 cert");
        res = KVS_ERROR_OUT_OF_MEMORY;
    }
    else if ((pxNet->pPrivKey = (mbedtls_pk_context *)k_malloc(sizeof(mbedtls_pk_context))) == NULL)
    {
        LOG_ERR("Failed to allocate memory PRIVATE for x509 cert");
        res = KVS_ERROR_OUT_OF_MEMORY;
    }
    else
    {
        mbedtls_x509_crt_init(pxNet->pRootCA);
        mbedtls_x509_crt_init(pxNet->pCert);
        mbedtls_pk_init(pxNet->pPrivKey);
    }

    return res;
}

int zephyr_net_rcv(void *ctx,unsigned char *buf,size_t len)
{
  int socket = ( int ) ctx;
  ssize_t recvStatus = zsock_recv( socket, buf, len, 0 );

  return recvStatus;
}

/* Function to send data (equivalent to mbedtls_net_send) */
int zephyr_net_send(void *ctx, const unsigned char *buf, size_t len)
{
  int socket = ( int ) ctx;
  LOG_DBG("Sending data via socket %d", socket);
  ssize_t sendStatus = zsock_send( socket, buf, len, 0 );

  return sendStatus;
}

static int prvInitConfig(NetIo_t *pxNet, const char *pcHost, const char *pcRootCA, const char *pcCert, const char *pcPrivKey)
{
    int res = KVS_ERRNO_NONE;
    int retVal = 0;

    if (pxNet == NULL)
    {
        res = KVS_ERROR_INVALID_ARGUMENT;
    }
    else
    {
        mbedtls_ssl_set_bio(&(pxNet->xSsl), ( void * )pxNet->tcpSocket, zephyr_net_send, zephyr_net_rcv, NULL);

        if ((retVal = mbedtls_ssl_config_defaults(&(pxNet->xConf), MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
        {
            res = KVS_GENERATE_MBEDTLS_ERROR(retVal);
            LogError("Failed to config ssl (err:-%X)", -res);
        }
        else
        {
            mbedtls_ssl_conf_rng(&(pxNet->xConf), mbedtls_ctr_drbg_random, &(pxNet->xCtrDrbg));
            mbedtls_ssl_set_hostname(&(pxNet->xSsl), pcHost);
            mbedtls_ssl_conf_read_timeout(&(pxNet->xConf), pxNet->uRecvTimeoutMs);
            NetIo_setSendTimeout(pxNet, pxNet->uSendTimeoutMs);

            if (pcRootCA != NULL && pcCert != NULL && pcPrivKey != NULL)
            {
                // Log out the pointers
                LOG_DBG("Root CA: %p", pcRootCA);
                LOG_DBG("Device Cert: %p", pcCert);
                LOG_DBG("Device Private Key: %p", pcPrivKey);
                
                if ((retVal = mbedtls_x509_crt_parse(pxNet->pRootCA, (void *)pcRootCA, strlen(pcRootCA) + 1)) != 0 )
                {
                    res = KVS_GENERATE_MBEDTLS_ERROR(retVal);
                    LOG_ERR("Failed to parse root x509 (err:-%02x)", -retVal);
                } else {
                    LOG_DBG("Successfully parsed root x509");
                }
                if ((retVal = mbedtls_x509_crt_parse(pxNet->pCert, (void *)pcCert, strlen(pcCert) + 1)) != 0)
                {
                    res = KVS_GENERATE_MBEDTLS_ERROR(retVal);
                    LOG_ERR("Failed to parse device x509 (err:-%02x)", -retVal);
                }
                else
                {
                    LOG_DBG("Successfully parsed device x509");
                }
                if ((retVal = mbedtls_pk_parse_key(pxNet->pPrivKey, (void *)pcPrivKey, strlen(pcPrivKey) + 1, NULL, 0, mbedtls_psa_get_random, MBEDTLS_PSA_RANDOM_STATE)) != 0)
                {
                    res = KVS_GENERATE_MBEDTLS_ERROR(retVal);
                    LOG_ERR("Failed to parse private x509 (err:-%02x)", -retVal);
                }
                else
                {
                    LOG_DBG("Successfully parsed private x509");
                    mbedtls_ssl_conf_authmode(&(pxNet->xConf), MBEDTLS_SSL_VERIFY_REQUIRED);
                    mbedtls_ssl_conf_ca_chain(&(pxNet->xConf), pxNet->pRootCA, NULL);

                    if ((retVal = mbedtls_ssl_conf_own_cert(&(pxNet->xConf), pxNet->pCert, pxNet->pPrivKey)) != 0)
                    {
                        res = KVS_GENERATE_MBEDTLS_ERROR(retVal);
                        LogError("Failed to conf own cert (err:-%X)", -res);
                    }
                }
            }
            else
            {
                mbedtls_ssl_conf_authmode(&(pxNet->xConf), MBEDTLS_SSL_VERIFY_OPTIONAL);
            }
        }
    }

    if (res == KVS_ERRNO_NONE)
    {
        if ((retVal = mbedtls_ssl_setup(&(pxNet->xSsl), &(pxNet->xConf))) != 0)
        {
            res = KVS_GENERATE_MBEDTLS_ERROR(retVal);
            LogError("Failed to setup ssl (err:-%X)", -res);
        }
    }

    LOG_DBG("Init config done");
    return res;
}

static int prvConnect(NetIo_t *pxNet, const char *pcHost, const char *pcPort, const char *pcRootCA, const char *pcCert, const char *pcPrivKey)
{
    int res = KVS_ERRNO_NONE;
    int32_t mbedtlsError = 0;
    SocketStatus_t returnStatus = SOCKETS_SUCCESS;

    struct ServerInfo serverInfo ={
      .hostNameLength = strlen(pcHost),
      .pHostName = pcHost,
      .port = 443
    };

    if (pxNet == NULL || pcHost == NULL || pcPort == NULL)
    {
        res = KVS_ERROR_INVALID_ARGUMENT;
        LOG_ERR("Invalid argument");
        return -1;
    }
    
    if ((pcRootCA != NULL && pcCert != NULL && pcPrivKey != NULL) && (res = prvCreateX509Cert(pxNet)) != KVS_ERRNO_NONE)
    {
        LOG_ERR("Failed to init x509 (err:-%X)", -res);
        return res;
    }
    if ((returnStatus = Sockets_Connect(&(pxNet->tcpSocket), &serverInfo, pxNet->uRecvTimeoutMs, pxNet->uSendTimeoutMs) != SOCKETS_SUCCESS))
    {
      LOG_ERR("Failed to connect to %s (err:-%d)", pcHost, returnStatus);
      return -1;
    } else {
      LOG_DBG("Successfully connected to %s", pcHost);
    }
    
    if ((res = prvInitConfig(pxNet, pcHost, pcRootCA, pcCert, pcPrivKey)) != KVS_ERRNO_NONE)
    {
      LOG_ERR("Failed to config ssl (err:-%X)", -res);
      /* Propagate the res error */
      return -1;
    } else {
      LOG_DBG("Successfully configured ssl");
    }

    // if (( mbedtlsError = mbedtls_ssl_setup(&(pxNet->xSsl), &(pxNet->xConf)) ) != 0)
    // {
    //   LOG_ERR("Failed to setup mbedTLS: mbedTLSError= %d", mbedtlsError);
    //   return -1;
    // } else {
    //   LOG_DBG("Successfully setup mbedTLS");
    // }
    
    /* Perform the TLS handshake. */
    do
    {
      mbedtlsError = mbedtls_ssl_handshake( &( pxNet->xSsl ) );
    } while( 
      ( mbedtlsError == MBEDTLS_ERR_SSL_WANT_READ ) ||
      ( mbedtlsError == MBEDTLS_ERR_SSL_WANT_WRITE ) 
    );

    if( mbedtlsError != 0 )
    {
        LOG_ERR("Failed to perform TLS handshake: mbedTLSError= %d", mbedtlsError);
        return -1;
    }

    return res;
}

NetIoHandle NetIo_create(void)
{
    //Log out the call

    if ((_pxNet = (NetIo_t *)k_malloc(sizeof(NetIo_t))) != NULL)
    {
        memset(_pxNet, 0, sizeof(NetIo_t));
        mbedtls_ssl_init(&(_pxNet->xSsl));
        mbedtls_ssl_config_init(&(_pxNet->xConf));
        mbedtls_ctr_drbg_init(&(_pxNet->xCtrDrbg));
        mbedtls_entropy_init(&(_pxNet->xEntropy));
        mbedtls_ssl_conf_dbg(&(_pxNet->xConf), zephyr_mbedtls_debug, NULL);
        _pxNet->uRecvTimeoutMs = DEFAULT_CONNECTION_TIMEOUT_MS;
        _pxNet->uSendTimeoutMs = DEFAULT_CONNECTION_TIMEOUT_MS;

        if (mbedtls_ctr_drbg_seed(&(_pxNet->xCtrDrbg), mbedtls_entropy_func, &(_pxNet->xEntropy), NULL, 0) != 0)
        {
            NetIo_terminate(_pxNet);
            _pxNet = NULL;
        }
    }

    return _pxNet;
}

void NetIo_terminate(NetIoHandle xNetIoHandle)
{
    NetIo_t *pxNet = (NetIo_t *)xNetIoHandle;

    if (pxNet != NULL)
    {
        mbedtls_ctr_drbg_free(&(pxNet->xCtrDrbg));
        mbedtls_entropy_free(&(pxNet->xEntropy));
        mbedtls_ssl_free(&(pxNet->xSsl));
        mbedtls_ssl_config_free(&(pxNet->xConf));

        if (pxNet->pRootCA != NULL)
        {
            mbedtls_x509_crt_free(pxNet->pRootCA);
            kvsFree(pxNet->pRootCA);
            pxNet->pRootCA = NULL;
        }

        if (pxNet->pCert != NULL)
        {
            mbedtls_x509_crt_free(pxNet->pCert);
            kvsFree(pxNet->pCert);
            pxNet->pCert = NULL;
        }

        if (pxNet->pPrivKey != NULL)
        {
            mbedtls_pk_free(pxNet->pPrivKey);
            kvsFree(pxNet->pPrivKey);
            pxNet->pPrivKey = NULL;
        }
        kvsFree(pxNet);
    }
}

int NetIo_connect(NetIoHandle xNetIoHandle, const char *pcHost, const char *pcPort)
{
    return prvConnect(xNetIoHandle, pcHost, pcPort, NULL, NULL, NULL);
}

int NetIo_connectWithX509(NetIoHandle xNetIoHandle, const char *pcHost, const char *pcPort, const char *pcRootCA, const char *pcCert, const char *pcPrivKey)
{
    return prvConnect(xNetIoHandle, pcHost, pcPort, pcRootCA, pcCert, pcPrivKey);
}

void NetIo_disconnect(NetIoHandle xNetIoHandle)
{
    NetIo_t *pxNet = (NetIo_t *)xNetIoHandle;

    if (pxNet != NULL)
    {
        mbedtls_ssl_close_notify(&(pxNet->xSsl));
    }
}

int NetIo_send(NetIoHandle xNetIoHandle, const unsigned char *pBuffer, size_t uBytesToSend)
{
    int res = 0;
    NetIo_t *pxNet = (NetIo_t *)xNetIoHandle;
    size_t uBytesRemaining = uBytesToSend;
    char *pIndex = (char *)pBuffer;

    int32_t tlsStatus = 0;
    struct zsock_pollfd pollFds;
    int32_t pollStatus;

    /* Initialize the file descriptor. */
    pollFds.events = ZSOCK_POLLOUT;
    pollFds.revents = 0;
    /* Set the file descriptor for poll. */
    pollFds.fd = xNetIoHandle->tcpSocket;

    /* `zsock_poll` checks if the socket is ready to send data.
     * Note: This is done to avoid blocking on SSL_write()
     * when TCP socket is not ready to accept more data for
     * network transmission (possibly due to a full TX buffer). */
    do {
      pollStatus = zsock_poll( &pollFds, 1, 0 );

      if( pollStatus > 0 )
      {
        LOG_DBG("Sending data: bytesRemaining= %d", uBytesRemaining);
        // Log data that is being sent
        LOG_HEXDUMP_DBG(pIndex, uBytesRemaining, "Data being sent");
        tlsStatus = (uint32_t) mbedtls_ssl_write(&(pxNet->xSsl), (const unsigned char *)pIndex, uBytesRemaining);
        if( 
          ( tlsStatus == MBEDTLS_ERR_SSL_TIMEOUT ) ||
          ( tlsStatus == MBEDTLS_ERR_SSL_WANT_READ ) ||
          ( tlsStatus == MBEDTLS_ERR_SSL_WANT_WRITE ) 
        ){
          LOG_ERR("Failed to send data. However, send can be retried on this error");
          break;
        }
        else if (tlsStatus < 0)
        {
          res = KVS_GENERATE_MBEDTLS_ERROR(tlsStatus);
          LOG_ERR("Failed to send data:  mbedTLSError= %d", tlsStatus);
          break;
        }
        uBytesRemaining -= tlsStatus;
        pIndex += tlsStatus;
      } 
      else if (pollStatus < 0) {
        res = -1;
        LOG_ERR("Failed to poll socket: %d", pollStatus);
      } 
      else {
        LOG_ERR("Socket not ready to send data");
      }
    } while (uBytesRemaining > 0);

    return res;

    // if (pxNet == NULL || pBuffer == NULL)
    // {
    //     res = KVS_ERROR_INVALID_ARGUMENT;
    // }
    // else
    // {
    //     do
    //     {
    //         n = mbedtls_ssl_write(&(pxNet->xSsl), (const unsigned char *)pIndex, uBytesRemaining);
    //         if (n < 0)
    //         {
    //             res = KVS_GENERATE_MBEDTLS_ERROR(n);
    //             LogError("SSL send error -%X", -res);
    //             break;
    //         }
    //         else if (n > uBytesRemaining)
    //         {
    //             res = KVS_ERROR_NETIO_SEND_MORE_THAN_REMAINING_DATA;
    //             LogError("SSL send error -%X", -res);
    //             break;
    //         }
    //         uBytesRemaining -= n;
    //         pIndex += n;
    //     } while (uBytesRemaining > 0);
    // }

    // return res;
}

int NetIo_recv(NetIoHandle xNetIoHandle, unsigned char *pBuffer, size_t uBufferSize, size_t *puBytesReceived)
{
    LOG_DBG("Receiving data");
    int n;
    int res = KVS_ERRNO_NONE;
    NetIo_t *pxNet = (NetIo_t *)xNetIoHandle;

    if (pxNet == NULL || pBuffer == NULL || puBytesReceived == NULL)
    {
      res = KVS_ERROR_INVALID_ARGUMENT;
    }
    else
    {
        n = mbedtls_ssl_read(&(pxNet->xSsl), pBuffer, uBufferSize);
        if (n < 0)
        {
          res = KVS_GENERATE_MBEDTLS_ERROR(n);
          LOG_ERR("SSL recv error -%X", -res);
        }
        else if (n > uBufferSize)
        {
          res = KVS_ERROR_NETIO_RECV_MORE_THAN_AVAILABLE_SPACE;
          LogError("SSL recv error -%X", -res);
        }
        else
        {
          *puBytesReceived = n;
        }
    }
    return res;
}

bool NetIo_isDataAvailable(NetIoHandle xNetIoHandle)
{
    NetIo_t *pxNet = (NetIo_t *)xNetIoHandle;
    bool bDataAvailable = false;
    struct timeval tv = {0};
    fd_set read_fds = {0};
    int fd = 0;

    if (pxNet != NULL)
    {
        // if (k_fifo_is_empty(&(pxNet->xFd->recv_q)))
        // {
        //     bDataAvailable = false;
        // }
        // else
        // {
        //     bDataAvailable = true;
        // }
        // fd = pxNet->xFd.fd;
        // if (fd >= 0)
        // {
        //     FD_ZERO(&read_fds);
        //     FD_SET(fd, &read_fds);

        //     tv.tv_sec = 0;
        //     tv.tv_usec = 0;

        //     if (select(fd + 1, &read_fds, NULL, NULL, &tv) >= 0)
        //     {
        //         if (FD_ISSET(fd, &read_fds))
        //         {
        //             bDataAvailable = true;
        //         }
        //     }
        // }
    }

    return bDataAvailable;
}

int NetIo_setRecvTimeout(NetIoHandle xNetIoHandle, unsigned int uRecvTimeoutMs)
{
    int res = KVS_ERRNO_NONE;
    NetIo_t *pxNet = (NetIo_t *)xNetIoHandle;

    if (pxNet == NULL)
    {
        res = KVS_ERROR_INVALID_ARGUMENT;
    }
    else
    {
        pxNet->uRecvTimeoutMs = (uint32_t)uRecvTimeoutMs;
        mbedtls_ssl_conf_read_timeout(&(pxNet->xConf), pxNet->uRecvTimeoutMs);
    }

    return res;
}

int NetIo_setSendTimeout(NetIoHandle xNetIoHandle, unsigned int uSendTimeoutMs)
{
    int res = KVS_ERRNO_NONE;
    NetIo_t *pxNet = (NetIo_t *)xNetIoHandle;
    int fd = 0;
    struct timeval tv = {0};

    if (pxNet == NULL)
    {
        res = KVS_ERROR_INVALID_ARGUMENT;
    }
    else
    {
        // pxNet->uSendTimeoutMs = (uint32_t)uSendTimeoutMs;
        // fd = pxNet->xFd.fd;
        // tv.tv_sec = uSendTimeoutMs / 1000;
        // tv.tv_usec = (uSendTimeoutMs % 1000) * 1000;

        // if (fd < 0)
        // {
        //     /* Do nothing when connection hasn't established. */
        // }
        // else if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (void *)&tv, sizeof(tv)) != 0)
        // {
        //     res = KVS_ERROR_NETIO_UNABLE_TO_SET_SEND_TIMEOUT;
        // }
        // else
        // {
        //     /* nop */
        // }
    }

    return res;
}
