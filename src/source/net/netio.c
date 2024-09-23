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
#include "kvs/certs.h"

LOG_MODULE_REGISTER(netio, LOG_LEVEL_DBG);

#define DEFAULT_CONNECTION_TIMEOUT_MS       (10 * 1000)

typedef struct NetIo 
{
    /* Basic ssl connection parameters */
    //mbedtls_net_context xFd;Not supported on zephyr, have to switch to net_context
    struct net_context *xFd;
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

NetIo_t *pxNet = NULL;

static int prvCreateX509Cert(NetIo_t *pxNet)
{
    int res = KVS_ERRNO_NONE;

    if (pxNet == NULL)
    {
        res = KVS_ERROR_INVALID_ARGUMENT;
    }
    else if ((pxNet->pRootCA = (mbedtls_x509_crt *)kvsMalloc(sizeof(mbedtls_x509_crt))) == NULL ||
        (pxNet->pCert = (mbedtls_x509_crt *)kvsMalloc(sizeof(mbedtls_x509_crt))) == NULL ||
        (pxNet->pPrivKey = (mbedtls_pk_context *)kvsMalloc(sizeof(mbedtls_pk_context))) == NULL)
    {
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

/* Callback function that gets called when data is received */
void my_recv_cb(
  struct net_context *context, struct net_pkt *pkt,
				      union net_ip_header *ip_hdr,
				      union net_proto_header *proto_hdr,
				      int status,
				      void *user_data)
{
    if (pkt) {
        // Data received, process packet here
    } else if (status == -ETIMEDOUT) {
        // Timeout occurred
    }
}

/* Function that sets up receive with a timeout */
int zephyr_net_recv_timeout(/*struct net_context*/void *context, unsigned char *buf, size_t len, uint32_t timeout_ms)
{
    int ret;

    /* Convert timeout_ms to Zephyr timeout format */
    k_timeout_t timeout = K_MSEC(timeout_ms);

    /* Set up the receive callback with the specified timeout */
    ret = net_context_recv(context, my_recv_cb, timeout, NULL);
    if (ret < 0) {
        // Handle error
        return ret;
    }

    return 0; // Success
}

/* Callback function that gets called when data is sent */
void my_send_cb(struct net_context *context, int status, void *user_data)
{
    if (status == 0) {
        // Data sent successfully
    } else {
        // Handle error (e.g., connection closed, failure, etc.)
    }
}

/* Function to send data (equivalent to mbedtls_net_send) */
int zephyr_net_send(/*struct net_context*/void *context, const unsigned char *buf, size_t len)
{
    struct net_pkt *pkt;
    int ret;

    // Cast context to NetIo_t
    struct net_context *ctx = (struct net_context *)context;

    //NetIo_t *pxNet = NULL;
    net_context_get(AF_INET, SOCK_STREAM, IPPROTO_TCP, &(pxNet->xFd));

    /* Allocate a network packet for the data */
    pkt = net_pkt_alloc_with_buffer(context, len, AF_UNSPEC, 0, K_NO_WAIT);
    if (!pkt) {
        return -ENOMEM;  // Failed to allocate packet
    }

    /* Copy the data into the packet */
    ret = net_pkt_write(pkt, buf, len);
    if (ret < 0) {
        net_pkt_unref(pkt);  // Free the packet on failure
        return ret;
    }

    /* Send the packet over the context (non-blocking send) */
    ret = net_context_send(pxNet->xFd, pkt->buffer->data, pkt->buffer->len, my_send_cb, K_MSEC(5), NULL);
    if (ret < 0) {
        net_pkt_unref(pkt);  // Free the packet on failure
        return ret;
    }

    return 0;  // Success
}

static int prvInitConfig(NetIo_t *pxNet, const char *pcHost, const char *pcRootCA, const char *pcCert, const char *pcPrivKey)
{
    int res = KVS_ERRNO_NONE;
    int retVal = 0;

    // // Log out the pointers
    // LOG_DBG("Root CA: %p", pcRootCA);
    // LOG_DBG("Device Cert: %p", pcCert);
    // LOG_DBG("Device Private Key: %p", pcPrivKey);

    // /* Log out the certificates  */
    // LOG_HEXDUMP_DBG(pcRootCA, strlen(pcRootCA), "Root CA");
    // LOG_HEXDUMP_DBG(pcCert, strlen(pcCert), "Device Cert");
    // LOG_HEXDUMP_DBG(pcPrivKey, strlen(pcPrivKey), "Device Private Key");
    // LOG_DBG("Root CA:\n%s\n", pcRootCA);
    // LOG_DBG("Device Cert:\n%s\n", pcCert);
    // LOG_DBG("Device Private Key:\n%s\n", pcPrivKey);

    if (pxNet == NULL)
    {
        res = KVS_ERROR_INVALID_ARGUMENT;
    }
    else
    {
        mbedtls_ssl_set_bio(&(pxNet->xSsl), &(pxNet->xFd), zephyr_net_send, NULL, zephyr_net_recv_timeout);

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

static void connect_cb(struct net_context *context, int status,
		       void *user_data)
{
	sa_family_t family = POINTER_TO_INT(user_data);

	if (net_context_get_family(context) != family) {
		// TC_ERROR("Connect family mismatch %d should be %d\n",
		//        net_context_get_family(context), family);
		// cb_failure = true;
		return;
	}

	//cb_failure = false;
}

static int prvConnect(NetIo_t *pxNet, const char *pcHost, const char *pcPort, const char *pcRootCA, const char *pcCert, const char *pcPrivKey)
{
    int res = KVS_ERRNO_NONE;
    int retVal = 0;

    struct sockaddr_in addr = {
		  .sin_family = AF_INET,
		  .sin_port = htons(443),
		  .sin_addr = { { { 3, 219, 160, 238 } } }
	  };

    if (pxNet == NULL || pcHost == NULL || pcPort == NULL)
    {
        res = KVS_ERROR_INVALID_ARGUMENT;
        LOG_ERR("Invalid argument");
    }
    else if ((pcRootCA != NULL && pcCert != NULL && pcPrivKey != NULL) && (res = prvCreateX509Cert(pxNet)) != KVS_ERRNO_NONE)
    {
        LOG_ERR("Failed to init x509 (err:-%X)", -res);
        /* Propagate the res error */
    }
    //else if ((retVal = mbedtls_net_connect(&(pxNet->xFd), pcHost, pcPort, MBEDTLS_NET_PROTO_TCP)) != 0)
    else if ((retVal = net_context_connect(pxNet->xFd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in), connect_cb, K_MSEC(200), INT_TO_POINTER(AF_INET)) != 0))
    {
        res = KVS_GENERATE_MBEDTLS_ERROR(retVal);
        LOG_ERR("Failed to connect to %s (err:-%d)", pcHost, retVal);
    }
    else if ((res = prvInitConfig(pxNet, pcHost, pcRootCA, pcCert, pcPrivKey)) != KVS_ERRNO_NONE)
    {
        LOG_ERR("Failed to config ssl (err:-%X)", -res);
        /* Propagate the res error */
    }
    else if ((retVal = mbedtls_ssl_handshake(&(pxNet->xSsl))) != 0)
    {
        res = KVS_GENERATE_MBEDTLS_ERROR(retVal);
        LOG_ERR("ssl handshake err (-%X)", -retVal);
    }
    else 
    {
        /* nop */
    }

    return res;
}

NetIoHandle NetIo_create(void)
{
    //Log out the call

    if ((pxNet = (NetIo_t *)kvsMalloc(sizeof(NetIo_t))) != NULL)
    {
        memset(pxNet, 0, sizeof(NetIo_t));

        //mbedtls_net_init(&(pxNet->xFd));
        int ret = net_context_get(AF_INET, SOCK_STREAM, IPPROTO_TCP, &(pxNet->xFd));

        if (ret < 0) {
            LOG_ERR("Failed to get context: %d", ret);
            kvsFree(pxNet);
            return NULL;
        }
        mbedtls_ssl_init(&(pxNet->xSsl));
        mbedtls_ssl_config_init(&(pxNet->xConf));
        mbedtls_ctr_drbg_init(&(pxNet->xCtrDrbg));
        mbedtls_entropy_init(&(pxNet->xEntropy));

        pxNet->uRecvTimeoutMs = DEFAULT_CONNECTION_TIMEOUT_MS;
        pxNet->uSendTimeoutMs = DEFAULT_CONNECTION_TIMEOUT_MS;

        if (mbedtls_ctr_drbg_seed(&(pxNet->xCtrDrbg), mbedtls_entropy_func, &(pxNet->xEntropy), NULL, 0) != 0)
        {
            NetIo_terminate(pxNet);
            pxNet = NULL;
        }
    }

    return pxNet;
}

void NetIo_terminate(NetIoHandle xNetIoHandle)
{
    NetIo_t *pxNet = (NetIo_t *)xNetIoHandle;

    if (pxNet != NULL)
    {
        mbedtls_ctr_drbg_free(&(pxNet->xCtrDrbg));
        mbedtls_entropy_free(&(pxNet->xEntropy));
        //mbedtls_net_free(&(pxNet->xFd));
        net_context_put(pxNet->xFd);
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
    return prvConnect(xNetIoHandle, pcHost, pcPort, aws_root_ca, aws_device_cert, aws_private_key);
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
    int n = 0;
    int res = KVS_ERRNO_NONE;
    NetIo_t *pxNet = (NetIo_t *)xNetIoHandle;
    size_t uBytesRemaining = uBytesToSend;
    char *pIndex = (char *)pBuffer;

    if (pxNet == NULL || pBuffer == NULL)
    {
        res = KVS_ERROR_INVALID_ARGUMENT;
    }
    else
    {
        do
        {
            n = mbedtls_ssl_write(&(pxNet->xSsl), (const unsigned char *)pIndex, uBytesRemaining);
            if (n < 0)
            {
                res = KVS_GENERATE_MBEDTLS_ERROR(n);
                LogError("SSL send error -%X", -res);
                break;
            }
            else if (n > uBytesRemaining)
            {
                res = KVS_ERROR_NETIO_SEND_MORE_THAN_REMAINING_DATA;
                LogError("SSL send error -%X", -res);
                break;
            }
            uBytesRemaining -= n;
            pIndex += n;
        } while (uBytesRemaining > 0);
    }

    return res;
}

int NetIo_recv(NetIoHandle xNetIoHandle, unsigned char *pBuffer, size_t uBufferSize, size_t *puBytesReceived)
{
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
            LogError("SSL recv error -%X", -res);
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
        if (k_fifo_is_empty(&(pxNet->xFd->recv_q)))
        {
            bDataAvailable = false;
        }
        else
        {
            bDataAvailable = true;
        }
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
