/*
 * AWS IoT Device Embedded C SDK for ZephyrRTOS
 * Copyright (C) 2021 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/* Standard includes. */
#include <assert.h>
#include <string.h>
#include <errno.h>

/* Zephyr socket includes */
#include <zephyr/net/socket.h>

#include "kvs/transport/sockets_zephyr.h"
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER( sockets_zep, LOG_LEVEL_WRN );
/*-----------------------------------------------------------*/

/**
 * @brief Number of milliseconds in one second.
 */
#define ONE_SEC_TO_MS    ( 1000 )

/**
 * @brief Number of microseconds in one millisecond.
 */
#define ONE_MS_TO_US     ( 1000 )

/*-----------------------------------------------------------*/

/**
 * @brief Resolve a host name.
 *
 * @param[in] pHostName Server host name.
 * @param[in] hostNameLength Length associated with host name.
 * @param[out] pListHead The output parameter to return the list containing
 * resolved DNS records.
 *
 * @return #SOCKETS_SUCCESS if successful; #SOCKETS_DNS_FAILURE, #SOCKETS_CONNECT_FAILURE on error.
 */
static SocketStatus_t resolveHostName( const char * pHostName,
                                       size_t hostNameLength,
                                       struct zsock_addrinfo ** pListHead );

/**
 * @brief Traverse list of DNS records until a connection is established.
 *
 * @param[in] pListHead List containing resolved DNS records.
 * @param[in] pHostName Server host name.
 * @param[in] hostNameLength Length associated with host name.
 * @param[in] port Server port in host-order.
 * @param[out] pTcpSocket The output parameter to return the created socket.
 *
 * @return #SOCKETS_SUCCESS if successful; #SOCKETS_CONNECT_FAILURE on error.
 */
static SocketStatus_t attemptConnection( struct zsock_addrinfo * pListHead,
                                         const char * pHostName,
                                         size_t hostNameLength,
                                         uint16_t port,
                                         int32_t * pTcpSocket );

/**
 * @brief Connect to server using the provided address record.
 *
 * @param[in, out] pAddrInfo Address record of the server.
 * @param[in] port Server port in host-order.
 * @param[in] pTcpSocket Socket handle.
 *
 * @return #SOCKETS_SUCCESS if successful; #SOCKETS_CONNECT_FAILURE on error.
 */
static SocketStatus_t connectToAddress( struct sockaddr * pAddrInfo,
                                        uint16_t port,
                                        int32_t tcpSocket );

/*-----------------------------------------------------------*/

static SocketStatus_t resolveHostName( const char * pHostName,
                                       size_t hostNameLength,
                                       struct zsock_addrinfo ** pListHead )
{
    SocketStatus_t returnStatus = SOCKETS_SUCCESS;
    int32_t dnsStatus = -1;
    struct zsock_addrinfo hints;

    assert( pHostName != NULL );
    assert( hostNameLength > 0 );

    /* Unused parameter. These parameters are used only for logging. */
    ( void ) hostNameLength;

    /* Add hints to retrieve only TCP sockets in getaddrinfo. */
    ( void ) memset( &hints, 0, sizeof( hints ) );

    /* Address family of either IPv4 or IPv6. */
    hints.ai_family = AF_UNSPEC;
    /* TCP Socket. */
    hints.ai_socktype = ( int32_t ) SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    /* Perform a DNS lookup on the given host name. */
    dnsStatus = zsock_getaddrinfo( pHostName, NULL, &hints, pListHead );

    if( dnsStatus != 0 )
    {
        LOG_ERR("Failed to resolve DNS: Hostname=, ErrorCode.\n");
        returnStatus = SOCKETS_DNS_FAILURE;
    }

    return returnStatus;
}
/*-----------------------------------------------------------*/

static SocketStatus_t connectToAddress( struct sockaddr * pAddrInfo,
                                        uint16_t port,
                                        int32_t tcpSocket )
{
    SocketStatus_t returnStatus = SOCKETS_SUCCESS;
    int32_t connectStatus = 0;
    char resolvedIpAddr[ INET6_ADDRSTRLEN ];
    socklen_t addrInfoLength;
    uint16_t netPort = 0;
    struct sockaddr_in * pIpv4Address;
    struct sockaddr_in6 * pIpv6Address;

    assert( pAddrInfo != NULL );
    assert( pAddrInfo->sa_family == AF_INET || pAddrInfo->sa_family == AF_INET6 );
    assert( tcpSocket >= 0 );

    /* Convert port from host byte order to network byte order. */
    netPort = htons( port );

    if( pAddrInfo->sa_family == ( sa_family_t ) AF_INET )
    {
        pIpv4Address = ( struct sockaddr_in * ) pAddrInfo;
        /* Store IPv4 in string to log. */
        pIpv4Address->sin_port = netPort;
        addrInfoLength = ( socklen_t ) sizeof( struct sockaddr_in );
        ( void ) zsock_inet_ntop( ( int32_t ) pAddrInfo->sa_family,
                                  &pIpv4Address->sin_addr,
                                  resolvedIpAddr,
                                  addrInfoLength );
    }
    else
    {
        pIpv6Address = ( struct sockaddr_in6 * ) pAddrInfo;
        /* Store IPv6 in string to log. */
        pIpv6Address->sin6_port = netPort;
        addrInfoLength = ( socklen_t ) sizeof( struct sockaddr_in6 );
        ( void ) zsock_inet_ntop( ( int32_t ) pAddrInfo->sa_family,
                                  &pIpv6Address->sin6_addr,
                                  resolvedIpAddr,
                                  addrInfoLength );
    }

    LOG_DBG("Attempting to connect to server using the resolved IP address:"
                " IP address=%s.",
                resolvedIpAddr );

    /* Attempt to connect. */
    connectStatus = zsock_connect( tcpSocket, pAddrInfo, addrInfoLength );

    if( connectStatus == -1 )
    {
        LOG_WRN("Failed to connect to server using the resolved IP address: IP address=%s.",
                   resolvedIpAddr );
        ( void ) zsock_close( tcpSocket );
        returnStatus = SOCKETS_CONNECT_FAILURE;
    }

    return returnStatus;
}
/*-----------------------------------------------------------*/

static SocketStatus_t attemptConnection( struct zsock_addrinfo * pListHead,
                                         const char * pHostName,
                                         size_t hostNameLength,
                                         uint16_t port,
                                         int32_t * pTcpSocket )
{
    SocketStatus_t returnStatus = SOCKETS_CONNECT_FAILURE;
    const struct zsock_addrinfo * pIndex = NULL;

    assert( pListHead != NULL );
    assert( pHostName != NULL );
    assert( hostNameLength > 0 );
    assert( pTcpSocket != NULL );

    /* Unused parameters when logging is disabled. */
    ( void ) pHostName;
    ( void ) hostNameLength;

    LOG_DBG( "Attempting to connect to: Host=%.*s.",
                ( int32_t ) hostNameLength,
                pHostName );

    /* Attempt to connect to one of the retrieved DNS records. */
    for( pIndex = pListHead; pIndex != NULL; pIndex = pIndex->ai_next )
    {
        LOG_DBG( "Creating a TCP socket." );
        *pTcpSocket = zsock_socket( pIndex->ai_family,
                                    pIndex->ai_socktype,
                                    pIndex->ai_protocol );

        LOG_DBG( "Created a TCP socket: Socket=%d.", *pTcpSocket );

        if( *pTcpSocket == -1 )
        {
            continue;
        }

        // Log out the resolved IP address
        char resolvedIpAddr[ INET6_ADDRSTRLEN ];
        if( pIndex->ai_family == AF_INET )
        {
            struct sockaddr_in * pIpv4Address = ( struct sockaddr_in * ) pIndex->ai_addr;
            ( void ) zsock_inet_ntop( ( int32_t ) pIndex->ai_family,
                                      &pIpv4Address->sin_addr,
                                      resolvedIpAddr,
                                      sizeof( resolvedIpAddr ) );
        }
        else
        {
            struct sockaddr_in6 * pIpv6Address = ( struct sockaddr_in6 * ) pIndex->ai_addr;
            ( void ) zsock_inet_ntop( ( int32_t ) pIndex->ai_family,
                                      &pIpv6Address->sin6_addr,
                                      resolvedIpAddr,
                                      sizeof( resolvedIpAddr ) );
        }
        LOG_DBG( "Attempting to connect to server using the resolved IP address: IP address=%s.",
                    resolvedIpAddr );

        /* Attempt to connect to a resolved DNS address of the host. */
        returnStatus = connectToAddress( pIndex->ai_addr, port, *pTcpSocket );

        /* If connected to an IP address successfully, exit from the loop. */
        if( returnStatus == SOCKETS_SUCCESS )
        {
            break;
        }
    }

    if( returnStatus == SOCKETS_SUCCESS )
    {
        LOG_DBG( "Established TCP connection: Server" );
    }
    else
    {
        LOG_ERR("Could not connect to any resolved IP address from %.*s.",
                    ( int32_t ) hostNameLength,
                    pHostName);
    }

    zsock_freeaddrinfo( pListHead );

    return returnStatus;
}
/*-----------------------------------------------------------*/

SocketStatus_t Sockets_Connect( int32_t * pTcpSocket,
                                const ServerInfo_t * pServerInfo,
                                uint32_t sendTimeoutMs,
                                uint32_t recvTimeoutMs )
{
    SocketStatus_t returnStatus = SOCKETS_SUCCESS;
    struct zsock_addrinfo * pListHead = NULL;

    if( pServerInfo == NULL )
    {
        LOG_ERR("Parameter check failed: pServerInfo is NULL.");
        returnStatus = SOCKETS_INVALID_PARAMETER;
    }
    else if( pServerInfo->pHostName == NULL )
    {
        LOG_ERR("Parameter check failed: pServerInfo->pHostName is NULL.");
        returnStatus = SOCKETS_INVALID_PARAMETER;
    }
    else if( pTcpSocket == NULL )
    {
        LOG_ERR("Parameter check failed: pTcpSocket is NULL.");
        returnStatus = SOCKETS_INVALID_PARAMETER;
    }
    else if( pServerInfo->hostNameLength == 0UL )
    {
        LOG_ERR("Parameter check failed: hostNameLength must be greater than 0.");
        returnStatus = SOCKETS_INVALID_PARAMETER;
    }
    else
    {
        /* Empty else. */
    }

    if( returnStatus == SOCKETS_SUCCESS )
    {
        LOG_DBG("Attempting to resolve the host name: Host=%.*s.",
                    ( int32_t ) pServerInfo->hostNameLength,
                    pServerInfo->pHostName );
        returnStatus = resolveHostName( pServerInfo->pHostName,
                                        pServerInfo->hostNameLength,
                                        &pListHead );
    }

    if( returnStatus == SOCKETS_SUCCESS )
    {
        LOG_DBG("Resolved the host name: Host=%.*s.",
                    ( int32_t ) pServerInfo->hostNameLength,
                    pServerInfo->pHostName );

        // Log out resolved IP addresses
        struct zsock_addrinfo * pIndex = NULL;
        char resolvedIpAddr[ INET6_ADDRSTRLEN ];
        for( pIndex = pListHead; pIndex != NULL; pIndex = pIndex->ai_next )
        {
            if( pIndex->ai_family == AF_INET )
            {
                struct sockaddr_in * pIpv4Address = ( struct sockaddr_in * ) pIndex->ai_addr;
                ( void ) zsock_inet_ntop( ( int32_t ) pIndex->ai_family,
                                          &pIpv4Address->sin_addr,
                                          resolvedIpAddr,
                                          sizeof( resolvedIpAddr ) );
            }
            else
            {
                struct sockaddr_in6 * pIpv6Address = ( struct sockaddr_in6 * ) pIndex->ai_addr;
                ( void ) zsock_inet_ntop( ( int32_t ) pIndex->ai_family,
                                          &pIpv6Address->sin6_addr,
                                          resolvedIpAddr,
                                          sizeof( resolvedIpAddr ) );
            }

            LOG_DBG("Resolved IP address: %s", resolvedIpAddr);
        }
        //
        returnStatus = attemptConnection( pListHead,
                                          pServerInfo->pHostName,
                                          pServerInfo->hostNameLength,
                                          pServerInfo->port,
                                          pTcpSocket );
    }

    return returnStatus;
}
/*-----------------------------------------------------------*/

SocketStatus_t Sockets_Disconnect( int32_t tcpSocket )
{
    SocketStatus_t returnStatus = SOCKETS_SUCCESS;

    if( tcpSocket >= 0 )
    {
        ( void ) zsock_shutdown( tcpSocket, ZSOCK_SHUT_RDWR );
        ( void ) zsock_close( tcpSocket );
    }
    else
    {
        LOG_ERR("Parameter check failed: tcpSocket was negative.");
        returnStatus = SOCKETS_INVALID_PARAMETER;
    }

    return returnStatus;
}
/*-----------------------------------------------------------*/
