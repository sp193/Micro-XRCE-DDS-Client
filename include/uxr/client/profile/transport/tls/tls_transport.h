// Copyright 2018 Proyectos y Sistemas de Mantenimiento SL (eProsima).
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef _UXR_CLIENT_TLS_TRANSPORT_H_
#define _UXR_CLIENT_TLS_TRANSPORT_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <uxr/client/core/communication/communication.h>
#include <uxr/client/config.h>
#include <uxr/client/visibility.h>

typedef enum uxrTLSInputBufferState
{
    UXR_TLS_BUFFER_EMPTY,
    UXR_TLS_SIZE_INCOMPLETE,
    UXR_TLS_SIZE_READ,
    UXR_TLS_MESSAGE_INCOMPLETE,
    UXR_TLS_MESSAGE_AVAILABLE

} uxrTLSInputBufferState;

typedef struct uxrTLSInputBuffer
{
    uint8_t buffer[UXR_CONFIG_TCP_TRANSPORT_MTU];
    size_t position;
    uxrTLSInputBufferState state;
    size_t msg_size;

} uxrTLSInputBuffer;

struct uxrTLSPlatform;

typedef struct uxrTLSTransport
{
    uxrTLSInputBuffer input_buffer;
    uxrCommunication comm;
    struct uxrTLSPlatform* platform;

} uxrTLSTransport;

/**
 * @brief Initializes a TLS transport.
 * @param transport The uninitialized transport structure used for managing the transport.
 *                  This structure must be accesible during the connection.
 * @param platform  A structure that contains the platform dependencies.
 * @param ip        The IP address of the Agent.
 * @param port      The port of the Agent.
 * @param CAfile    The path to the CAfile, containing the certificates for the CA.
 * @return `true` in case of successful initialization. `false` in other case.
 */
UXRDLLAPI bool uxr_init_tls_transport(
        uxrTLSTransport* transport,
        struct uxrTLSPlatform* platform,
        const char* ip,
        uint16_t port,
        const char *CAfile);

/**
 * @brief Initializes a TLS transport with mutual authentication.
 * @param transport The uninitialized transport structure used for managing the transport.
 *                  This structure must be accesible during the connection.
 * @param platform  A structure that contains the platform dependencies.
 * @param ip        The IP address of the Agent.
 * @param port      The port of the Agent.
 * @param CAfile    The path to the CAfile, containing the certificates for the CA.
 * @param key       The path to the private key PEM.
 * @param cert      The path to the public certificate PEM.
 * @return `true` in case of successful initialization. `false` in other case.
 */
UXRDLLAPI bool uxr_init_mutual_tls_transport(
        uxrTLSTransport* transport,
        struct uxrTLSPlatform* platform,
        const char* ip,
        uint16_t port,
        const char *CAfile,
        const char *key,
        const char *cert);

/**
 * @brief Closes a TLS transport.
 * @param transport The transport structure.
 * @return `true` in case of successful closing. `false` in other case.
 */
UXRDLLAPI bool uxr_close_tls_transport(uxrTLSTransport* transport);

#ifdef __cplusplus
}
#endif

#endif //_UXR_CLIENT_TLS_TRANSPORT_H_
