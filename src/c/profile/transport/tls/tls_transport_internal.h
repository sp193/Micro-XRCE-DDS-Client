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

#ifndef _SRC_C_PROFILE_TRANSPORT_TLS_TLS_TRANSPORT_INTERNAL_H_
#define _SRC_C_PROFILE_TRANSPORT_TLS_TLS_TRANSPORT_INTERNAL_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <uxr/client/profile/transport/tls/tls_transport.h>
#include <string.h>
#include <openssl/ssl.h>

#define TLS_TCP_TIMEOUT 10

bool uxr_init_tls_platform(struct uxrTLSPlatform* platform, const char* ip, uint16_t port, SSL_CTX *ctx, SSL *ssl);
bool uxr_close_tls_platform(struct uxrTLSPlatform* platform);

size_t uxr_write_tls_data_platform(struct uxrTLSPlatform* platform,
                                   const uint8_t* buf,
                                   size_t len,
                                   uint8_t* errcode);

size_t uxr_read_tls_data_platform(struct uxrTLSPlatform* platform,
                                  uint8_t* buf,
                                  size_t len,
                                  int timeout,
                                  uint8_t* errcode);

void uxr_disconnect_tls_platform(struct uxrTLSPlatform* platform);

bool uxr_set_blocking_mode_tls_transport_platform(struct uxrTLSPlatform* platform, bool block);

bool uxr_init_tls_connection_platform(struct uxrTLSPlatform* platform, SSL *ssl, uint8_t* errcode);

#ifdef __cplusplus
}
#endif

#endif //_SRC_C_PROFILE_TRANSPORT_TLS_TLS_TRANSPORT_INTERNAL_H_
