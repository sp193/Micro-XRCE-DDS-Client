#include "tls_transport_internal.h"
#include <uxr/client/util/time.h>

#define UXR_MAX_WRITE_TLS_ATTEMPS 16

/*******************************************************************************
 * Static members.
 *******************************************************************************/
static uint8_t error_code;

/*******************************************************************************
 * Private function declarations.
 *******************************************************************************/
static bool send_tls_msg(void* instance, const uint8_t* buf, size_t len);
static bool recv_tls_msg(void* instance, uint8_t** buf, size_t* len, int timeout);
static uint8_t get_tls_error(void);
static size_t read_tls_data(uxrTLSTransport* transport, int timeout);

/*******************************************************************************
 * Private function definitions.
 *******************************************************************************/
bool send_tls_msg(void* instance, const uint8_t* buf, size_t len)
{
    bool rv = false;
    uxrTLSTransport* transport = (uxrTLSTransport*)instance;
    uint8_t msg_size_buf[2];

    msg_size_buf[0] = (uint8_t)(0x00FF & len);
    msg_size_buf[1] = (uint8_t)((0xFF00 & len) >> 8);
    uint8_t n_attemps = 0;
    size_t bytes_sent = 0;

    /* Send message size. */
    bool size_sent = false;
    do
    {
        uint8_t errcode;
        size_t send_rv = uxr_write_tls_data_platform(transport->platform, msg_size_buf, 2, &errcode);
        if (0 < send_rv)
        {
            bytes_sent = (size_t)(bytes_sent + send_rv);
            size_sent = (sizeof(msg_size_buf) == bytes_sent);
        }
        else
        {
            if (0 < errcode)
            {
                error_code = errcode;
                break;
            }
        }
        ++n_attemps;
    }
    while (!size_sent && n_attemps < UXR_MAX_WRITE_TLS_ATTEMPS);

    /* Send message payload. */
    bool payload_sent = false;
    if (size_sent)
    {
        n_attemps = 0;
        bytes_sent = 0;
        do
        {
            uint8_t errcode;
            size_t send_rv = uxr_write_tls_data_platform(transport->platform, 
                                                         buf + bytes_sent, 
                                                         len - bytes_sent, 
                                                         &errcode);
            if (0 < send_rv)
            {
                bytes_sent = (size_t)(bytes_sent + send_rv);
                payload_sent = (bytes_sent == len);
            }
            else
            {
                if (0 < errcode)
                {
                    error_code = errcode;
                    break;
                }
            }
            ++n_attemps;
        }
        while (!payload_sent && n_attemps < UXR_MAX_WRITE_TLS_ATTEMPS);
    }

    if (payload_sent)
    {
        rv = true;
    }
    else
    {
        uxr_disconnect_tls_platform(transport->platform);
    }

    return rv;
}

bool recv_tls_msg(void* instance, uint8_t** buf, size_t* len, int timeout)
{
    bool rv = false;
    uxrTLSTransport* transport = (uxrTLSTransport*)instance;

    size_t bytes_read = 0;
    do
    {
        int64_t time_init = uxr_millis();
        bytes_read = read_tls_data(transport, timeout);
        if (0 < bytes_read)
        {
            *buf = transport->input_buffer.buffer;
            *len = bytes_read;
            rv = true;
        }
        timeout -= (int)(uxr_millis() - time_init);
    }
    while ((0 == bytes_read) && (0 < timeout));

    return rv;
}

uint8_t get_tls_error(void)
{
    return error_code;
}

size_t read_tls_data(uxrTLSTransport* transport, int timeout)
{
    size_t rv = 0;
    bool exit_flag = false;

    /* State Machine. */
    while(!exit_flag)
    {
        switch (transport->input_buffer.state)
        {
            case UXR_TLS_BUFFER_EMPTY:
            {
                transport->input_buffer.position = 0;
                uint8_t size_buf[2];
                uint8_t errcode;
                size_t bytes_received = uxr_read_tls_data_platform(transport->platform, size_buf, 2, timeout, &errcode);
                if (0 < bytes_received)
                {
                    transport->input_buffer.msg_size = 0;
                    if (2 == bytes_received)
                    {
                        transport->input_buffer.msg_size = (size_t)(((uint16_t)size_buf[1] << 8) | size_buf[0]);
                        if (transport->input_buffer.msg_size != 0)
                        {
                            transport->input_buffer.state = UXR_TLS_SIZE_READ;
                        }
                    }
                    else
                    {
                        transport->input_buffer.msg_size = (size_t)size_buf[0];
                        transport->input_buffer.state = UXR_TLS_SIZE_INCOMPLETE;
                    }
                }
                else
                {
                    if (0 < errcode)
                    {
                        uxr_disconnect_tls_platform(transport->platform);
                    }
                    error_code = errcode;
                    exit_flag = true;
                }
                break;
            }
            case UXR_TLS_SIZE_INCOMPLETE:
            {
                uint8_t size_msb;
                uint8_t errcode;
                size_t bytes_received = uxr_read_tls_data_platform(transport->platform, &size_msb, 1, timeout, &errcode);
                if (0 < bytes_received)
                {
                    transport->input_buffer.msg_size = (size_t)(size_msb << 8) | transport->input_buffer.msg_size;
                    if (transport->input_buffer.msg_size != 0)
                    {
                        transport->input_buffer.state = UXR_TLS_SIZE_READ;
                    }
                    else
                    {
                        transport->input_buffer.state = UXR_TLS_BUFFER_EMPTY;
                    }
                }
                else
                {
                    if (0 < errcode)
                    {
                        uxr_disconnect_tls_platform(transport->platform);
                    }
                    error_code = errcode;
                    exit_flag = true;
                }
                break;
            }
            case UXR_TLS_SIZE_READ:
            {
                uint8_t errcode;
                size_t bytes_received = uxr_read_tls_data_platform(transport->platform,
                                                                   transport->input_buffer.buffer,
                                                                   transport->input_buffer.msg_size,
                                                                   timeout,
                                                                   &errcode);
                if (0 < bytes_received)
                {
                    if (bytes_received == transport->input_buffer.msg_size)
                    {
                        transport->input_buffer.state = UXR_TLS_MESSAGE_AVAILABLE;
                    }
                    else
                    {
                        transport->input_buffer.position = bytes_received;
                        transport->input_buffer.state = UXR_TLS_MESSAGE_INCOMPLETE;
                        exit_flag = true;
                    }
                }
                else
                {
                    if (0 < errcode)
                    {
                        uxr_disconnect_tls_platform(transport->platform);
                    }
                    error_code = errcode;
                    exit_flag = true;
                }
                break;
            }
            case UXR_TLS_MESSAGE_INCOMPLETE:
            {
                uint8_t errcode;
                size_t bytes_received = uxr_read_tls_data_platform(transport->platform,
                                                                   transport->input_buffer.buffer +
                                                                   transport->input_buffer.position,
                                                                   (size_t)(transport->input_buffer.msg_size -
                                                                            transport->input_buffer.position),
                                                                   timeout,
                                                                   &errcode);
                if (0 < bytes_received)
                {
                    transport->input_buffer.position = (size_t)(transport->input_buffer.position +  bytes_received);
                    if (transport->input_buffer.position == transport->input_buffer.msg_size)
                    {
                        transport->input_buffer.state = UXR_TLS_MESSAGE_AVAILABLE;
                    }
                    else
                    {
                        exit_flag = true;
                    }
                }
                else
                {
                    if (0 < errcode)
                    {
                        uxr_disconnect_tls_platform(transport->platform);
                    }
                    error_code = errcode;
                    exit_flag = true;
                }
                break;
            }
            case UXR_TLS_MESSAGE_AVAILABLE:
            {
                rv = transport->input_buffer.msg_size;
                transport->input_buffer.state = UXR_TLS_BUFFER_EMPTY;
                exit_flag = true;
                break;
            }
            default:
                rv = 0;
                exit_flag = true;
                break;
        }
    }

    return rv;
}


/*******************************************************************************
 * Public function definitions.
 *******************************************************************************/
bool uxr_init_tls_transport(uxrTLSTransport* transport, struct uxrTLSPlatform* platform, const char* ip, uint16_t port, const char *CAfile)
{
    bool rv = false;

    memset(transport, 0, sizeof(uxrTLSTransport));

    //Initializing OpenSSL
    SSL_load_error_strings();
    const SSL_METHOD *meth = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(meth);

    if (ctx != NULL)
    {
        if (SSL_CTX_load_verify_locations(ctx, CAfile, NULL) == 1)
        {
            SSL *ssl = SSL_new(ctx);

            if (ssl != NULL)
            {
                if(uxr_init_tls_platform(platform, ip, port, ctx, ssl))
                {
                    if (uxr_init_tls_connection_platform(platform, ssl, &error_code))
                    {
                        /* Setup platform. */
                        transport->platform = platform;

                        /* Interface setup. */
                        transport->comm.instance = (void*)transport;
                        transport->comm.send_msg = send_tls_msg;
                        transport->comm.recv_msg = recv_tls_msg;
                        transport->comm.comm_error = get_tls_error;
                        transport->comm.mtu = UXR_CONFIG_TCP_TRANSPORT_MTU;
                        transport->input_buffer.state = UXR_TLS_BUFFER_EMPTY;
                        rv = true;
                        error_code = 0;
                    }
                    else
                    {
                        printf("Failed to establish TLS connection.\n");
                    }
                }

                if (!rv)
                {
                    SSL_free(ssl);
                }
            }
            else
            {
                fprintf(stderr, "Failed to allocate SSL data structure.\n");
            }
        }
        else
        {
            printf("Failed to load CAfile %s\n", CAfile);
        }

        if (!rv)
        {
            SSL_CTX_free(ctx);
        }
    }
    else
    {
        fprintf(stderr, "Failed to allocate SSL context.\n");
    }

    return rv;
}

static bool uxr_validate_mutual_keys(SSL_CTX *ctx, const char *CAfile, const char *key, const char *cert)
{
    bool rv = false;

    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) == 1)
    {
        if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) == 1)
        {
            //Check if keys of keypair match.
            if (SSL_CTX_check_private_key(ctx) == 1)
            {
                if (SSL_CTX_load_verify_locations(ctx, CAfile, NULL) == 1)
                {
                    rv = true;
                }
                else
                {
                    fprintf(stderr, "Failed to load CAfile %s\n", CAfile);
                }
            }
            else
            {
                fprintf(stderr, "Keypair does not match");
            }
        }
        else
        {
            fprintf(stderr, "Failed to load certificate file %s.\n", cert);
        }
    }
    else
    {
        fprintf(stderr, "Failed to load private key file %s.\n", key);
    }

    return rv;
}

bool uxr_init_mutual_tls_transport(uxrTLSTransport* transport, struct uxrTLSPlatform* platform, const char* ip, uint16_t port, const char *CAfile, const char *key, const char *cert)
{
    bool rv = false;

    memset(transport, 0, sizeof(uxrTLSTransport));

    //Initializing OpenSSL
    SSL_load_error_strings();
    const SSL_METHOD *meth = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(meth);

    if (ctx != NULL)
    {
        if (uxr_validate_mutual_keys(ctx, CAfile, key, cert))
        {
            SSL *ssl = SSL_new(ctx);

            if (ssl != NULL)
            {
                if (uxr_init_tls_platform(platform, ip, port, ctx, ssl))
                {
                    if (uxr_init_tls_connection_platform(platform, ssl, &error_code))
                    {
                        if (SSL_get_peer_certificate(ssl) != NULL)
                        {
                            if (SSL_get_verify_result(ssl) == X509_V_OK)
                            {
                                /* Setup platform. */
                                transport->platform = platform;

                                /* Interface setup. */
                                transport->comm.instance = (void*)transport;
                                transport->comm.send_msg = send_tls_msg;
                                transport->comm.recv_msg = recv_tls_msg;
                                transport->comm.comm_error = get_tls_error;
                                transport->comm.mtu = UXR_CONFIG_TCP_TRANSPORT_MTU;
                                transport->input_buffer.state = UXR_TLS_BUFFER_EMPTY;
                                rv = true;
                                error_code = 0;
                            }
                            else
                            {
                                fprintf(stderr, "Failed to verify server certificate.\n");
                            }
                        }
                        else
                        {
                            fprintf(stderr, "Server did not present certificate.\n");
                        }
                    }
                    else
                    {
                        fprintf(stderr, "Failed to establish TLS connection.\n");
                    }
                }

                if (!rv)
                {
                    SSL_free(ssl);
                }
            }
            else
            {
                fprintf(stderr, "Failed to allocate SSL data structure.\n");
            }
        }

        if (!rv)
        {
            SSL_CTX_free(ctx);
        }
    }
    else
    {
        fprintf(stderr, "Failed to allocate SSL context.\n");
    }

    return rv;
}

bool uxr_close_tls_transport(uxrTLSTransport* transport)
{
    return uxr_close_tls_platform(transport->platform);
}
