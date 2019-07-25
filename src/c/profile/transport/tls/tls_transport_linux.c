#include <uxr/client/profile/transport/tls/tls_transport_linux.h>
#include "tls_transport_internal.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

static int ssl_last_error;

#ifdef PLATFORM_NAME_LINUX
static void sigpipe_handler(int fd)
{
    (void)fd;
}
#endif

bool uxr_init_tls_platform(struct uxrTLSPlatform* platform, const char* ip, uint16_t port, SSL_CTX *ctx, SSL *ssl)
{
    bool rv = false;

    memset(platform, 0, sizeof(struct uxrTLSPlatform));

    ssl_last_error = 0;

    /* Socket initialization. */
    platform->poll_fd.fd = socket(PF_INET, SOCK_STREAM, 0);
    if (-1 != platform->poll_fd.fd)
    {
#ifdef PLATFORM_NAME_LINUX
        signal(SIGPIPE, sigpipe_handler);
#endif

        /* Remote IP setup. */
        struct sockaddr_in temp_addr;
        temp_addr.sin_family = AF_INET;
        temp_addr.sin_port = htons(port);
        temp_addr.sin_addr.s_addr = inet_addr(ip);
        platform->remote_addr = *((struct sockaddr *) &temp_addr);

        /* Poll setup. */
        platform->poll_fd.events = POLLIN;

        /* Server connection. */
        int connected = connect(platform->poll_fd.fd,
                                &platform->remote_addr,
                                sizeof(platform->remote_addr));

        if (connected == 0)
        {
            SSL_set_fd(ssl, platform->poll_fd.fd);
            platform->ctx = ctx;
            platform->ssl = ssl;
        }

        rv = (0 == connected);
    }
    return rv;
}

bool uxr_close_tls_platform(struct uxrTLSPlatform* platform)
{
    return (-1 == platform->poll_fd.fd) ? true : (0 == close(platform->poll_fd.fd));
}

size_t uxr_write_tls_data_platform(struct uxrTLSPlatform* platform,
                                   const uint8_t* buf,
                                   size_t len,
                                   uint8_t* errcode)
{
    const int fd = platform->poll_fd.fd;
    int bytes_sent = 0;

    if (platform->ssl != NULL)
    {
        while ((bytes_sent = SSL_write(platform->ssl, (void*)buf, (int)len)) < 0)
        {
            int err = SSL_get_error(platform->ssl, bytes_sent);
            fd_set rset, wset;
            struct timeval timeout;

            ssl_last_error = err;

            switch (err)
            {
                case SSL_ERROR_WANT_READ:
                case SSL_ERROR_WANT_WRITE:
                    break;
                default:
                    fprintf(stderr, "uxr_write_tls_data_platform: error %d.\n", err);
                    *errcode = (uint8_t)err;
                    return 0;
            }

            FD_ZERO(&rset);
            FD_ZERO(&wset);

            // Determine whether to wait for a socket read or write operation.
            switch (err)
            {
                case SSL_ERROR_WANT_READ:
                    FD_SET(fd, &rset);
                    break;
                case SSL_ERROR_WANT_WRITE:
                    FD_SET(fd, &wset);
                    break;
            }

            timeout.tv_sec = TLS_TCP_TIMEOUT;
            timeout.tv_usec = 0;

            if (select(fd + 1, &rset, &wset, NULL, &timeout) == 0)
            {
                fprintf(stderr, "uxr_write_tls_data_platform: timed out.\n");
                *errcode = 1;
                return 0;
            }
        }
    }
    else
    {
        *errcode = 1;
    }
    return (size_t)bytes_sent;
}

size_t uxr_read_tls_data_platform(struct uxrTLSPlatform* platform,
                                  uint8_t* buf,
                                  size_t len,
                                  int timeout,
                                  uint8_t* errcode)
{
    size_t rv = 0;

    if (platform->ssl != NULL)
    {
        int poll_rv = poll(&platform->poll_fd, 1, timeout);
        if (0 < poll_rv)
        {
            const int fd = platform->poll_fd.fd;
            int bytes_received;

            while ((bytes_received = SSL_read(platform->ssl, (void*)buf, (int)len)) < 0)
            {
                int err = SSL_get_error(platform->ssl, bytes_received);
                fd_set rset, wset;
                struct timeval socket_timeout;

                ssl_last_error = err;

                switch (err)
                {
                    case SSL_ERROR_WANT_READ:
                    case SSL_ERROR_WANT_WRITE:
                        break;
                    default:
                        fprintf(stderr, "uxr_read_tls_data_platform: error %d.\n", err);
                        *errcode = (uint8_t)err;
                        return 0;
                }

                FD_ZERO(&rset);
                FD_ZERO(&wset);

                // Determine whether to wait for a socket read or write operation.
                switch (err)
                {
                    case SSL_ERROR_WANT_READ:
                        FD_SET(fd, &rset);
                        break;
                    case SSL_ERROR_WANT_WRITE:
                        FD_SET(fd, &wset);
                        break;
                }

                socket_timeout.tv_sec = TLS_TCP_TIMEOUT;
                socket_timeout.tv_usec = 0;

                if (select(fd + 1, &rset, &wset, NULL, &socket_timeout) == 0)
                {
                    fprintf(stderr, "uxr_read_tls_data_platform: timed out.\n");
                    *errcode = 1;
                    return 0;
                }
            }

            rv = (size_t)bytes_received;
        }
        else
        {
            *errcode = (0 == poll_rv) ? 0 : 1;
        }
    }
    else
    {
        *errcode = 1;
    }
    return rv;
}

static void uxr_ssl_shutdown_platform(struct uxrTLSPlatform* platform)
{
    int ret;

    if (platform->ssl != NULL)
    {
        const int fd = platform->poll_fd.fd;

        while ((ret = SSL_shutdown(platform->ssl)) < 0)
        {
            int err = SSL_get_error(platform->ssl, ret);
            fd_set rset, wset;
            struct timeval socket_timeout;

            ssl_last_error = err;

            switch (err)
            {
                case SSL_ERROR_WANT_READ:
                case SSL_ERROR_WANT_WRITE:
                    break;
                default:
                    fprintf(stderr, "uxr_ssl_shutdown_platform: error %d.\n", err);
                    return; //Do not continue.
            }

            FD_ZERO(&rset);
            FD_ZERO(&wset);

            // Determine whether to wait for a socket read or write operation.
            switch (err)
            {
                case SSL_ERROR_WANT_READ:
                    FD_SET(fd, &rset);
                    break;
                case SSL_ERROR_WANT_WRITE:
                    FD_SET(fd, &wset);
                    break;
            }

            socket_timeout.tv_sec = TLS_TCP_TIMEOUT;
            socket_timeout.tv_usec = 0;

            if (select(fd + 1, &rset, &wset, NULL, &socket_timeout) == 0)
            {
                fprintf(stderr, "uxr_ssl_shutdown_platform: timed out.\n");
                break;
            }
        }
    }
}

void uxr_disconnect_tls_platform(struct uxrTLSPlatform* platform)
{
    switch (ssl_last_error)
    {
        case SSL_ERROR_SYSCALL:
        case SSL_ERROR_SSL:
            // Do not call SSL_shutdown() if these errors occurred.
            break;
        default:
            uxr_ssl_shutdown_platform(platform);
    }

    if (platform->poll_fd.fd >= 0)
    {
        close(platform->poll_fd.fd);
        platform->poll_fd.fd = -1;
    }

    if (platform->ssl != NULL)
    {
        SSL_free(platform->ssl);
        platform->ssl = NULL;
    }

    if (platform->ctx != NULL)
    {
        SSL_CTX_free(platform->ctx);
        platform->ctx = NULL;
    }
}

bool uxr_set_blocking_mode_tls_transport_platform(struct uxrTLSPlatform* platform, bool block)
{
    const int fd = platform->poll_fd.fd;
    const int flags = fcntl(fd, F_GETFL, 0);
    if (flags != -1)
    {
        return (fcntl(fd, F_SETFL, block ? (flags & ~O_NONBLOCK) : (flags | O_NONBLOCK)) == 0);
    }

    return false;
}

bool uxr_init_tls_connection_platform(struct uxrTLSPlatform* platform, SSL *ssl, uint8_t* errcode)
{
    const int fd = platform->poll_fd.fd;
    int ret;

    if (!uxr_set_blocking_mode_tls_transport_platform(platform, false))
    {
        fprintf(stderr, "uxr_init_tls_connection_platform: Failed to change socket mode: blocking -> non-blocking.\n");
        *errcode = 1;
        return false;
    }

    while ((ret = SSL_connect(ssl)) < 0)
    {
        int err = SSL_get_error(ssl, ret);
        fd_set rset, wset;
        struct timeval socket_timeout;

        ssl_last_error = err;

        switch (err)
        {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                break;
            default:
                fprintf(stderr, "uxr_init_tls_connection_platform: TLS Handshake failed (%d).\n", err);
                *errcode = (uint8_t)err;
                return false;
        }

        FD_ZERO(&rset);
        FD_ZERO(&wset);

        // Determine whether to wait for a socket read or write operation.
        switch (err)
        {
            case SSL_ERROR_WANT_READ:
                FD_SET(fd, &rset);
                break;
            case SSL_ERROR_WANT_WRITE:
                FD_SET(fd, &wset);
                break;
        }

        socket_timeout.tv_sec = TLS_TCP_TIMEOUT;
        socket_timeout.tv_usec = 0;

        if (select(fd + 1, &rset, &wset, NULL, &socket_timeout) == 0)
        {
            fprintf(stderr, "uxr_init_tls_connection_platform: timed out during TLS handshake.\n");
            *errcode = 1;
            return false;
        }
    }

    *errcode = 0;
    return true;
}
