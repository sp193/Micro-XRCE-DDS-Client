#include "udp_transport_internal.h"

/*******************************************************************************
 * Private function declarations.
 *******************************************************************************/
static bool send_udp_msg(void* instance, const uint8_t* buf, size_t len);
static bool recv_udp_msg(void* instance, uint8_t** buf, size_t* len, int timeout);

/*******************************************************************************
 * Private function definitions.
 *******************************************************************************/
static bool send_udp_msg(void* instance, const uint8_t* buf, size_t len)
{
    bool rv = false;
    uxrUDPTransport* transport = (uxrUDPTransport*)instance;

    uint8_t errcode;
    size_t bytes_sent = uxr_write_udp_data_platform(transport->platform, buf, len, &errcode);
    if (0 < bytes_sent)
    {
        rv = (bytes_sent == len);
    }
    else
    {
        transport->comm.error_code = errcode;
    }
    return rv;
}

static bool recv_udp_msg(void* instance, uint8_t** buf, size_t* len, int timeout)
{
    bool rv = false;
    uxrUDPTransport* transport = (uxrUDPTransport*)instance;

    uint8_t errcode;
    size_t bytes_received = uxr_read_udp_data_platform(transport->platform,
                                                       transport->buffer,
                                                       sizeof(transport->buffer),
                                                       timeout,
                                                       &errcode);
    if (0 < bytes_received)
    {
        *buf = transport->buffer;
        *len = bytes_received;
        rv = true;
    }
    else
    {
        transport->comm.error_code = errcode;
    }
    return rv;
}

/*******************************************************************************
 * Public function definitions.
 *******************************************************************************/
bool uxr_init_udp_transport(uxrUDPTransport* transport, struct uxrUDPPlatform* platform, const char* ip, uint16_t port)
{
    bool rv = false;

    if (uxr_init_udp_platform(platform, ip, port))
    {
        /* Setup platform. */
        transport->platform = platform;

        /* Setup interface. */
        transport->comm.instance = (void*)transport;
        transport->comm.send_msg = send_udp_msg;
        transport->comm.recv_msg = recv_udp_msg;
        transport->comm.error_code = 0;
        transport->comm.mtu = UXR_CONFIG_UDP_TRANSPORT_MTU;
        rv = true;
    }
    return rv;
}

bool uxr_close_udp_transport(uxrUDPTransport* transport)
{
    return uxr_close_udp_platform(transport->platform);
}
