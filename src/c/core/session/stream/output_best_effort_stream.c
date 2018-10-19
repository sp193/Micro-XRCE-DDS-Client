#include "output_best_effort_stream_internal.h"
#include "seq_num_internal.h"

#include <ucdr/microcdr.h>

//==================================================================
//                              PUBLIC
//==================================================================
void uxr_init_output_best_effort_stream(uxrOutputBestEffortStream* stream, uint8_t* buffer, size_t size, uint8_t offset)
{
    stream->buffer = buffer;
    stream->offset = offset;
    stream->size = size;

    uxr_reset_output_best_effort_stream(stream);
}

void uxr_reset_output_best_effort_stream(uxrOutputBestEffortStream* stream)
{
    stream->writer = stream->offset;
    stream->last_send = UINT16_MAX;
}

bool uxr_prepare_best_effort_buffer_to_write(uxrOutputBestEffortStream* stream, size_t size, ucdrBuffer* mb)
{
    bool available_to_write = stream->writer + size <= stream->size;
    if(available_to_write)
    {
        ucdr_init_buffer_offset(mb, stream->buffer, (uint32_t)(stream->writer + size), (uint32_t)stream->writer);
        stream->writer += size;
    }

    return available_to_write;
}

bool uxr_prepare_best_effort_buffer_to_send(uxrOutputBestEffortStream* stream, uint8_t** buffer, size_t* length, uint16_t* seq_num)
{
    bool data_to_send = stream->writer > stream->offset;
    if(data_to_send)
    {
        stream->last_send = uxr_seq_num_add(stream->last_send, 1);

        *seq_num = stream->last_send;
        *buffer = stream->buffer;
        *length = stream->writer;

        stream->writer = stream->offset;
    }

    return data_to_send;
}

