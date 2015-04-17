#pragma once
#include "buffer.h"

#ifdef __cplusplus
extern "C" {
#endif
    void * get_lex(GWBUF* querybuf);
    bool is_select_command(void* lex);
#ifdef __cplusplus
}
#endif
