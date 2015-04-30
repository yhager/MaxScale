#pragma once
#include "buffer.h"

#ifdef __cplusplus
extern "C" {
#endif
void* get_lex(GWBUF*);
bool can_handle_sql_command(void*);
bool can_handle_server_command(char);
#ifdef __cplusplus
}
#endif
