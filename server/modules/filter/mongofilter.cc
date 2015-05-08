#define MYSQL_SERVER

#include <sql_class.h>

#include "skygw_debug.h"
#include "log_manager.h"
#include "query_classifier.h"

#include "mongofilter.h"

void* get_lex(GWBUF* querybuf)
{
  parsing_info_t* pi;
  MYSQL*          mysql;
  THD*            thd;

  if (!GWBUF_IS_PARSED(querybuf))
  {
      return NULL;
  }
  pi = (parsing_info_t *)gwbuf_get_buffer_object_data(querybuf,
                                                      GWBUF_PARSING_INFO);

  if (pi == NULL)
  {
      return NULL;
  }

  if ((mysql = (MYSQL *)pi->pi_handle) == NULL ||
      (thd = (THD *)mysql->thd) == NULL)
  {
      ss_dassert(mysql != NULL &&
                 thd != NULL);
      return NULL;
  }

  return (void *)thd->lex;
}

bool can_handle_sql_command(void *lex)
{
    enum_sql_command sql_command = lex ? ((LEX*)lex)->sql_command : SQLCOM_END;
    switch (sql_command)
    {
    case SQLCOM_SELECT:
    case SQLCOM_SHOW_DATABASES:
    case SQLCOM_SHOW_FIELDS:
    case SQLCOM_SHOW_TABLES:
        return true;
    default:
        skygw_log_write_flush(
            LOGFILE_DEBUG,
            "Query command code 0x%x is not implemented by mongo filter",
            sql_command);
        return false;
    }
    return false;
}

bool can_handle_server_command(char c)
{
    enum_server_command cmd = (enum_server_command)c;
    switch (cmd)
    {
    case COM_INIT_DB:
    case COM_QUERY:
    case COM_FIELD_LIST:
    case COM_PING:
    case COM_QUIT:
    case COM_REFRESH:
        return true;
    default:
        skygw_log_write_flush(
            LOGFILE_DEBUG,
            "Server command code 0x%hx is not implemented by mongo filter", c);
        return false;
    }
    return false;
}
