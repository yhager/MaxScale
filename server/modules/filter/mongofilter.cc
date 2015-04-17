#define MYSQL_SERVER

#include <sql_class.h>

#include "mongofilter.h"
#include "query_classifier.h"


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

bool is_select_command(void* lex)
{
    return lex ? ((LEX*)lex)->sql_command == SQLCOM_SELECT : false;
}
