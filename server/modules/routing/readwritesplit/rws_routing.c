/*
 * This file is distributed as part of the MariaDB Corporation MaxScale.  It is free
 * software: you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation,
 * version 2.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright MariaDB Corporation Ab 2013-2014
 */

#include <readwritesplitsession.h>
#include <readwritesplit2.h>
#include <query_classifier.h>
#include <modutil.h>
#include <sescmd.h>

/** Defined in log_manager.cc */
extern int            lm_enabled_logfiles_bitmask;
extern size_t         log_ses_count[];
extern __thread       log_info_t tls_log_info;

int hashkeyfun(void* key);
int hashcmpfun (void *, void *);
void* hstrdup(void* fval);
void* hfree(void* fval);
 bool get_dcb(
        DCB**              p_dcb,
        ROUTER_CLIENT_SES* rses,
        backend_type_t     btype,
        char*              name,
        int                max_rlag);

bool route_session_write(
        ROUTER_CLIENT_SES* router_client_ses,
        GWBUF*             querybuf,
        ROUTER_INSTANCE*   inst,
        unsigned char      packet_type,
        skygw_query_type_t qtype);
bool rses_begin_locked_router_action(
        ROUTER_CLIENT_SES* rses);

void rses_end_locked_router_action(
        ROUTER_CLIENT_SES* rses);
 backend_ref_t* get_bref_from_dcb(ROUTER_CLIENT_SES* rses, DCB* dcb);
backend_ref_t* get_root_master_bref(ROUTER_CLIENT_SES* rses);
/**
 * Examine the query type, transaction state and routing hints. Find out the
 * target for query routing.
 * 
 *  @param qtype      Type of query 
 *  @param trx_active Is transacation active or not
 *  @param hint       Pointer to list of hints attached to the query buffer
 * 
 *  @return bitfield including the routing target, or the target server name 
 *          if the query would otherwise be routed to slave.
 */
route_target_t get_route_target (
        skygw_query_type_t qtype,
        bool               trx_active,
	target_t           use_sql_variables_in,
        HINT*              hint)
{
        route_target_t target = TARGET_UNDEFINED;
	/**
	 * These queries are not affected by hints
	 */
	if (QUERY_IS_TYPE(qtype, QUERY_TYPE_SESSION_WRITE) ||
		QUERY_IS_TYPE(qtype, QUERY_TYPE_PREPARE_STMT) ||
		QUERY_IS_TYPE(qtype, QUERY_TYPE_PREPARE_NAMED_STMT) ||
		/** Configured to allow writing variables to all nodes */
		(use_sql_variables_in == TYPE_ALL &&
			QUERY_IS_TYPE(qtype, QUERY_TYPE_GSYSVAR_WRITE)) ||
		/** enable or disable autocommit are always routed to all */
		QUERY_IS_TYPE(qtype, QUERY_TYPE_ENABLE_AUTOCOMMIT) ||
		QUERY_IS_TYPE(qtype, QUERY_TYPE_DISABLE_AUTOCOMMIT))
	{
		/** 
		 * This is problematic query because it would be routed to all
		 * backends but since this is SELECT that is not possible:
		 * 1. response set is not handled correctly in clientReply and
		 * 2. multiple results can degrade performance.
		 */
		if (QUERY_IS_TYPE(qtype, QUERY_TYPE_READ))
		{
			LOGIF(LE, (skygw_log_write_flush(
				LOGFILE_ERROR,
				"Warning : The query can't be routed to all "
				"backend servers because it includes SELECT and "
				"SQL variable modifications which is not supported. "
				"Set use_sql_variables_in=master or split the "
				"query to two, where SQL variable modifications "
				"are done in the first and the SELECT in the "
				"second one.")));
			
			target = TARGET_MASTER;
		}
		target |= TARGET_ALL;
	}
	/**
	 * Hints may affect on routing of the following queries
	 */
	else if (!trx_active && 
		(QUERY_IS_TYPE(qtype, QUERY_TYPE_READ) ||	/*< any SELECT */
		QUERY_IS_TYPE(qtype, QUERY_TYPE_SHOW_TABLES) || /*< 'SHOW TABLES' */
		QUERY_IS_TYPE(qtype, QUERY_TYPE_USERVAR_READ)||	/*< read user var */
		QUERY_IS_TYPE(qtype, QUERY_TYPE_SYSVAR_READ) ||	/*< read sys var */
		QUERY_IS_TYPE(qtype, QUERY_TYPE_EXEC_STMT) ||   /*< prepared stmt exec */
		QUERY_IS_TYPE(qtype, QUERY_TYPE_GSYSVAR_READ))) /*< read global sys var */
	{
		/** First set expected targets before evaluating hints */
		if (!QUERY_IS_TYPE(qtype, QUERY_TYPE_MASTER_READ) &&
			(QUERY_IS_TYPE(qtype, QUERY_TYPE_READ) ||
			QUERY_IS_TYPE(qtype, QUERY_TYPE_SHOW_TABLES) || /*< 'SHOW TABLES' */
			/** Configured to allow reading variables from slaves */
			(use_sql_variables_in == TYPE_ALL && 
			(QUERY_IS_TYPE(qtype, QUERY_TYPE_USERVAR_READ) ||
			QUERY_IS_TYPE(qtype, QUERY_TYPE_SYSVAR_READ) ||
			QUERY_IS_TYPE(qtype, QUERY_TYPE_GSYSVAR_READ)))))
		{
			target = TARGET_SLAVE;
		}
		else if (QUERY_IS_TYPE(qtype, QUERY_TYPE_MASTER_READ) ||
			QUERY_IS_TYPE(qtype, QUERY_TYPE_EXEC_STMT)	||
			/** Configured not to allow reading variables from slaves */
			(use_sql_variables_in == TYPE_MASTER && 
			(QUERY_IS_TYPE(qtype, QUERY_TYPE_USERVAR_READ)	||
			QUERY_IS_TYPE(qtype, QUERY_TYPE_SYSVAR_READ))))
		{
			target = TARGET_MASTER;
		}
		/** process routing hints */
		while (hint != NULL)
		{
			if (hint->type == HINT_ROUTE_TO_MASTER)
			{
				target = TARGET_MASTER; /*< override */
				LOGIF(LD, (skygw_log_write(
					LOGFILE_DEBUG,
					"%lu [get_route_target] Hint: route to master.",
					pthread_self())));
				break;
			}
			else if (hint->type == HINT_ROUTE_TO_NAMED_SERVER)
			{
				/** 
				 * Searching for a named server. If it can't be
				 * found, the oroginal target is chosen.
				 */
				target |= TARGET_NAMED_SERVER;
				LOGIF(LD, (skygw_log_write(
					LOGFILE_DEBUG,
					"%lu [get_route_target] Hint: route to "
					"named server : ",
					pthread_self())));
			}
			else if (hint->type == HINT_ROUTE_TO_UPTODATE_SERVER)
			{
				/** not implemented */
			}
			else if (hint->type == HINT_ROUTE_TO_ALL)
			{
				/** not implemented */
			}
			else if (hint->type == HINT_PARAMETER)
			{
				if (strncasecmp(
					(char *)hint->data, 
						"max_slave_replication_lag", 
						strlen("max_slave_replication_lag")) == 0)
				{
					target |= TARGET_RLAG_MAX;
				}
				else
				{
					LOGIF(LT, (skygw_log_write(
						LOGFILE_TRACE,
						"Error : Unknown hint parameter "
						"'%s' when 'max_slave_replication_lag' "
						"was expected.",
						(char *)hint->data)));
					LOGIF(LE, (skygw_log_write_flush(
						LOGFILE_ERROR,
						"Error : Unknown hint parameter "
						"'%s' when 'max_slave_replication_lag' "
						"was expected.",
						(char *)hint->data)));                                        
				}
			}
			else if (hint->type == HINT_ROUTE_TO_SLAVE)
			{
				target = TARGET_SLAVE;
				LOGIF(LD, (skygw_log_write(
					LOGFILE_DEBUG,
					"%lu [get_route_target] Hint: route to "
					"slave.",
					pthread_self())));                                
			}
			hint = hint->next;
		} /*< while (hint != NULL) */
		/** If nothing matches then choose the master */
		if ((target & (TARGET_ALL|TARGET_SLAVE|TARGET_MASTER)) == 0)
		{
			target = TARGET_MASTER;
		}
	}
	else
	{
		/** hints don't affect on routing */
		ss_dassert(trx_active ||
			(QUERY_IS_TYPE(qtype, QUERY_TYPE_WRITE) ||
			QUERY_IS_TYPE(qtype, QUERY_TYPE_MASTER_READ) ||
			QUERY_IS_TYPE(qtype, QUERY_TYPE_SESSION_WRITE) ||
			(QUERY_IS_TYPE(qtype, QUERY_TYPE_USERVAR_READ) &&
				use_sql_variables_in == TYPE_MASTER) ||
			(QUERY_IS_TYPE(qtype, QUERY_TYPE_SYSVAR_READ) &&
				use_sql_variables_in == TYPE_MASTER) ||
			(QUERY_IS_TYPE(qtype, QUERY_TYPE_GSYSVAR_READ) &&
				use_sql_variables_in == TYPE_MASTER) ||
			(QUERY_IS_TYPE(qtype, QUERY_TYPE_GSYSVAR_WRITE) &&
				use_sql_variables_in == TYPE_MASTER) ||
			QUERY_IS_TYPE(qtype, QUERY_TYPE_BEGIN_TRX) ||
			QUERY_IS_TYPE(qtype, QUERY_TYPE_ENABLE_AUTOCOMMIT) ||
			QUERY_IS_TYPE(qtype, QUERY_TYPE_DISABLE_AUTOCOMMIT) ||
			QUERY_IS_TYPE(qtype, QUERY_TYPE_ROLLBACK) ||
			QUERY_IS_TYPE(qtype, QUERY_TYPE_COMMIT) ||
			QUERY_IS_TYPE(qtype, QUERY_TYPE_EXEC_STMT) ||
			QUERY_IS_TYPE(qtype, QUERY_TYPE_CREATE_TMP_TABLE) ||
			QUERY_IS_TYPE(qtype, QUERY_TYPE_READ_TMP_TABLE) ||
			QUERY_IS_TYPE(qtype, QUERY_TYPE_UNKNOWN)));
		target = TARGET_MASTER;
	}

	return target;
}

/**
 * Check if the query is a DROP TABLE... query and
 * if it targets a temporary table, remove it from the hashtable.
 * @param router_cli_ses Router client session
 * @param querybuf GWBUF containing the query
 * @param type The type of the query resolved so far
 */
void
check_drop_tmp_table(
		     ROUTER_CLIENT_SES* router_cli_ses,
		     GWBUF* querybuf,
		     skygw_query_type_t type)
{

    int tsize = 0, klen = 0, i;
    char** tbl = NULL;
    char *hkey, *dbname;
    MYSQL_session* data;

    DCB* master_dcb = NULL;
    rses_property_t* rses_prop_tmp;

    rses_prop_tmp = router_cli_ses->rses_properties[RSES_PROP_TYPE_TMPTABLES];
    master_dcb = router_cli_ses->rses_master_ref->bref_dcb;

    CHK_DCB(master_dcb);

    data = (MYSQL_session*) master_dcb->session->data;
    dbname = (char*) data->db;

    if(is_drop_table_query(querybuf))
    {
	tbl = skygw_get_table_names(querybuf, &tsize, false);
	if(tbl != NULL)
	{
	    for(i = 0; i < tsize; i++)
	    {
		klen = strlen(dbname) + strlen(tbl[i]) + 2;
		hkey = calloc(klen, sizeof(char));
		strcpy(hkey, dbname);
		strcat(hkey, ".");
		strcat(hkey, tbl[i]);

		if(rses_prop_tmp &&
		   rses_prop_tmp->rses_prop_data.temp_tables)
		{
		    if(hashtable_delete(rses_prop_tmp->rses_prop_data.temp_tables,
					(void *) hkey))
		    {
			LOGIF(LT, (skygw_log_write(LOGFILE_TRACE,
						   "Temporary table dropped: %s", hkey)));
		    }
		}
		free(tbl[i]);
		free(hkey);
	    }

	    free(tbl);
	}
    }
}

/**
 * Check if the query targets a temporary table.
 * @param router_cli_ses Router client session
 * @param querybuf GWBUF containing the query
 * @param type The type of the query resolved so far
 * @return The type of the query
 */
 skygw_query_type_t is_read_tmp_table(
	ROUTER_CLIENT_SES* router_cli_ses,
	GWBUF*  querybuf,
	skygw_query_type_t type)
{

  bool target_tmp_table = false;
  int tsize = 0, klen = 0,i;
  char** tbl = NULL;
  char *hkey,*dbname;
  MYSQL_session* data;

  DCB*               master_dcb     = NULL;
  skygw_query_type_t qtype = type;
  rses_property_t*   rses_prop_tmp;

  rses_prop_tmp = router_cli_ses->rses_properties[RSES_PROP_TYPE_TMPTABLES];
  master_dcb = router_cli_ses->rses_master_ref->bref_dcb;

  CHK_DCB(master_dcb);

  data = (MYSQL_session*)master_dcb->session->data;
  dbname = (char*)data->db;

  if (QUERY_IS_TYPE(qtype, QUERY_TYPE_READ) || 
	  QUERY_IS_TYPE(qtype, QUERY_TYPE_LOCAL_READ) ||
	  QUERY_IS_TYPE(qtype, QUERY_TYPE_USERVAR_READ) ||
	  QUERY_IS_TYPE(qtype, QUERY_TYPE_SYSVAR_READ) ||
	  QUERY_IS_TYPE(qtype, QUERY_TYPE_GSYSVAR_READ))	  
    {
      tbl = skygw_get_table_names(querybuf,&tsize,false);

      if (tbl != NULL && tsize > 0)
	{ 
	  /** Query targets at least one table */
	  for(i = 0; i<tsize && !target_tmp_table && tbl[i]; i++)
	    {
	      klen = strlen(dbname) + strlen(tbl[i]) + 2;
	      hkey = calloc(klen,sizeof(char));
	      strcpy(hkey,dbname);
	      strcat(hkey,".");
	      strcat(hkey,tbl[i]);

	      if (rses_prop_tmp && 
		  rses_prop_tmp->rses_prop_data.temp_tables)
		{
				
		  if( (target_tmp_table = 
		       (bool)hashtable_fetch(rses_prop_tmp->rses_prop_data.temp_tables,(void *)hkey)))
		    {
		      /**Query target is a temporary table*/
		      qtype = QUERY_TYPE_READ_TMP_TABLE;			
		      LOGIF(LT, 
			    (skygw_log_write(LOGFILE_TRACE,
					     "Query targets a temporary table: %s",hkey)));
		    }
		}

	      free(hkey);
	    }

	}
    }

	
	if(tbl != NULL){
		for(i = 0; i<tsize;i++)
			{
				free(tbl[i]);
			}
		free(tbl);
	}
	
	return qtype;
}

/** 
 * If query is of type QUERY_TYPE_CREATE_TMP_TABLE then find out 
 * the database and table name, create a hashvalue and 
 * add it to the router client session's property. If property 
 * doesn't exist then create it first.
 * @param router_cli_ses Router client session
 * @param querybuf GWBUF containing the query
 * @param type The type of the query resolved so far
 */ 
 void check_create_tmp_table(
	ROUTER_CLIENT_SES* router_cli_ses,
	GWBUF*  querybuf,
	skygw_query_type_t type)
{

  int klen = 0;

  char *hkey,*dbname;
  MYSQL_session* data;

  DCB*               master_dcb     = NULL;
  rses_property_t*   rses_prop_tmp;
  HASHTABLE*	   h;

  rses_prop_tmp = router_cli_ses->rses_properties[RSES_PROP_TYPE_TMPTABLES];
  master_dcb = router_cli_ses->rses_master_ref->bref_dcb;

  CHK_DCB(master_dcb);

  data = (MYSQL_session*)master_dcb->session->data;
  dbname = (char*)data->db;


  if (QUERY_IS_TYPE(type, QUERY_TYPE_CREATE_TMP_TABLE))
    {
      bool  is_temp = true;
      char* tblname = NULL;
		
      tblname = skygw_get_created_table_name(querybuf);
		
      if (tblname && strlen(tblname) > 0)
	{
	  klen = strlen(dbname) + strlen(tblname) + 2;
	  hkey = calloc(klen,sizeof(char));
	  strcpy(hkey,dbname);
	  strcat(hkey,".");
	  strcat(hkey,tblname);
	}
      else
	{
	  hkey = NULL;
	}
		
      if(rses_prop_tmp == NULL)
	{
	  if((rses_prop_tmp = 
	      (rses_property_t*)calloc(1,sizeof(rses_property_t))))
	    {
#if defined(SS_DEBUG)
	      rses_prop_tmp->rses_prop_chk_top = CHK_NUM_ROUTER_PROPERTY;
	      rses_prop_tmp->rses_prop_chk_tail = CHK_NUM_ROUTER_PROPERTY;
#endif
	      rses_prop_tmp->rses_prop_rsession = router_cli_ses;
	      rses_prop_tmp->rses_prop_refcount = 1;
	      rses_prop_tmp->rses_prop_next = NULL;
	      rses_prop_tmp->rses_prop_type = RSES_PROP_TYPE_TMPTABLES;
	      router_cli_ses->rses_properties[RSES_PROP_TYPE_TMPTABLES] = rses_prop_tmp;
	    }
	  else
		{
		  LOGIF(LE, (skygw_log_write_flush(LOGFILE_ERROR,"Error : Call to malloc() failed.")));
		}
	}
	  if(rses_prop_tmp){
      if (rses_prop_tmp->rses_prop_data.temp_tables == NULL)
	{
	  h = hashtable_alloc(7, hashkeyfun, hashcmpfun);
	  hashtable_memory_fns(h,hstrdup,NULL,hfree,NULL);
	  if (h != NULL)
	    {
	      rses_prop_tmp->rses_prop_data.temp_tables = h;
	    }else{
		  LOGIF(LE, (skygw_log_write_flush(LOGFILE_ERROR,"Error : Failed to allocate a new hashtable.")));
	  }

	}
		
     if (hkey && rses_prop_tmp->rses_prop_data.temp_tables &&
	  hashtable_add(rses_prop_tmp->rses_prop_data.temp_tables,
			(void *)hkey,
			(void *)is_temp) == 0) /*< Conflict in hash table */
	{
	  LOGIF(LT, (skygw_log_write(
				     LOGFILE_TRACE,
				     "Temporary table conflict in hashtable: %s",
				     hkey)));
	}
#if defined(SS_DEBUG)
      {
	bool retkey = 
	  hashtable_fetch(
			  rses_prop_tmp->rses_prop_data.temp_tables,
			  hkey);
	if (retkey)
	  {
	    LOGIF(LT, (skygw_log_write(
				       LOGFILE_TRACE,
				       "Temporary table added: %s",
				       hkey)));
	  }
      }
#endif
	  }
	  
      free(hkey);
      free(tblname);
    }
}


/**
 * Routing function. Find out query type, backend type, and target DCB(s). 
 * Then route query to found target(s).
 * @param inst		router instance
 * @param rses		router session
 * @param querybuf	GWBUF including the query
 * 
 * @return true if routing succeed or if it failed due to unsupported query.
 * false if backend failure was encountered.
 */
bool route_single_stmt(
	ROUTER_INSTANCE*   inst,
	ROUTER_CLIENT_SES* rses,
	GWBUF*             querybuf)
{
	skygw_query_type_t qtype          = QUERY_TYPE_UNKNOWN;
	mysql_server_cmd_t packet_type;
	uint8_t*           packet;
	int                ret            = 0;
	DCB*               master_dcb     = NULL;
	DCB*               target_dcb     = NULL;
	route_target_t     route_target;
	bool           	   succp          = false;
	int                rlag_max       = MAX_RLAG_UNDEFINED;
	backend_type_t     btype; /*< target backend type */
	
	
	ss_dassert(!GWBUF_IS_TYPE_UNDEFINED(querybuf));
	packet = GWBUF_DATA(querybuf);
	packet_type = packet[4];

	/** 
	 * Read stored master DCB pointer. If master is not set, routing must 
	 * be aborted 
	 */
	if ((master_dcb = rses->rses_master_ref->bref_dcb) == NULL)
	{
		char* query_str = modutil_get_query(querybuf);
		CHK_DCB(master_dcb);
		LOGIF(LE, (skygw_log_write_flush(
			LOGFILE_ERROR,
			"Error: Can't route %s:%s:\"%s\" to "
			"backend server. Session doesn't have a Master "
			"node",
			STRPACKETTYPE(packet_type),
			STRQTYPE(qtype),
			(query_str == NULL ? "(empty)" : query_str))));
		free(query_str);
		succp = false;
		goto retblock;
	}
	
	/** If buffer is not contiguous, make it such */
	if (querybuf->next != NULL)
	{
		querybuf = gwbuf_make_contiguous(querybuf);
	}
	
	switch(packet_type) {
		case MYSQL_COM_QUIT:        /*< 1 QUIT will close all sessions */
		case MYSQL_COM_INIT_DB:     /*< 2 DDL must go to the master */
		case MYSQL_COM_REFRESH:     /*< 7 - I guess this is session but not sure */
		case MYSQL_COM_DEBUG:       /*< 0d all servers dump debug info to stdout */
		case MYSQL_COM_PING:        /*< 0e all servers are pinged */
		case MYSQL_COM_CHANGE_USER: /*< 11 all servers change it accordingly */
		case MYSQL_COM_STMT_CLOSE:  /*< free prepared statement */
		case MYSQL_COM_STMT_SEND_LONG_DATA: /*< send data to column */
		case MYSQL_COM_STMT_RESET:  /*< resets the data of a prepared statement */
			qtype = QUERY_TYPE_SESSION_WRITE;
			break;
			
		case MYSQL_COM_CREATE_DB:   /**< 5 DDL must go to the master */
		case MYSQL_COM_DROP_DB:     /**< 6 DDL must go to the master */
			qtype = QUERY_TYPE_WRITE;
			break;
			
		case MYSQL_COM_QUERY:
			qtype = query_classifier_get_type(querybuf);
			break;
			
		case MYSQL_COM_STMT_PREPARE:
			qtype = query_classifier_get_type(querybuf);
			qtype |= QUERY_TYPE_PREPARE_STMT;
			break;
			
		case MYSQL_COM_STMT_EXECUTE:
			/** Parsing is not needed for this type of packet */
			qtype = QUERY_TYPE_EXEC_STMT;
			break;
			
		case MYSQL_COM_SHUTDOWN:       /**< 8 where should shutdown be routed ? */
		case MYSQL_COM_STATISTICS:     /**< 9 ? */
		case MYSQL_COM_PROCESS_INFO:   /**< 0a ? */
		case MYSQL_COM_CONNECT:        /**< 0b ? */
		case MYSQL_COM_PROCESS_KILL:   /**< 0c ? */
		case MYSQL_COM_TIME:           /**< 0f should this be run in gateway ? */
		case MYSQL_COM_DELAYED_INSERT: /**< 10 ? */
		case MYSQL_COM_DAEMON:         /**< 1d ? */
		default:
			break;
	} /**< switch by packet type */
	
	/**
	 * Check if the query has anything to do with temporary tables.
	 */
	qtype = is_read_tmp_table(rses, querybuf, qtype);
	check_create_tmp_table(rses, querybuf, qtype);
	check_drop_tmp_table(rses, querybuf,qtype);
	
	/**
	 * If autocommit is disabled or transaction is explicitly started
	 * transaction becomes active and master gets all statements until
	 * transaction is committed and autocommit is enabled again.
	 */
	if (rses->rses_autocommit_enabled &&
		QUERY_IS_TYPE(qtype, QUERY_TYPE_DISABLE_AUTOCOMMIT))
	{
		rses->rses_autocommit_enabled = false;
		
		if (!rses->rses_transaction_active)
		{
			rses->rses_transaction_active = true;
		}
	}
	else if (!rses->rses_transaction_active &&
		QUERY_IS_TYPE(qtype, QUERY_TYPE_BEGIN_TRX))
	{
		rses->rses_transaction_active = true;
	}
	/** 
	 * Explicit COMMIT and ROLLBACK, implicit COMMIT.
	 */
	if (rses->rses_autocommit_enabled &&
		rses->rses_transaction_active &&
		(QUERY_IS_TYPE(qtype,QUERY_TYPE_COMMIT) ||
		QUERY_IS_TYPE(qtype,QUERY_TYPE_ROLLBACK)))
	{
		rses->rses_transaction_active = false;
	} 
	else if (!rses->rses_autocommit_enabled &&
		QUERY_IS_TYPE(qtype, QUERY_TYPE_ENABLE_AUTOCOMMIT))
	{
		rses->rses_autocommit_enabled = true;
		rses->rses_transaction_active = false;
	}        
	
	if (LOG_IS_ENABLED(LOGFILE_TRACE))
	{
		uint8_t*      packet = GWBUF_DATA(querybuf);
		unsigned char ptype = packet[4];
		size_t        len = MIN(GWBUF_LENGTH(querybuf), 
					MYSQL_GET_PACKET_LEN((unsigned char *)querybuf->start)-1);
		char*         data = (char*)&packet[5];
		char*         contentstr = strndup(data, len);
		char*         qtypestr = skygw_get_qtype_str(qtype);
		
		skygw_log_write(
			LOGFILE_TRACE,
				"> Autocommit: %s, trx is %s, cmd: %s, type: %s, "
				"stmt: %s%s %s",
				(rses->rses_autocommit_enabled ? "[enabled]" : "[disabled]"),
				(rses->rses_transaction_active ? "[open]" : "[not open]"),
				STRPACKETTYPE(ptype),
				(qtypestr==NULL ? "N/A" : qtypestr),
				contentstr,
				(querybuf->hint == NULL ? "" : ", Hint:"),
				(querybuf->hint == NULL ? "" : STRHINTTYPE(querybuf->hint->type)));
		
		free(contentstr);
		free(qtypestr);
	}
	/** 
	 * Find out where to route the query. Result may not be clear; it is 
	 * possible to have a hint for routing to a named server which can
	 * be either slave or master. 
	 * If query would otherwise be routed to slave then the hint determines 
	 * actual target server if it exists.
	 * 
	 * route_target is a bitfield and may include :
	 * TARGET_ALL
	 * - route to all connected backend servers
	 * TARGET_SLAVE[|TARGET_NAMED_SERVER|TARGET_RLAG_MAX]
	 * - route primarily according to hints, then to slave and if those
	 *   failed, eventually to master
	 * TARGET_MASTER[|TARGET_NAMED_SERVER|TARGET_RLAG_MAX]
	 * - route primarily according to the hints and if they failed, 
	 *   eventually to master
	 */
	route_target = get_route_target(qtype, 
					rses->rses_transaction_active,
					rses->rses_config.rw_use_sql_variables_in,
					querybuf->hint);
	
	if(skygw_is_session_command(querybuf))
	{
	    succp = route_session_write(
					rses, 
					gwbuf_clone(querybuf), 
					inst, 
					packet_type, 
					qtype);
		
		if (succp)
		{
			atomic_add(&inst->stats.n_all, 1);
		}
		goto retblock;
	}
	
	
	/** Lock router session */
	if (!rses_begin_locked_router_action(rses))
	{
		if (packet_type != MYSQL_COM_QUIT)
		{
			char* query_str = modutil_get_query(querybuf);
			
			LOGIF(LE, (skygw_log_write_flush(
				LOGFILE_ERROR,
				"Error: Can't route %s:%s:\"%s\" to "
				"backend server. Router is closed.",
				STRPACKETTYPE(packet_type),
				STRQTYPE(qtype),
				(query_str == NULL ? "(empty)" : query_str))));
			free(query_str);
		}
		succp = false;
		goto retblock;
	}
	/**
	 * There is a hint which either names the target backend or
	 * hint which sets maximum allowed replication lag for the 
	 * backend.
	 */
	if (TARGET_IS_NAMED_SERVER(route_target) ||
		TARGET_IS_RLAG_MAX(route_target))
	{
		HINT* hint;
		char* named_server = NULL;
		
		hint = querybuf->hint;
		
		while (hint != NULL)
		{
			if (hint->type == HINT_ROUTE_TO_NAMED_SERVER)
			{
				/**
				 * Set the name of searched 
				 * backend server.
				 */
				named_server = hint->data;
				LOGIF(LT, (skygw_log_write(
					LOGFILE_TRACE,
					"Hint: route to server "
					"'%s'",
					named_server)));       
			}
			else if (hint->type == HINT_PARAMETER &&
				(strncasecmp((char *)hint->data,
				"max_slave_replication_lag",
				strlen("max_slave_replication_lag")) == 0))
			{
				int val = (int) strtol((char *)hint->value, 
							(char **)NULL, 10);
				
				if (val != 0 || errno == 0)
				{
					/**
					 * Set max. acceptable
					 * replication lag 
					 * value for backend srv
					 */
					rlag_max = val;
					LOGIF(LT, (skygw_log_write(
						LOGFILE_TRACE,
						"Hint: "
						"max_slave_replication_lag=%d",
						rlag_max)));
				}
			}
			hint = hint->next;
		} /*< while */
		
		if (rlag_max == MAX_RLAG_UNDEFINED) /*< no rlag max hint, use config */
		{
			rlag_max = rses_get_max_replication_lag(rses);
		}
		btype = route_target & TARGET_SLAVE ? BE_SLAVE : BE_MASTER; /*< target may be master or slave */
		/**
		 * Search backend server by name or replication lag. 
		 * If it fails, then try to find valid slave or master.
		 */ 
		succp = get_dcb(&target_dcb, rses, btype, named_server,rlag_max);
		
		if (!succp)
		{
			if (TARGET_IS_NAMED_SERVER(route_target))
			{
				LOGIF(LT, (skygw_log_write(
					LOGFILE_TRACE,
					"Was supposed to route to named server "
					"%s but couldn't find the server in a "
					"suitable state.",
					named_server)));
			}
			else if (TARGET_IS_RLAG_MAX(route_target))
			{
				LOGIF(LT, (skygw_log_write(
					LOGFILE_TRACE,
					"Was supposed to route to server with "
					"replication lag at most %d but couldn't "
					"find such a slave.",
					rlag_max)));
			}
		}
	}
	else if (TARGET_IS_SLAVE(route_target))
	{
		btype = BE_SLAVE;
		
		if (rlag_max == MAX_RLAG_UNDEFINED) /*< no rlag max hint, use config */
		{
			rlag_max = rses_get_max_replication_lag(rses);
		}
		/**
		 * Search suitable backend server, get DCB in target_dcb
		 */ 
		succp = get_dcb(&target_dcb, rses, BE_SLAVE, NULL,rlag_max);

		if (succp)
		{
		    backend_ref_t* br = get_root_master_bref(rses);
			ss_dassert(get_root_master_bref(rses) == 
				rses->rses_master_ref);
			atomic_add(&inst->stats.n_slave, 1);
		}
		else
		{
			LOGIF(LT, (skygw_log_write(LOGFILE_TRACE,
						   "Was supposed to route to slave"
						   "but finding suitable one "
						   "failed.")));
		}
	}
	else if (TARGET_IS_MASTER(route_target))
	{
		DCB* curr_master_dcb = NULL;
		
		succp = get_dcb(&curr_master_dcb, 
				rses, 
				BE_MASTER, 
				NULL,
				MAX_RLAG_UNDEFINED);
		
		if (succp && master_dcb == curr_master_dcb)
		{
			atomic_add(&inst->stats.n_master, 1);
			target_dcb = master_dcb;
		}
		else
		{
			if (succp && master_dcb != curr_master_dcb)
			{
				LOGIF(LT, (skygw_log_write(LOGFILE_TRACE,
							   "Was supposed to "
							   "route to master "
							   "but master has "
							   "changed.")));
			}
			else
			{
				LOGIF(LT, (skygw_log_write(LOGFILE_TRACE,
							   "Was supposed to "
							   "route to master "
							   "but couldn't find "
							   "master in a "
							   "suitable state.")));
			}
			/**
			 * Master has changed. Return with error indicator.
			 */
			rses_end_locked_router_action(rses);
			succp = false;
			goto retblock;
		}
	}
	
	if (succp) /*< Have DCB of the target backend */
	{
		backend_ref_t*   bref;
		
		
		bref = get_bref_from_dcb(rses, target_dcb);
		
		ss_dassert(target_dcb != NULL);
		
		LOGIF(LT, (skygw_log_write(
			LOGFILE_TRACE,
			"Route query to %s \t%s:%d <",
			(SERVER_IS_MASTER(bref->bref_backend->backend_server) ? 
			"master" : "slave"),
			bref->bref_backend->backend_server->name,
			bref->bref_backend->backend_server->port)));
		/** 
		 * Store current stmt if execution of previous session command 
		 * haven't completed yet.
		 * 
		 * !!! Note that according to MySQL protocol
		 * there can only be one such non-sescmd stmt at the time.
		 * It is possible that bref->bref_pending_cmd includes a pending
		 * command if rwsplit is parent or child for another router, 
		 * which runs all the same commands.
		 * 
		 * If the assertion below traps, pending queries are treated 
		 * somehow wrong, or client is sending more queries before 
		 * previous is received.
		 */
		if (BREF_IS_WAITING_RESULT(bref))
		{
			ss_dassert(bref->bref_pending_cmd == NULL);
			bref->bref_pending_cmd = gwbuf_clone(querybuf);
			
			rses_end_locked_router_action(rses);
			goto retblock;
		}
		
		if ((ret = target_dcb->func.write(target_dcb, gwbuf_clone(querybuf))) == 1)
		{
			backend_ref_t* bref;
			
			atomic_add(&inst->stats.n_queries, 1);
			/**
			 * Add one query response waiter to backend reference
			 */
			bref = get_bref_from_dcb(rses, target_dcb);
			bref_set_state(bref, BREF_QUERY_ACTIVE);
			bref_set_state(bref, BREF_WAITING_RESULT);
		}
		else
		{
			LOGIF(LE, (skygw_log_write_flush(
				LOGFILE_ERROR,
				"Error : Routing query failed.")));
			succp = false;
		}
	}
	rses_end_locked_router_action(rses);
	
retblock:

	return succp;	
}
/**
 * Client Reply routine
 *
 * The routine will reply to client for session change with master server data
 *
 * @param	instance	The router instance
 * @param	router_session	The router session 
 * @param	backend_dcb	The backend DCB
 * @param	queue		The GWBUF with reply data
 */
void handle_clientReply (
        ROUTER* instance,
        void*   router_session,
        GWBUF*  writebuf,
        DCB*    backend_dcb)
{
        DCB*               client_dcb;
        ROUTER_CLIENT_SES* router_cli_ses;
        backend_ref_t*     bref;
	GWBUF* buffer = writebuf;
        SCMDCURSOR* cursor;
	router_cli_ses = (ROUTER_CLIENT_SES *)router_session;
        CHK_CLIENT_RSES(router_cli_ses);

        /**
         * Lock router client session for secure read of router session members.
         * Note that this could be done without lock by using version #
         */
        if (!rses_begin_locked_router_action(router_cli_ses))
        {
                print_error_packet(router_cli_ses, buffer, backend_dcb);
                goto lock_failed;
	}
        /** Holding lock ensures that router session remains open */
        ss_dassert(backend_dcb->session != NULL);
	client_dcb = backend_dcb->session->client;

        /** Unlock */
        rses_end_locked_router_action(router_cli_ses);        
	
	if (client_dcb == NULL)
	{
                while ((buffer = gwbuf_consume(
                        buffer,
                        GWBUF_LENGTH(buffer))) != NULL);
		/** Log that client was closed before reply */
                goto lock_failed;
	}
	/** Lock router session */
        if (!rses_begin_locked_router_action(router_cli_ses))
        {
                /** Log to debug that router was closed */
                goto lock_failed;
        }
        bref = get_bref_from_dcb(router_cli_ses, backend_dcb);

	/** This makes the issue becoming visible in poll.c */
	if (bref == NULL)
	{
		/** Unlock router session */
		rses_end_locked_router_action(router_cli_ses);
		goto lock_failed;
	}
	
        CHK_BACKEND_REF(bref);
        
	if (GWBUF_IS_TYPE_SESCMD_RESPONSE(buffer))
	{
                
	    /** 
	     * Discard all those responses that have already been sent to
	     * the client. 
	     */
	    GWBUF* ncmd;
	    SCMDCURSOR* cursor;

	    cursor = dcb_get_sescmdcursor(backend_dcb);
	    bool success = sescmdlist_process_replies(cursor, &buffer);

	    if(!success)
	    {
		bref_clear_state(bref,BREF_IN_USE);
		bref_set_state(bref,BREF_CLOSED);
	    }
	    else
	    {
		sescmdlist_execute(cursor);
	    }

	    /** 
	     * If response will be sent to client, decrease waiter count.
	     * This applies to session commands only. Counter decrement
	     * for other type of queries is done outside this block.
	     */
	    if (buffer != NULL && client_dcb != NULL)
	    {
		/** Set response status as replied */
		bref_clear_state(bref, BREF_WAITING_RESULT);
	    }
	}
	/**
         * Clear BREF_QUERY_ACTIVE flag and decrease waiter counter.
         * This applies for queries  other than session commands.
         */

	else if (BREF_IS_QUERY_ACTIVE(bref))
	{
                bref_clear_state(bref, BREF_QUERY_ACTIVE);
                /** Set response status as replied */
                bref_clear_state(bref, BREF_WAITING_RESULT);
        }

        if (buffer != NULL && client_dcb != NULL)
        {
                /** Write reply to client DCB */
		SESSION_ROUTE_REPLY(backend_dcb->session, buffer);
        }
        /** Unlock router session */
        rses_end_locked_router_action(router_cli_ses);
        
        /** Lock router session */
        if (!rses_begin_locked_router_action(router_cli_ses))
        {
                /** Log to debug that router was closed */
                goto lock_failed;
        }
        
       if (bref->bref_pending_cmd != NULL) /*< non-sescmd is waiting to be routed */
	{
		int ret;
		
		CHK_GWBUF(bref->bref_pending_cmd);
		
		if ((ret = bref->bref_dcb->func.write(
				bref->bref_dcb, 
				gwbuf_clone(bref->bref_pending_cmd))) == 1)
		{
			ROUTER_INSTANCE* inst = (ROUTER_INSTANCE *)instance;
			atomic_add(&inst->stats.n_queries, 1);
			/**
			 * Add one query response waiter to backend reference
			 */
			bref_set_state(bref, BREF_QUERY_ACTIVE);
			bref_set_state(bref, BREF_WAITING_RESULT);
		}
		else
		{
			LOGIF(LE, (skygw_log_write_flush(
				LOGFILE_ERROR,
				"Error : Routing query \"%s\" failed.",
				bref->bref_pending_cmd)));
		}
		gwbuf_free(bref->bref_pending_cmd);
		bref->bref_pending_cmd = NULL;
	}
	/** Unlock router session */
        rses_end_locked_router_action(router_cli_ses);
        
lock_failed:
        return;
}
/**
 * Execute in backends used by current router session.
 * Save session variable commands to router session property
 * struct. Thus, they can be replayed in backends which are 
 * started and joined later.
 * 
 * Suppress redundant OK packets sent by backends.
 * 
 * The first OK packet is replied to the client.
 * 
 * @param router_cli_ses	Client's router session pointer
 * @param querybuf		GWBUF including the query to be routed
 * @param inst			Router instance
 * @param packet_type		Type of MySQL packet
 * @param qtype			Query type from query_classifier
 * 
 * @return True if at least one backend is used and routing succeed to all 
 * backends being used, otherwise false.
 * 
 */
bool route_session_write(
        ROUTER_CLIENT_SES* router_cli_ses,
        GWBUF*             querybuf,
        ROUTER_INSTANCE*   inst,
        unsigned char      packet_type,
        skygw_query_type_t qtype)
{
        bool              succp;
        rses_property_t*  prop;
        backend_ref_t*    backend_ref;
        int               i;
	int               max_nslaves;
	int               nbackends;
	int 		  nsucc;
  
        LOGIF(LT, (skygw_log_write(
                LOGFILE_TRACE,
                "Session write, routing to all servers.")));
	/** Maximum number of slaves in this router client session */
	max_nslaves = rses_get_max_slavecount(router_cli_ses, 
					  router_cli_ses->rses_nbackends);
	nsucc = 0;
	nbackends = 0;
        backend_ref = router_cli_ses->rses_backend_ref;
        
        /**
         * These are one-way messages and server doesn't respond to them.
         * Therefore reply processing is unnecessary and session 
         * command property is not needed. It is just routed to all available
         * backends.
         */
        if (packet_type == MYSQL_COM_STMT_SEND_LONG_DATA ||
                packet_type == MYSQL_COM_QUIT ||
                packet_type == MYSQL_COM_STMT_CLOSE)
        {
                int rc;

		/** Lock router session */
                if (!rses_begin_locked_router_action(router_cli_ses))
                {
                        goto return_succp;
                }
                                
                for (i=0; i<router_cli_ses->rses_nbackends; i++)
                {
                        DCB* dcb = backend_ref[i].bref_dcb;     
			
			if (LOG_IS_ENABLED(LOGFILE_TRACE))
			{
				LOGIF(LT, (skygw_log_write(
					LOGFILE_TRACE,
					"Route query to %s \t%s:%d%s",
					(SERVER_IS_MASTER(backend_ref[i].bref_backend->backend_server) ? 
						"master" : "slave"),
					backend_ref[i].bref_backend->backend_server->name,
					backend_ref[i].bref_backend->backend_server->port,
					(i+1==router_cli_ses->rses_nbackends ? " <" : " "))));
			}

                        if (BREF_IS_IN_USE((&backend_ref[i])))
                        {
				nbackends += 1;
                                if ((rc = dcb->func.write(dcb, gwbuf_clone(querybuf))) == 1)
				{
					nsucc += 1;
				}
                        }
                }
                rses_end_locked_router_action(router_cli_ses);
                gwbuf_free(querybuf);
                goto return_succp;
        }
        /** Lock router session */
        if (!rses_begin_locked_router_action(router_cli_ses))
        {
                goto return_succp;
        }
        
        if (router_cli_ses->rses_nbackends <= 0)
	{
		LOGIF(LT, (skygw_log_write(
			LOGFILE_TRACE,
			"Router session doesn't have any backends in use. "
			"Routing failed. <")));
		
		goto return_succp;
	}
	
        /** 
         * Add the command to the list of session commands.
         */
        sescmdlist_add_command(router_cli_ses->rses_sescmd_list,querybuf);
	for(i = 0;i<router_cli_ses->rses_nbackends;i++)
	{
	    if(BREF_IS_IN_USE(&router_cli_ses->rses_backend_ref[i]))
	    {
		SCMDCURSOR* cursor;
		cursor = dcb_get_sescmdcursor(router_cli_ses->rses_backend_ref[i].bref_dcb);
		sescmdlist_execute(cursor);
	    }
	}

        gwbuf_free(querybuf);
	
        /** Unlock router session */
        rses_end_locked_router_action(router_cli_ses);
               
return_succp:
	/** 
	 * Routing must succeed to all backends that are used.
	 * There must be at leas one and at most max_nslaves+1 backends.
	 */
	succp = (nbackends > 0 && nsucc == nbackends && nbackends <= max_nslaves+1);
        return succp;
}
