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
#include <my_config.h>
#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include <router.h>
#include <readwritesplit2.h>

#include <mysql.h>
#include <skygw_utils.h>
#include <log_manager.h>
#include <dcb.h>
#include <spinlock.h>
#include <modinfo.h>
#include <modutil.h>
#include <mysql_client_server_protocol.h>
#include <readwritesplitsession.h>
#include <readwritespliterror.h>

MODULE_INFO 	info = {
	MODULE_API_ROUTER,
	MODULE_GA,
	ROUTER_VERSION,
	"A Read/Write splitting router for enhancement read scalability"
};

/** Defined in log_manager.cc */
extern int            lm_enabled_logfiles_bitmask;
extern size_t         log_ses_count[];
extern __thread log_info_t tls_log_info;
/**
 * @file readwritesplit.c	The entry points for the read/write query splitting
 * router module.
 *
 * This file contains the entry points that comprise the API to the read write
 * query splitting router.
 * @verbatim
 * Revision History
 *
 * Date		Who			Description
 * 01/07/2013	Vilho Raatikka		Initial implementation
 * 15/07/2013	Massimiliano Pinto	Added clientReply
 *					from master only in case of session change
 * 17/07/2013	Massimiliano Pinto	clientReply is now used by mysql_backend
 *					for all reply situations
 * 18/07/2013	Massimiliano Pinto	routeQuery now handles COM_QUIT
 *					as QUERY_TYPE_SESSION_WRITE
 * 17/07/2014	Massimiliano Pinto	Server connection counter is updated in closeSession
 *
 * @endverbatim
 */

static char *version_str = "V1.0.2";

static	ROUTER* createInstance(SERVICE *service, char **options);

static	void*   newSession(ROUTER *instance, SESSION *session);
static	void    closeSession(ROUTER *instance, void *session);
static	void    freeSession(ROUTER *instance, void *session);
static	int     routeQuery(ROUTER *instance, void *session, GWBUF *queue);
static	void    diagnostic(ROUTER *instance, DCB *dcb);
static  void	clientReply(
        ROUTER* instance,
        void*   router_session,
        GWBUF*  queue,
        DCB*    backend_dcb);
static  uint8_t getCapabilities (ROUTER* inst, void* router_session);

void handle_clientReply (
        ROUTER* instance,
        void*   router_session,
        GWBUF*  writebuf,
        DCB*    backend_dcb);

void*   handle_newSession(ROUTER *instance, SESSION *session);
void    handle_closeSession(ROUTER *instance, void *session);
void    handle_freeSession(ROUTER *instance, void *session);

 int  router_get_servercount(ROUTER_INSTANCE* router);
 int  rses_get_max_slavecount(ROUTER_CLIENT_SES* rses, int router_nservers);
 int  rses_get_max_replication_lag(ROUTER_CLIENT_SES* rses);
 backend_ref_t* get_bref_from_dcb(ROUTER_CLIENT_SES* rses, DCB* dcb);
 DCB* rses_get_client_dcb(ROUTER_CLIENT_SES* rses);

 route_target_t get_route_target (
	skygw_query_type_t qtype,
	bool               trx_active,
	target_t           use_sql_variables_in,
	HINT*              hint);

 backend_ref_t* check_candidate_bref(
	backend_ref_t* candidate_bref,
	backend_ref_t* new_bref,
	select_criteria_t sc);

 skygw_query_type_t is_read_tmp_table(
	ROUTER_CLIENT_SES* router_cli_ses,
	GWBUF*  querybuf,
	skygw_query_type_t type);

 void check_create_tmp_table(
	ROUTER_CLIENT_SES* router_cli_ses,
	GWBUF*  querybuf,
	skygw_query_type_t type);

 bool route_single_stmt(
	ROUTER_INSTANCE*   inst,
	ROUTER_CLIENT_SES* rses,
	GWBUF*             querybuf);




int bref_cmp_global_conn(
        const void* bref1,
        const void* bref2);

int bref_cmp_router_conn(
        const void* bref1,
        const void* bref2);

int bref_cmp_behind_master(
        const void* bref1,
        const void* bref2);

int bref_cmp_current_load(
        const void* bref1,
        const void* bref2);

/**
 * The order of functions _must_ match with the order the select criteria are
 * listed in select_criteria_t definition in readwritesplit.h
 */
int (*criteria_cmpfun[LAST_CRITERIA])(const void*, const void*)=
{
        NULL,
        bref_cmp_global_conn,
        bref_cmp_router_conn,
        bref_cmp_behind_master,
        bref_cmp_current_load
};

 bool select_connect_backend_servers(
        backend_ref_t**    p_master_ref,
        backend_ref_t*     backend_ref,
        int                router_nservers,
        int                max_nslaves,
        int                max_rlag,
        select_criteria_t  select_criteria,
        SESSION*           session,
        ROUTER_CLIENT_SES* rses,
        ROUTER_INSTANCE*   router);

 bool get_dcb(
        DCB**              dcb,
        ROUTER_CLIENT_SES* rses,
        backend_type_t     btype,
        char*              name,
        int                max_rlag);

 void rwsplit_process_router_options(
        ROUTER_INSTANCE* router,
        char**           options);




bool rses_begin_locked_router_action(
        ROUTER_CLIENT_SES* rses);

void rses_end_locked_router_action(
        ROUTER_CLIENT_SES* rses);

rses_property_t* rses_property_init(
	rses_property_type_t prop_type);

void rses_property_add(
	ROUTER_CLIENT_SES* rses,
	rses_property_t*   prop);

void rses_property_done(
	rses_property_t* prop);


void tracelog_routed_query(
        ROUTER_CLIENT_SES* rses,
        char*              funcname,
        backend_ref_t*     bref,
        GWBUF*             buf);

bool route_session_write(
        ROUTER_CLIENT_SES* router_client_ses,
        GWBUF*             querybuf,
        ROUTER_INSTANCE*   inst,
        unsigned char      packet_type,
        skygw_query_type_t qtype);

void refreshInstance(
        ROUTER_INSTANCE*  router,
        CONFIG_PARAMETER* param);

void bref_clear_state(backend_ref_t* bref, bref_state_t state);
void bref_set_state(backend_ref_t*   bref, bref_state_t state);

backend_ref_t* get_root_master_bref(ROUTER_CLIENT_SES* rses);

BACKEND* get_root_master(
        backend_ref_t* servers,
        int            router_nservers);

bool have_enough_servers(
        ROUTER_CLIENT_SES** rses,
        const int           nsrv,
        int                 router_nsrv,
        ROUTER_INSTANCE*    router);

static SPINLOCK	        instlock;
static ROUTER_INSTANCE* instances;

static ROUTER_OBJECT MyObject = {
        createInstance,
        newSession,
        closeSession,
        freeSession,
        routeQuery,
        diagnostic,
        clientReply,
        handleError,
        getCapabilities
};


/**
 * Implementation of the mandatory version entry point
 *
 * @return version string of the module
 */
char *
version()
{
	return version_str;
}

/**
 * The module initialisation routine, called when the module
 * is first loaded.
 */
void
ModuleInit()
{
        LOGIF(LM, (skygw_log_write_flush(
                           LOGFILE_MESSAGE,
                           "Initializing statemend-based read/write split router module.")));
        spinlock_init(&instlock);
        instances = NULL;
}

/**
 * The module entry point routine. It is this routine that
 * must populate the structure that is referred to as the
 * "module object", this is a structure with the set of
 * external entry points for this module.
 *
 * @return The module object
 */
ROUTER_OBJECT* GetModuleObject()
{
        return &MyObject;
}


/**
 * Refresh the instance by the given parameter value.
 * 
 * @param router	Router instance
 * @param singleparam	Parameter fo be reloaded
 * 
 * Note: this part is not done. Needs refactoring.
 */
void refreshInstance(
        ROUTER_INSTANCE*  router,
        CONFIG_PARAMETER* singleparam)
{
        CONFIG_PARAMETER*   param;
        bool                refresh_single;
	config_param_type_t paramtype;
	
        if (singleparam != NULL)
        {
                param = singleparam;
                refresh_single = true;
        }
        else
        {
                param = router->service->svc_config_param;
                refresh_single = false;
        }
        paramtype = config_get_paramtype(param);
	
        while (param != NULL)         
        {
		/** Catch unused parameter types */
		ss_dassert(paramtype == COUNT_TYPE || 
			paramtype == PERCENT_TYPE ||
			paramtype == SQLVAR_TARGET_TYPE);
		
                if (paramtype == COUNT_TYPE)
                {
                        if (strncmp(param->name, "max_slave_connections", MAX_PARAM_LEN) == 0)
                        {
				int  val;
				bool succp;
				
                                router->rwsplit_config.rw_max_slave_conn_percent = 0;
				
				succp = config_get_valint(&val, param, NULL, paramtype);
				
				if (succp)
				{
					router->rwsplit_config.rw_max_slave_conn_count = val;
				}
                        }
                        else if (strncmp(param->name, 
                                        "max_slave_replication_lag", 
                                        MAX_PARAM_LEN) == 0)
                        {
				int  val;
				bool succp;
				
				succp = config_get_valint(&val, param, NULL, paramtype);
				
				if (succp)
				{
					router->rwsplit_config.rw_max_slave_replication_lag = val;
				}
			}
                }
                else if (paramtype == PERCENT_TYPE)
                {
                        if (strncmp(param->name, "max_slave_connections", MAX_PARAM_LEN) == 0)
                        {
				int  val;
				bool succp;
				
                                router->rwsplit_config.rw_max_slave_conn_count = 0;
                                
				succp = config_get_valint(&val, param, NULL, paramtype);
				
				if (succp)
				{
					router->rwsplit_config.rw_max_slave_conn_percent = val;
				}	
                        }
                }
		else if (paramtype == SQLVAR_TARGET_TYPE)
		{
			if (strncmp(param->name, 
				"use_sql_variables_in", 
				MAX_PARAM_LEN) == 0)
			{
				target_t valtarget;
				bool succp;
				
				succp = config_get_valtarget(&valtarget, param, NULL, paramtype);
				
				if (succp)
				{
					router->rwsplit_config.rw_use_sql_variables_in = valtarget;
				}
			}
		}
		
                if (refresh_single)
                {
                        break;
                }
                param = param->next;
        }
        
#if defined(NOT_USED) /*< can't read monitor config parameters */
        if ((*router->servers)->backend_server->rlag == -2)
        {
                rlag_enabled = false;
        }
        else
        {
                rlag_enabled = true;
        }
        /** 
         * If replication lag detection is not enabled the measure can't be
         * used in slave selection.
         */
        if (!rlag_enabled)
        {
                if (rlag_limited)
                {
                        LOGIF(LE, (skygw_log_write_flush(
                                LOGFILE_ERROR,
                                "Warning : Configuration Failed, max_slave_replication_lag "
                                "is set to %d,\n\t\t      but detect_replication_lag "
                                "is not enabled. Replication lag will not be checked.",
                                router->rwsplit_config.rw_max_slave_replication_lag)));
                }
            
                if (router->rwsplit_config.rw_slave_select_criteria == 
                        LEAST_BEHIND_MASTER)
                {
                        LOGIF(LE, (skygw_log_write_flush(
                                LOGFILE_ERROR,
                                "Warning : Configuration Failed, router option "
                                "\n\t\t      slave_selection_criteria=LEAST_BEHIND_MASTER "
                                "is specified, but detect_replication_lag "
                                "is not enabled.\n\t\t      "
                                "slave_selection_criteria=%s will be used instead.",
                                STRCRITERIA(DEFAULT_CRITERIA))));
                        
                        router->rwsplit_config.rw_slave_select_criteria =
                                DEFAULT_CRITERIA;
                }
        }
#endif /*< NOT_USED */

}

/**
 * Create an instance of read/write statement router within the MaxScale.
 *
 * 
 * @param service	The service this router is being create for
 * @param options	The options for this query router
 *
 * @return NULL in failure, pointer to router in success.
 */
static ROUTER *
createInstance(SERVICE *service, char **options)
{
        ROUTER_INSTANCE*    router;
        SERVER*             server;
        SERVER_REF*         sref;
        int                 nservers;
        int                 i;
        CONFIG_PARAMETER*   param;
	char		    *weightby;
        
        if ((router = calloc(1, sizeof(ROUTER_INSTANCE))) == NULL) {
                return NULL; 
        } 
        router->service = service;
        spinlock_init(&router->lock);
        
        /** Calculate number of servers */
        sref = service->dbref;
        nservers = 0;
        
        while (sref != NULL)
        {
                nservers++;
                sref=sref->next;
        }
        router->servers = (BACKEND **)calloc(nservers + 1, sizeof(BACKEND *));
        
        if (router->servers == NULL)
        {
                free(router);
                return NULL;
        }
        /**
         * Create an array of the backend servers in the router structure to
         * maintain a count of the number of connections to each
         * backend server.
         */

        sref = service->dbref;
        nservers= 0;
        
        while (sref != NULL) {
                if ((router->servers[nservers] = malloc(sizeof(BACKEND))) == NULL)
                {
                        /** clean up */
                        for (i = 0; i < nservers; i++) {
                                free(router->servers[i]);
                        }
                        free(router->servers);
                        free(router);
                        return NULL;
                }
                router->servers[nservers]->backend_server = sref->server;
                router->servers[nservers]->backend_conn_count = 0;
                router->servers[nservers]->be_valid = false;
                router->servers[nservers]->weight = 1000;
#if defined(SS_DEBUG)
                router->servers[nservers]->be_chk_top = CHK_NUM_BACKEND;
                router->servers[nservers]->be_chk_tail = CHK_NUM_BACKEND;
#endif
                nservers += 1;
                sref = sref->next;
        }
        router->servers[nservers] = NULL;

	/*
	 * Until we know otherwise assume we have some available slaves.
	 */
	router->available_slaves = true;

	/*
	 * If server weighting has been defined calculate the percentage
	 * of load that will be sent to each server. This is only used for
	 * calculating the least connections, either globally or within a
	 * service, or the numebr of current operations on a server.
	 */
	if ((weightby = serviceGetWeightingParameter(service)) != NULL)
	{
		int 	n, total = 0;
		BACKEND	*backend;

		for (n = 0; router->servers[n]; n++)
		{
			backend = router->servers[n];
			total += atoi(serverGetParameter(
					backend->backend_server, weightby));
		}
		if (total == 0)
		{
			LOGIF(LE, (skygw_log_write(LOGFILE_ERROR,
				"WARNING: Weighting Parameter for service '%s' "
				"will be ignored as no servers have values "
				"for the parameter '%s'.\n",
				service->name, weightby)));
		}
		else
		{
			for (n = 0; router->servers[n]; n++)
			{
				int perc;
				int wght;
				backend = router->servers[n];
				wght = atoi(serverGetParameter(backend->backend_server,
							       weightby));
				perc = (wght*1000) / total;
					
				if (perc == 0 && wght != 0)
				{
					perc = 1;
				}
				backend->weight = perc;

				if (perc == 0)
				{
					LOGIF(LE, (skygw_log_write(
						LOGFILE_ERROR,
						"Server '%s' has no value "
						"for weighting parameter '%s', "
						"no queries will be routed to "
						"this server.\n",
						router->servers[n]->backend_server->unique_name,
						weightby)));
				}
			}
		}
	}
        
        /**
         * vraa : is this necessary for readwritesplit ?
         * Option : where can a read go?
         * - master (only)
         * - slave (only)
         * - joined (to both)
         *
	 * Process the options
	 */
	router->bitmask = 0;
	router->bitvalue = 0;
        
	router->semantics.must_reply = SNUM_ONE;
	router->semantics.reply_on = SRES_DCB;
	router->semantics.timeout = 0;
	router->semantics.on_error = SERR_DROP;
	
        /** Call this before refreshInstance */
	if (options)
	{
                rwsplit_process_router_options(router, options);
	}
	/** 
         * Set default value for max_slave_connections and for slave selection
         * criteria. If parameter is set in config file max_slave_connections 
         * will be overwritten.
         */
        router->rwsplit_config.rw_max_slave_conn_count = CONFIG_MAX_SLAVE_CONN;
        
        if (router->rwsplit_config.rw_slave_select_criteria == UNDEFINED_CRITERIA)
        {
                router->rwsplit_config.rw_slave_select_criteria = DEFAULT_CRITERIA;
        }
        /**
         * Copy all config parameters from service to router instance.
         * Finally, copy version number to indicate that configs match.
         */
        param = config_get_param(service->svc_config_param, "max_slave_connections");
        
        if (param != NULL)
        {
                refreshInstance(router, param);
        }
        /** 
         * Read default value for slave replication lag upper limit and then
         * configured value if it exists.
         */
        router->rwsplit_config.rw_max_slave_replication_lag = CONFIG_MAX_SLAVE_RLAG;
        param = config_get_param(service->svc_config_param, "max_slave_replication_lag");
        
        if (param != NULL)
        {
                refreshInstance(router, param);
        }
        router->rwsplit_version = service->svc_config_version;
	/** Set default values */
	router->rwsplit_config.rw_use_sql_variables_in = CONFIG_SQL_VARIABLES_IN;
	param = config_get_param(service->svc_config_param, "use_sql_variables_in");

	if (param != NULL)
	{
		refreshInstance(router, param);
	}
        /**
         * We have completed the creation of the router data, so now
         * insert this router into the linked list of routers
         * that have been created with this module.
         */
        spinlock_acquire(&instlock);
        router->next = instances;
        instances = router;
        spinlock_release(&instlock);
        
        return (ROUTER *)router;
}

/**
 * Associate a new session with this instance of the router.
 *
 * The session is used to store all the data required for a particular
 * client connection.
 *
 * @param instance	The router instance data
 * @param session	The session itself
 * @return Session specific data for this session
 */
static void* newSession(
        ROUTER*  router,
        SESSION* session)
{
    return handle_newSession(router,session);
}



/**
 * Close a session with the router, this is the mechanism
 * by which a router may cleanup data structure etc.
 *
 * @param instance	The router instance data
 * @param session	The session being closed
 */
static void closeSession(
        ROUTER* router,
        void*   session)
{
    handle_closeSession(router,session);
}

/**
 * When router session is closed, freeSession can be called to free allocated 
 * resources.
 * 
 * @param router_instance	The router instance the session belongs to
 * @param router_client_session	Client session
 * 
 */
static void freeSession(
        ROUTER* router,
        void*   session)
{
    handle_freeSession(router,session);
}

/**
 * Provide the router with a pointer to a suitable backend dcb. 
 * 
 * Detect failures in server statuses and reselect backends if necessary.
 * If name is specified, server name becomes primary selection criteria. 
 * Similarly, if max replication lag is specified, skip backends which lag too 
 * much.
 * 
 * @param p_dcb Address of the pointer to the resulting DCB
 * @param rses  Pointer to router client session
 * @param btype Backend type
 * @param name  Name of the backend which is primarily searched. May be NULL.
 * 
 * @return True if proper DCB was found, false otherwise.
 */
 bool get_dcb(
        DCB**              p_dcb,
        ROUTER_CLIENT_SES* rses,
        backend_type_t     btype,
        char*              name,
        int                max_rlag)
{
        backend_ref_t* backend_ref;
	backend_ref_t* master_bref;
        int            i;
        bool           succp = false;
	BACKEND*       master_host;
        
        CHK_CLIENT_RSES(rses);
        ss_dassert(p_dcb != NULL && *(p_dcb) == NULL);
        
        if (p_dcb == NULL)
        {
                goto return_succp;
        }
        backend_ref = rses->rses_backend_ref;

	/** get root master from available servers */
	master_bref = get_root_master_bref(rses);
	/**
	 * If master can't be found, session will be closed.
	 */
	if (master_bref == NULL)
	{
		goto return_succp;
	}
#if defined(SS_DEBUG)
	/** master_host is just for additional checking */
	master_host = get_root_master(backend_ref, rses->rses_nbackends);
	if (master_bref->bref_backend != master_host)
	{
		LOGIF(LT, (skygw_log_write(LOGFILE_TRACE,
			"Master has changed.")));
	}
#endif
	if (name != NULL) /*< Choose backend by name from a hint */
	{
		ss_dassert(btype != BE_MASTER); /*< Master dominates and no name should be passed with it */
		
		for (i=0; i<rses->rses_nbackends; i++)
		{
			BACKEND* b = backend_ref[i].bref_backend;			
			/**
			 * To become chosen:
			 * backend must be in use, name must match,
			 * root master node must be found,
			 * backend's role must be either slave, relay 
			 * server, or master.
			 */
			if (BREF_IS_IN_USE((&backend_ref[i])) &&
				(strncasecmp(
					name,
					b->backend_server->unique_name, 
					PATH_MAX) == 0) &&
				master_bref->bref_backend != NULL && 
				(SERVER_IS_SLAVE(b->backend_server) || 
					SERVER_IS_RELAY_SERVER(b->backend_server) ||
					SERVER_IS_MASTER(b->backend_server)))
			{
				*p_dcb = backend_ref[i].bref_dcb;
				succp = true; 
				ss_dassert(backend_ref[i].bref_dcb->state != DCB_STATE_ZOMBIE);
				break;
			}
		}
		if (succp)
		{
			goto return_succp;
		}
		else
		{
			btype = BE_SLAVE;
		}
	}
	
        if (btype == BE_SLAVE)
        {
		backend_ref_t* candidate_bref = NULL;

		for (i=0; i<rses->rses_nbackends; i++)
		{
			BACKEND* b = (&backend_ref[i])->bref_backend;
			/** 
			 * Unused backend or backend which is not master nor
			 * slave can't be used 
			 */
			if (!BREF_IS_IN_USE(&backend_ref[i]) || 
				(!SERVER_IS_MASTER(b->backend_server) &&
				!SERVER_IS_SLAVE(b->backend_server)))
			{
				continue;
			}
			/** 
			 * If there are no candidates yet accept both master or
			 * slave.
			 */
			else if (candidate_bref == NULL)
			{
				/** 
				 * Ensure that master has not changed dunring 
				 * session and abort if it has.
				 */
				if (SERVER_IS_MASTER(b->backend_server) &&
					&backend_ref[i] == master_bref)
				{
					/** found master */
					candidate_bref = &backend_ref[i];						
					succp = true;
				}
				/**
				 * Ensure that max replication lag is not set
				 * or that candidate's lag doesn't exceed the
				 * maximum allowed replication lag.
				 */
				else if (max_rlag == MAX_RLAG_UNDEFINED ||
					(b->backend_server->rlag != MAX_RLAG_NOT_AVAILABLE &&
					b->backend_server->rlag <= max_rlag))
				{
					/** found slave */
					candidate_bref = &backend_ref[i];
					succp = true;
				}
			}
			/**
			 * If candidate is master, any slave which doesn't break 
			 * replication lag limits replaces it.
			 */
			else if (SERVER_IS_MASTER(candidate_bref->bref_backend->backend_server) &&
				SERVER_IS_SLAVE(b->backend_server) &&
				(max_rlag == MAX_RLAG_UNDEFINED ||
				(b->backend_server->rlag != MAX_RLAG_NOT_AVAILABLE &&
				b->backend_server->rlag <= max_rlag)))
			{
				/** found slave */
				candidate_bref = &backend_ref[i];
				succp = true;				
			}
			/** 
			 * When candidate exists, compare it against the current
			 * backend and update assign it to new candidate if 
			 * necessary.
			 */
			else if (SERVER_IS_SLAVE(b->backend_server))
			{
				if (max_rlag == MAX_RLAG_UNDEFINED ||
				(b->backend_server->rlag != MAX_RLAG_NOT_AVAILABLE &&
				b->backend_server->rlag <= max_rlag))
				{
					candidate_bref = check_candidate_bref(
								candidate_bref,
								&backend_ref[i],
								rses->rses_config.rw_slave_select_criteria);
				}
				else
				{
					LOGIF(LT, (skygw_log_write(
						LOGFILE_TRACE,
						"Server %s:%d is too much behind the "
						"master, %d s. and can't be chosen.",
						b->backend_server->name,
						b->backend_server->port,
						b->backend_server->rlag)));
				}
			}
		} /*<  for */
		/** Assign selected DCB's pointer value */
		if (candidate_bref != NULL)
		{
			*p_dcb = candidate_bref->bref_dcb;
		}
		
		goto return_succp;
	} /*< if (btype == BE_SLAVE) */
	/** 
	 * If target was originally master only then the execution jumps 
	 * directly here.
	 */
        if (btype == BE_MASTER)
        {
		if (BREF_IS_IN_USE(master_bref) &&
			SERVER_IS_MASTER(master_bref->bref_backend->backend_server))
		{
			*p_dcb = master_bref->bref_dcb;
			succp = true;
			/** if bref is in use DCB should not be closed */
			ss_dassert(master_bref->bref_dcb->state != DCB_STATE_ZOMBIE);
		}
		else
		{
			LOGIF(LE, (skygw_log_write_flush(
				LOGFILE_ERROR,
				"Error : Server at %s:%d should be master but "
				"is %s instead and can't be chosen to master.",
				master_bref->bref_backend->backend_server->name,
				master_bref->bref_backend->backend_server->port,
				STRSRVSTATUS(master_bref->bref_backend->backend_server))));
			succp = false;
		}
        }
        
return_succp:
        return succp;
}


/**
 * Find out which of the two backend servers has smaller value for select 
 * criteria property.
 * 
 * @param cand	previously selected candidate
 * @param new	challenger
 * @param sc	select criteria
 * 
 * @return pointer to backend reference of that backend server which has smaller
 * value in selection criteria. If either reference pointer is NULL then the 
 * other reference pointer value is returned.
 */
backend_ref_t* check_candidate_bref(
	backend_ref_t* cand,
	backend_ref_t* new,
	select_criteria_t sc)
{
	int (*p)(const void *, const void *);
	/** get compare function */
	p = criteria_cmpfun[sc];
	
	if (new == NULL)
	{
		return cand;
	}
	else if (cand == NULL || (p((void *)cand,(void *)new) > 0))
	{
		return new;
	}
	else
	{
		return cand;
	}
}

/**
 * The main routing entry, this is called with every packet that is
 * received and has to be forwarded to the backend database.
 *
 * The routeQuery will make the routing decision based on the contents
 * of the instance, session and the query itself in the queue. The
 * data in the queue may not represent a complete query, it represents
 * the data that has been received. The query router itself is responsible
 * for buffering the partial query, a later call to the query router will
 * contain the remainder, or part thereof of the query.
 *
 * @param instance		The query router instance
 * @param router_session	The session associated with the client
 * @param querybuf		MaxScale buffer queue with received packet
 *
 * @return if succeed 1, otherwise 0
 * If routeQuery fails, it means that router session has failed.
 * In any tolerated failure, handleError is called and if necessary,
 * an error message is sent to the client.
 * 
 * For now, routeQuery don't tolerate errors, so any error will close
 * the session. vraa 14.6.14
 */
static int routeQuery(
        ROUTER* instance,
        void*   router_session,
        GWBUF*  querybuf)
{
        int                ret            = 0;
        ROUTER_INSTANCE*   inst           = (ROUTER_INSTANCE *)instance;
        ROUTER_CLIENT_SES* router_cli_ses = (ROUTER_CLIENT_SES *)router_session;
	bool           	   succp          = false;

        CHK_CLIENT_RSES(router_cli_ses);

	/**
	 * GWBUF is called "type undefined" when the incoming data isn't parsed
	 * and MySQL packets haven't been extracted to separate buffers. 
	 * "Undefined" == "untyped".
	 * Untyped GWBUF means that it can consist of incomplete and/or multiple
	 * MySQL packets. 
	 * Read and route found MySQL packets one by one and store potential 
	 * incomplete packet to DCB's dcb_readqueue.
	 */
        if (GWBUF_IS_TYPE_UNDEFINED(querybuf))
	{
		GWBUF* tmpbuf = querybuf;
		do 
		{
			/**
			 * Try to read complete MySQL packet from tmpbuf.
			 * Append leftover to client's read queue.
			 */
			if ((querybuf = modutil_get_next_MySQL_packet(&tmpbuf)) == NULL)
			{
				if (GWBUF_LENGTH(tmpbuf) > 0)
				{
					DCB* dcb = rses_get_client_dcb(router_cli_ses);
					
					dcb->dcb_readqueue = gwbuf_append(dcb->dcb_readqueue, tmpbuf);
				}
				succp = true;
				goto retblock;
			}
			/** Mark buffer to as MySQL type */
			gwbuf_set_type(querybuf, GWBUF_TYPE_MYSQL);
			gwbuf_set_type(querybuf, GWBUF_TYPE_SINGLE_STMT);

			/** 
			 * If router is closed, discard the packet
			 */
			if (router_cli_ses->rses_closed)
			{
				uint8_t*           packet;
				mysql_server_cmd_t packet_type;
				
				packet = GWBUF_DATA(querybuf);
				packet_type = packet[4];
				
				if (packet_type != MYSQL_COM_QUIT)
				{
					char* query_str = modutil_get_query(querybuf);
					
					LOGIF(LE, (skygw_log_write_flush(
						LOGFILE_ERROR,
						"Error: Can't route %s:\"%s\" to "
						"backend server. Router is closed.",
						STRPACKETTYPE(packet_type),
						(query_str == NULL ? "(empty)" : query_str))));
					free(query_str);
				}
			}
			else
			{
				succp = route_single_stmt(inst, router_cli_ses, querybuf);
			}
		}
		while (tmpbuf != NULL);			
	}
	/** 
	 * If router is closed, discard the packet
	 */
	else if (router_cli_ses->rses_closed)
	{
		uint8_t*           packet;
		mysql_server_cmd_t packet_type;
		
		packet = GWBUF_DATA(querybuf);
		packet_type = packet[4];
		
		if (packet_type != MYSQL_COM_QUIT)
		{
			char* query_str = modutil_get_query(querybuf);
			
			LOGIF(LE, (skygw_log_write_flush(
				LOGFILE_ERROR,
				"Error: Can't route %s:\"%s\" to "
				"backend server. Router is closed.",
				STRPACKETTYPE(packet_type),
				(query_str == NULL ? "(empty)" : query_str))));
			free(query_str);
		}
	}
	else
	{
		succp = route_single_stmt(inst, router_cli_ses, querybuf);
	}
	
retblock:

	if (querybuf != NULL) gwbuf_free(querybuf);
	if (succp) ret = 1;

        return ret;
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
static void clientReply (
        ROUTER* instance,
        void*   router_session,
        GWBUF*  writebuf,
        DCB*    backend_dcb)
{
    handle_clientReply(instance,router_session,writebuf,backend_dcb);
}


/**
 * Return rc, rc < 0 if router session is closed. rc == 0 if there are no 
 * capabilities specified, rc > 0 when there are capabilities.
 */ 
static uint8_t getCapabilities (
        ROUTER* inst,
        void*   router_session)
{
        ROUTER_CLIENT_SES* rses = (ROUTER_CLIENT_SES *)router_session;
        uint8_t            rc;
        
        if (!rses_begin_locked_router_action(rses))
        {
                rc = 0xff;
                goto return_rc;
        }
        rc = rses->rses_capabilities;
        
        rses_end_locked_router_action(rses);
        
return_rc:
        return rc;
}

/**
 * Diagnostics routine
 *
 * Print query router statistics to the DCB passed in
 *
 * @param	instance	The router instance
 * @param	dcb		The DCB for diagnostic output
 */
static	void
diagnostic(ROUTER *instance, DCB *dcb)
{
ROUTER_CLIENT_SES *router_cli_ses;
ROUTER_INSTANCE	  *router = (ROUTER_INSTANCE *)instance;
int		  i = 0;
BACKEND		  *backend;
char		  *weightby;

	spinlock_acquire(&router->lock);
	router_cli_ses = router->connections;
	while (router_cli_ses)
	{
		i++;
		router_cli_ses = router_cli_ses->next;
	}
	spinlock_release(&router->lock);
	
	dcb_printf(dcb,
                   "\tNumber of router sessions:           	%d\n",
                   router->stats.n_sessions);
	dcb_printf(dcb,
                   "\tCurrent no. of router sessions:      	%d\n",
                   i);
	dcb_printf(dcb,
                   "\tNumber of queries forwarded:          	%d\n",
                   router->stats.n_queries);
	dcb_printf(dcb,
                   "\tNumber of queries forwarded to master:	%d\n",
                   router->stats.n_master);
	dcb_printf(dcb,
                   "\tNumber of queries forwarded to slave: 	%d\n",
                   router->stats.n_slave);
	dcb_printf(dcb,
                   "\tNumber of queries forwarded to all:   	%d\n",
                   router->stats.n_all);
	if ((weightby = serviceGetWeightingParameter(router->service)) != NULL)
        {
                dcb_printf(dcb,
		   "\tConnection distribution based on %s "
                                "server parameter.\n", weightby);
                dcb_printf(dcb,
                        "\t\tServer               Target %%    Connections  "
			"Operations\n");
                dcb_printf(dcb,
                        "\t\t                               Global  Router\n");
                for (i = 0; router->servers[i]; i++)
                {
                        backend = router->servers[i];
                        dcb_printf(dcb,
				"\t\t%-20s %3.1f%%     %-6d  %-6d  %d\n",
                                backend->backend_server->unique_name,
                                (float)backend->weight / 10,
				backend->backend_server->stats.n_current,
				backend->backend_conn_count,
				backend->backend_server->stats.n_current_ops);
                }

        }
}


/**
 * Error Handler routine to resolve _backend_ failures. If it succeeds then there
 * are enough operative backends available and connected. Otherwise it fails, 
 * and session is terminated.
 *
 * @param       instance        The router instance
 * @param       router_session  The router session
 * @param       errmsgbuf       The error message to reply
 * @param       backend_dcb     The backend DCB
 * @param       action          The action: REPLY, REPLY_AND_CLOSE, NEW_CONNECTION
 * @param       succp           Result of action. True if there is at least master 
 * and enough slaves to continue session. Otherwise false.
 * 
 * Even if succp == true connecting to new slave may have failed. succp is to
 * tell whether router has enough master/slave connections to continue work.
 */
static void handleError (
        ROUTER*        instance,
        void*          router_session,
        GWBUF*         errmsgbuf,
        DCB*           backend_dcb,
        error_action_t action,
        bool*          succp)
{
        SESSION*           session;
        ROUTER_INSTANCE*   inst    = (ROUTER_INSTANCE *)instance;
        ROUTER_CLIENT_SES* rses    = (ROUTER_CLIENT_SES *)router_session;
      
        CHK_DCB(backend_dcb);

	/** Reset error handle flag from a given DCB */
	if (action == ERRACT_RESET)
	{
		backend_dcb->dcb_errhandle_called = false;
		return;
	}
	
	/** Don't handle same error twice on same DCB */
	if (backend_dcb->dcb_errhandle_called)
	{
		/** we optimistically assume that previous call succeed */
		*succp = true;
		return;
	}
	else
	{
		backend_dcb->dcb_errhandle_called = true;
	}
        session = backend_dcb->session;
        
        if (session == NULL || rses == NULL)
	{
                *succp = false;
		return;
	}
	CHK_SESSION(session);
	CHK_CLIENT_RSES(rses);
        
        switch (action) {
                case ERRACT_NEW_CONNECTION:
                {
			SERVER* srv;
			
			if (!rses_begin_locked_router_action(rses))
			{
				*succp = false;
				return;
			}
			srv = rses->rses_master_ref->bref_backend->backend_server;
			/**
			 * If master has lost its Master status error can't be 
			 * handled so that session could continue.
			 */
                        if (rses->rses_master_ref->bref_dcb == backend_dcb &&
				!SERVER_IS_MASTER(srv))
			{
				if (!srv->master_err_is_logged)
				{
					LOGIF(LE, (skygw_log_write_flush(
						LOGFILE_ERROR,
						"Error : server %s:%d lost the "
						"master status. Readwritesplit "
						"service can't locate the master. "
						"Client sessions will be closed.",
						srv->name,
						srv->port)));	
					srv->master_err_is_logged = true;
				}
				*succp = false;
			}
			else
			{
				/**
				* This is called in hope of getting replacement for 
				* failed slave(s).
				*/
			    
				*succp = handle_error_new_connection(inst, 
								rses, 
								backend_dcb, 
								errmsgbuf);
			}
                        rses_end_locked_router_action(rses);
                        break;
                }
                
                case ERRACT_REPLY_CLIENT:
                {
                        handle_error_reply_client(session, 
						  rses, 
						  backend_dcb, 
						  errmsgbuf);
			*succp = false; /*< no new backend servers were made available */
                        break;       
                }
                
		default:                        
                        *succp = false;
                        break;
        }
}


/** 
 * @node Search suitable backend servers from those of router instance.
 *
 * Parameters:
 * @param p_master_ref - in, use, out
 *      Pointer to location where master's backend reference is to  be stored.
 *      NULL is not allowed.
 *
 * @param backend_ref - in, use, out 
 *      Pointer to backend server reference object array.
 *      NULL is not allowed.
 *
 * @param router_nservers - in, use
 *      Number of backend server pointers pointed to by b.
 * 
 * @param max_nslaves - in, use
 *      Upper limit for the number of slaves. Configuration parameter or default.
 *
 * @param max_slave_rlag - in, use
 *      Maximum allowed replication lag for any slave. Configuration parameter or default.
 *
 * @param session - in, use
 *      MaxScale session pointer used when connection to backend is established.
 *
 * @param  router - in, use
 *      Pointer to router instance. Used when server states are qualified.
 * 
 * @return true, if at least one master and one slave was found.
 *
 * 
 * @details It is assumed that there is only one master among servers of
 *      a router instance. As a result, the first master found is chosen.
 *      There will possibly be more backend references than connected backends
 *      because only those in correct state are connected to.
 */
bool select_connect_backend_servers(
        backend_ref_t**    p_master_ref,
        backend_ref_t*     backend_ref,
        int                router_nservers,
        int                max_nslaves,
        int                max_slave_rlag,
        select_criteria_t  select_criteria,
        SESSION*           session,
        ROUTER_CLIENT_SES* rses,
        ROUTER_INSTANCE*   router)
{
        bool            succp = true;
        bool            master_found;
        bool            master_connected;
        int             slaves_found = 0;
        int             slaves_connected = 0;
        int             i;
        const int       min_nslaves = 0; /*< not configurable at the time */
        bool            is_synced_master;
        int (*p)(const void *, const void *);
	BACKEND*       master_host;
	SCMDCURSOR* cursor;

        if (p_master_ref == NULL || backend_ref == NULL)
        {
                ss_dassert(FALSE);
                succp = false;
                goto return_succp;
        }
      
	/* get the root Master */ 
	master_host = get_root_master(backend_ref, router_nservers);

	/** 
	 * Existing session : master is already chosen and connected. 
	 * The function was called because new slave must be selected to replace 
	 * failed one.
	 */
	if (*p_master_ref != NULL)
	{
		/**
		 * Ensure that backend reference is in use, stored master is 
		 * still current root master.
		 */
		if (!BREF_IS_IN_USE((*p_master_ref)) ||
			!SERVER_IS_MASTER((*p_master_ref)->bref_backend->backend_server) ||
			master_host != (*p_master_ref)->bref_backend)
		{
			succp = false;
			goto return_succp;
		}
		master_found     = true;
		master_connected = true;
	}
        /**
	 * New session : select master and slaves
	 */
        else
        {
                master_found     = false;
                master_connected = false;
        }
        /** Check slave selection criteria and set compare function */
        p = criteria_cmpfun[select_criteria];
        
        if (p == NULL)
        {
                succp = false;
                goto return_succp;
        }
        
        if (router->bitvalue != 0) /*< 'synced' is the only bitvalue in rwsplit */
        {
                is_synced_master = true;
        }
        else
        {
                is_synced_master = false;
        }


        /**
         * Sort the pointer list to servers according to connection counts. As 
         * a consequence those backends having least connections are in the 
         * beginning of the list.
         */
        qsort(backend_ref, (size_t)router_nservers, sizeof(backend_ref_t), p);

        if (LOG_IS_ENABLED(LOGFILE_TRACE))
        {
                if (select_criteria == LEAST_GLOBAL_CONNECTIONS ||
                        select_criteria == LEAST_ROUTER_CONNECTIONS ||
                        select_criteria == LEAST_BEHIND_MASTER ||
                        select_criteria == LEAST_CURRENT_OPERATIONS)
                {
                        LOGIF(LT, (skygw_log_write(LOGFILE_TRACE, 
                                "Servers and %s connection counts:",
                                select_criteria == LEAST_GLOBAL_CONNECTIONS ? 
                                "all MaxScale" : "router")));

                        for (i=0; i<router_nservers; i++)
                        {
                                BACKEND* b = backend_ref[i].bref_backend;
                                
                                switch(select_criteria) {
                                        case LEAST_GLOBAL_CONNECTIONS:
                                                LOGIF(LT, (skygw_log_write_flush(LOGFILE_TRACE, 
                                                        "MaxScale connections : %d in \t%s:%d %s",
							b->backend_server->stats.n_current,
							b->backend_server->name,
							b->backend_server->port,
							STRSRVSTATUS(b->backend_server))));
                                                break;
                                        
                                        case LEAST_ROUTER_CONNECTIONS:
                                                LOGIF(LT, (skygw_log_write_flush(LOGFILE_TRACE, 
                                                        "RWSplit connections : %d in \t%s:%d %s",
							b->backend_conn_count,
							b->backend_server->name,
							b->backend_server->port,
							STRSRVSTATUS(b->backend_server))));
                                                break;
                                                
                                        case LEAST_CURRENT_OPERATIONS:
                                                LOGIF(LT, (skygw_log_write_flush(LOGFILE_TRACE, 
							"current operations : %d in \t%s:%d %s",
							b->backend_server->stats.n_current_ops, 
							b->backend_server->name,
							b->backend_server->port,
							STRSRVSTATUS(b->backend_server))));
                                                break;
                                                
                                        case LEAST_BEHIND_MASTER:
                                                LOGIF(LT, (skygw_log_write_flush(LOGFILE_TRACE, 
							"replication lag : %d in \t%s:%d %s",
							b->backend_server->rlag,
							b->backend_server->name,
							b->backend_server->port,
							STRSRVSTATUS(b->backend_server))));
                                        default:
                                                break;
                                }
                        } 
                }
        } /*< log only */
        
        /**
         * Choose at least 1+min_nslaves (master and slave) and at most 1+max_nslaves 
         * servers from the sorted list. First master found is selected.
         */
        for (i=0; 
             i<router_nservers && 
             (slaves_connected < max_nslaves || !master_connected);
             i++)
        {
                BACKEND* b = backend_ref[i].bref_backend;

		if (router->servers[i]->weight == 0)
		{
			continue;
		}
		
                if (SERVER_IS_RUNNING(b->backend_server) &&
                        ((b->backend_server->status & router->bitmask) ==
                        router->bitvalue))
                {
			/* check also for relay servers and don't take the master_host */
                        if (slaves_found < max_nslaves &&
                                (max_slave_rlag == MAX_RLAG_UNDEFINED || 
                                (b->backend_server->rlag != MAX_RLAG_NOT_AVAILABLE &&
                                 b->backend_server->rlag <= max_slave_rlag)) &&
                                (SERVER_IS_SLAVE(b->backend_server) || 
					SERVER_IS_RELAY_SERVER(b->backend_server)) &&
				(master_host != NULL && 
					(b->backend_server != master_host->backend_server)))
                        {
                                slaves_found += 1;
                                
                                /** Slave is already connected */
                                if (BREF_IS_IN_USE((&backend_ref[i])))
                                {
                                        slaves_connected += 1;
                                }
                                /** New slave connection is taking place */
                                else
                                {
                                        backend_ref[i].bref_dcb = dcb_connect(
                                                b->backend_server,
                                                session,
                                                b->backend_server->protocol);
                                        
                                        if (backend_ref[i].bref_dcb != NULL)
                                        {
                                                slaves_connected += 1;
                                                
                                                /**
                                                 * Start executing session command
                                                 * history.
                                                 */
                                                sescmdlist_add_dcb(rses->rses_sescmd_list,backend_ref[i].bref_dcb);
						cursor = dcb_get_sescmdcursor(backend_ref[i].bref_dcb);
						sescmdlist_execute(cursor);

                                                /** 
						 * Here we actually say : When this
						 * type of issue occurs (DCB_REASON_...)
						 * for this particular DCB, 
						 * call this function.
                                                 */
                                                dcb_add_callback(
                                                        backend_ref[i].bref_dcb,
                                                        DCB_REASON_NOT_RESPONDING,
                                                        &router_handle_state_switch,
                                                        (void *)&backend_ref[i]);
                                                backend_ref[i].bref_state = 0;
                                                bref_set_state(&backend_ref[i], 
                                                               BREF_IN_USE);
                                               /** 
                                                * Increase backend connection counter.
                                                * Server's stats are _increased_ in 
                                                * dcb.c:dcb_alloc !
                                                * But decreased in the calling function 
                                                * of dcb_close.
                                                */
                                                atomic_add(&b->backend_conn_count, 1);
                                        }
                                        else
                                        {
                                                LOGIF(LE, (skygw_log_write_flush(
                                                        LOGFILE_ERROR,
                                                        "Error : Unable to establish "
                                                        "connection with slave %s:%d",
                                                        b->backend_server->name,
                                                        b->backend_server->port)));
                                                /* handle connect error */
                                        }
                                }
                        }
			/* take the master_host for master */
			else if (master_host && 
                                (b->backend_server == master_host->backend_server))
                        {
				/** 
				 * *p_master_ref must be assigned with this 
				 * backend_ref pointer because its original value
				 * may have been lost when backend references were
				 * sorted (qsort).
				 */
                                *p_master_ref = &backend_ref[i];
                                
                                if (master_connected)
                                {   
                                        continue;
                                }
                                master_found = true;
                                  
                                backend_ref[i].bref_dcb = dcb_connect(
                                        b->backend_server,
                                        session,
                                        b->backend_server->protocol);
                                
                                if (backend_ref[i].bref_dcb != NULL)
                                {
                                        master_connected = true;
                                        /** 
                                         * When server fails, this callback
                                         * is called.
                                         */
                                        dcb_add_callback(
                                                backend_ref[i].bref_dcb,
                                                DCB_REASON_NOT_RESPONDING,
                                                &router_handle_state_switch,
                                                (void *)&backend_ref[i]);

                                        backend_ref[i].bref_state = 0;
                                        bref_set_state(&backend_ref[i], 
                                                       BREF_IN_USE);
                                        /** Increase backend connection counters */
                                        atomic_add(&b->backend_conn_count, 1);
                                }
                                else
                                {
                                        succp = false;
                                        LOGIF(LE, (skygw_log_write_flush(
                                                LOGFILE_ERROR,
                                                "Error : Unable to establish "
                                                "connection with master %s:%d",
                                                b->backend_server->name,
                                                b->backend_server->port)));
                                        /** handle connect error */
                                }
                        }       
                }
        } /*< for */

        
        /**
         * Successful cases
         */
        if (master_connected && 
                slaves_connected >= min_nslaves && 
                slaves_connected <= max_nslaves)
        {
                succp = true;
                
                if (slaves_connected == 0 && slaves_found > 0)
                {

                }
                else if (slaves_found == 0)
                {

                }
                else if (slaves_connected < max_nslaves)
                {
                        LOGIF(LT, (skygw_log_write_flush(
                                LOGFILE_TRACE,
                                "Note : Couldn't connect to maximum number of "
                                "slaves. Connected successfully to %d slaves "
                                "of %d of them.",
                                slaves_connected,
                                slaves_found)));
                }
                
                if (LOG_IS_ENABLED(LT))
                {
                        for (i=0; i<router_nservers; i++)
                        {
                                BACKEND* b = backend_ref[i].bref_backend;

                                if (BREF_IS_IN_USE((&backend_ref[i])))
                                {                                        
                                        LOGIF(LT, (skygw_log_write(
                                                LOGFILE_TRACE,
                                                "Selected %s in \t%s:%d",
                                                STRSRVSTATUS(b->backend_server),
                                                b->backend_server->name,
                                                b->backend_server->port)));
                                }
                        } /* for */
                }
        }
        /**
         * Failure cases
         */
        else
        {          
                succp = false;
                
                if (!master_found)
                {
                        LOGIF(LE, (skygw_log_write(
                                LOGFILE_ERROR,
                                "Error : Couldn't find suitable %s from %d "
                                "candidates.",
                                (is_synced_master ? "Galera node" : "Master"),
                                router_nservers)));
                        
                        LOGIF(LM, (skygw_log_write(
                                LOGFILE_MESSAGE,
                                "Error : Couldn't find suitable %s from %d "
                                "candidates.",
                                (is_synced_master ? "Galera node" : "Master"),
                                router_nservers)));
 
                        LOGIF(LT, (skygw_log_write(
                                LOGFILE_TRACE,
                                "Error : Couldn't find suitable %s from %d "
                                "candidates.",
                                (is_synced_master ? "Galera node" : "Master"),
                                router_nservers)));
                }
                else if (!master_connected)
                {
                        LOGIF(LE, (skygw_log_write(
                                LOGFILE_ERROR,
                                "Error : Couldn't connect to any %s although "
                                "there exists at least one %s node in the "
                                "cluster.",
                                (is_synced_master ? "Galera node" : "Master"),
                                (is_synced_master ? "Galera node" : "Master"))));
                        
                        LOGIF(LM, (skygw_log_write(
                                LOGFILE_MESSAGE,
                                "Error : Couldn't connect to any %s although "
                                "there exists at least one %s node in the "
                                "cluster.",
                                (is_synced_master ? "Galera node" : "Master"),
                                (is_synced_master ? "Galera node" : "Master"))));

                        LOGIF(LT, (skygw_log_write(
                                LOGFILE_TRACE,
                                "Error : Couldn't connect to any %s although "
                                "there exists at least one %s node in the "
                                "cluster.",
                                (is_synced_master ? "Galera node" : "Master"),
                                (is_synced_master ? "Galera node" : "Master"))));
                }

                if (slaves_connected < min_nslaves)
                {
                        LOGIF(LE, (skygw_log_write(
                                LOGFILE_ERROR,
                                "Error : Couldn't establish required amount of "
                                "slave connections for router session.")));
                        
                        LOGIF(LM, (skygw_log_write(
                                LOGFILE_MESSAGE,
                                "Error : Couldn't establish required amount of "
                                "slave connections for router session.")));
                }
                
                /** Clean up connections */
                for (i=0; i<router_nservers; i++)
                {
                        if (BREF_IS_IN_USE((&backend_ref[i])))
                        {
                                ss_dassert(backend_ref[i].bref_backend->backend_conn_count > 0);
                                
                                /** disconnect opened connections */
                                dcb_close(backend_ref[i].bref_dcb);
                                bref_clear_state(&backend_ref[i], BREF_IN_USE);
                                /** Decrease backend's connection counter. */
                                atomic_add(&backend_ref[i].bref_backend->backend_conn_count, -1);
                        }
                }
                master_connected = false;
                slaves_connected = 0;
        }
return_succp:

        return succp;
}

 void rwsplit_process_router_options(
        ROUTER_INSTANCE* router,
        char**           options)
{
        int               i;
        char*             value;
        select_criteria_t c;
        
        for (i = 0; options[i]; i++)
        {
                if ((value = strchr(options[i], '=')) == NULL)
                {
                        LOGIF(LE, (skygw_log_write(
                                LOGFILE_ERROR, "Warning : Unsupported "
                                "router option \"%s\" for "
                                "readwritesplit router.",
                                options[i])));
                }
                else
                {
                        *value = 0;
                        value++;
                        if (strcmp(options[i], "slave_selection_criteria") == 0)
                        {
                                c = GET_SELECT_CRITERIA(value);
                                ss_dassert(
                                        c == LEAST_GLOBAL_CONNECTIONS ||
                                        c == LEAST_ROUTER_CONNECTIONS ||
                                        c == LEAST_BEHIND_MASTER ||
                                        c == LEAST_CURRENT_OPERATIONS ||
                                        c == UNDEFINED_CRITERIA);
                               
                                if (c == UNDEFINED_CRITERIA)
                                {
                                        LOGIF(LE, (skygw_log_write(
                                                LOGFILE_ERROR, "Warning : Unknown "
                                                "slave selection criteria \"%s\". "
                                                "Allowed values are LEAST_GLOBAL_CONNECTIONS, "
                                                "LEAST_ROUTER_CONNECTIONS, "
                                                "LEAST_BEHIND_MASTER,"
                                                "and LEAST_CURRENT_OPERATIONS.",
                                                STRCRITERIA(router->rwsplit_config.rw_slave_select_criteria))));
                                }
                                else
                                {
                                        router->rwsplit_config.rw_slave_select_criteria = c;
                                }
                        }
			else if(strcmp(options[i], "sescmd_reply_on") == 0)
			{
			    if(strcmp(value, "first") == 0)
			    {
				router->semantics.reply_on = SRES_FIRST;
			    }
			    else if(strcmp(value, "last") == 0)
			    {
				router->semantics.reply_on = SRES_LAST;
			    }
			    else
			    {
				int val = atoi(value);
				router->semantics.min_nreplies =  val;
				router->semantics.reply_on = SRES_MIN;
			    }
			}			
                }
        } /*< for */
}

/** 
 * Find out the number of read backend servers.
 * Depending on the configuration value type, either copy direct count 
 * of slave connections or calculate the count from percentage value.
 */
int rses_get_max_slavecount(
        ROUTER_CLIENT_SES* rses,
        int                router_nservers)
{
        int conf_max_nslaves;
        int max_nslaves;
        
        CHK_CLIENT_RSES(rses);
        
        if (rses->rses_config.rw_max_slave_conn_count > 0)
        {
                conf_max_nslaves = rses->rses_config.rw_max_slave_conn_count;
        }
        else
        {
                conf_max_nslaves = 
                (router_nservers*rses->rses_config.rw_max_slave_conn_percent)/100;
        }
        max_nslaves = MIN(router_nservers-1, MAX(1, conf_max_nslaves));
        
        return max_nslaves;
}


int rses_get_max_replication_lag(
        ROUTER_CLIENT_SES* rses)
{
        int conf_max_rlag;
        
        CHK_CLIENT_RSES(rses);
        
        /** if there is no configured value, then longest possible int is used */
        if (rses->rses_config.rw_max_slave_replication_lag > 0)
        {
                conf_max_rlag = rses->rses_config.rw_max_slave_replication_lag;
        }
        else
        {
                conf_max_rlag = ~(1<<31);
        }
        
        return conf_max_rlag;
}
