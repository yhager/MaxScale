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

/** Defined in log_manager.cc */
extern int            lm_enabled_logfiles_bitmask;
extern size_t         log_ses_count[];
extern __thread       log_info_t tls_log_info;

bool rses_begin_locked_router_action(
        ROUTER_CLIENT_SES* rses);
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
 void* handle_newSession(
        ROUTER*  router_inst,
        SESSION* session)
{
        backend_ref_t*      backend_ref; /*< array of backend references (DCB,BACKEND,cursor) */
        backend_ref_t*      master_ref  = NULL; /*< pointer to selected master */
        ROUTER_CLIENT_SES*  client_rses = NULL;
        ROUTER_INSTANCE*    router      = (ROUTER_INSTANCE *)router_inst;
        bool                succp;
        int                 router_nservers = 0; /*< # of servers in total */
        int                 max_nslaves;      /*< max # of slaves used in this session */
        int                 max_slave_rlag;   /*< max allowed replication lag for any slave */
        int                 i;
        const int           min_nservers = 1; /*< hard-coded for now */
        
        client_rses = (ROUTER_CLIENT_SES *)calloc(1, sizeof(ROUTER_CLIENT_SES));
        
        if (client_rses == NULL)
        {
                ss_dassert(false);
                goto return_rses;
        }
#if defined(SS_DEBUG)
        client_rses->rses_chk_top = CHK_NUM_ROUTER_SES;
        client_rses->rses_chk_tail = CHK_NUM_ROUTER_SES;
#endif

	client_rses->router = router;
        /** 
         * If service config has been changed, reload config from service to 
         * router instance first.
         */
        spinlock_acquire(&router->lock);
        
        if (router->service->svc_config_version > router->rwsplit_version)
        {
                /** re-read all parameters to rwsplit config structure */
                refreshInstance(router, NULL); /*< scan through all parameters */
                /** increment rwsplit router's config version number */
                router->rwsplit_version = router->service->svc_config_version;  
                /** Read options */
                rwsplit_process_router_options(router, router->service->routerOptions);
        }
        /** Copy config struct from router instance */
        client_rses->rses_config = router->rwsplit_config;
        
        spinlock_release(&router->lock);
        /** 
         * Set defaults to session variables. 
         */
        client_rses->rses_autocommit_enabled = true;
        client_rses->rses_transaction_active = false;
        
        router_nservers = router_get_servercount(router);
        
        if (!have_enough_servers(&client_rses, 
                                min_nservers, 
                                router_nservers, 
                                router))
        {
                goto return_rses;
        }
        
        if((client_rses->rses_sescmd_list = sescmdlist_allocate()) == NULL)
        {
            free(client_rses);
            client_rses = NULL;
            goto return_rses;
        }
        
	client_rses->rses_sescmd_list->semantics = router->semantics;
	
        /**
         * Create backend reference objects for this session.
         */
        backend_ref = (backend_ref_t *)calloc(1, router_nservers*sizeof(backend_ref_t));
        
        if (backend_ref == NULL)
        {
                /** log this */                        
                free(client_rses);
                free(backend_ref);
                client_rses = NULL;
                goto return_rses;
        }
        /** 
         * Initialize backend references with BACKEND ptr.
         * Initialize session command cursors for each backend reference.
         */
        for (i=0; i< router_nservers; i++)
        {
#if defined(SS_DEBUG)
                backend_ref[i].bref_chk_top = CHK_NUM_BACKEND_REF;
                backend_ref[i].bref_chk_tail = CHK_NUM_BACKEND_REF;
#endif
                backend_ref[i].bref_state = 0;
                backend_ref[i].bref_backend = router->servers[i];
                /** store pointers to sescmd list to both cursors */
        }
        max_nslaves    = rses_get_max_slavecount(client_rses, router_nservers);
        max_slave_rlag = rses_get_max_replication_lag(client_rses);
        
        spinlock_init(&client_rses->rses_lock);
        client_rses->rses_backend_ref = backend_ref;
        
        /**
         * Find a backend servers to connect to.
         * This command requires that rsession's lock is held.
         */

	succp = rses_begin_locked_router_action(client_rses);

        if(!succp)
	{
                free(client_rses->rses_backend_ref);
                free(client_rses);
		client_rses = NULL;
                goto return_rses;
	}
        succp = select_connect_backend_servers(&master_ref,
                                               backend_ref,
                                               router_nservers,
                                               max_nslaves,
                                               max_slave_rlag,
                                               client_rses->rses_config.rw_slave_select_criteria,
                                               session,
                                               client_rses,
                                               router);

        rses_end_locked_router_action(client_rses);
        client_rses->rses_sescmd_list->semantics.master_dcb = master_ref->bref_dcb;
        /** 
	 * Master and at least <min_nslaves> slaves must be found 
	 */
        if (!succp) {
                free(client_rses->rses_backend_ref);
                free(client_rses);
                client_rses = NULL;
                goto return_rses;                
        }
        /** Copy backend pointers to router session. */
        client_rses->rses_master_ref   = master_ref;	
	/* assert with master_host */
	ss_dassert(master_ref && (master_ref->bref_backend->backend_server && SERVER_MASTER));
        client_rses->rses_capabilities = RCAP_TYPE_STMT_INPUT;
        client_rses->rses_backend_ref  = backend_ref;
        client_rses->rses_nbackends    = router_nservers; /*< # of backend servers */
        router->stats.n_sessions      += 1;
        
	for(i = 0;i< router_nservers;i++)
	{
	    if(client_rses->rses_backend_ref[i].bref_dcb)
		sescmdlist_add_dcb(client_rses->rses_sescmd_list,
				 client_rses->rses_backend_ref[i].bref_dcb);
	}
	
        /**
         * Version is bigger than zero once initialized.
         */
        atomic_add(&client_rses->rses_versno, 2);
        ss_dassert(client_rses->rses_versno == 2);
	/**
         * Add this session to end of the list of active sessions in router.
         */
	spinlock_acquire(&router->lock);
        client_rses->next   = router->connections;
        router->connections = client_rses;
        spinlock_release(&router->lock);

return_rses:    
#if defined(SS_DEBUG)
        if (client_rses != NULL)
        {
                CHK_CLIENT_RSES(client_rses);
        }
#endif
        return (void *)client_rses;
}



/**
 * Close a session with the router, this is the mechanism
 * by which a router may cleanup data structure etc.
 *
 * @param instance	The router instance data
 * @param session	The session being closed
 */
 void handle_closeSession(
        ROUTER* instance,
        void*   router_session)
{
        ROUTER_CLIENT_SES* router_cli_ses;
        backend_ref_t*     backend_ref;

	LOGIF(LD, (skygw_log_write(LOGFILE_DEBUG,
			   "%lu [RWSplit:closeSession]",
			    pthread_self())));                                
	
        /** 
         * router session can be NULL if newSession failed and it is discarding
         * its connections and DCB's. 
         */
        if (router_session == NULL)
        {
                return;
        }
        router_cli_ses = (ROUTER_CLIENT_SES *)router_session;
        CHK_CLIENT_RSES(router_cli_ses);
        
        backend_ref = router_cli_ses->rses_backend_ref;
        /**
         * Lock router client session for secure read and update.
         */
        if (!router_cli_ses->rses_closed &&
                rses_begin_locked_router_action(router_cli_ses))
        {
		int i;
                /** 
                 * This sets router closed. Nobody is allowed to use router
                 * whithout checking this first.
                 */
                router_cli_ses->rses_closed = true;

                for (i=0; i<router_cli_ses->rses_nbackends; i++)
                {
                        backend_ref_t* bref = &backend_ref[i];
                        DCB* dcb = bref->bref_dcb;	
                        /** Close those which had been connected */
                        if (BREF_IS_IN_USE(bref))
                        {
                                CHK_DCB(dcb);
#if defined(SS_DEBUG)
				/**
				 * session must be moved to SESSION_STATE_STOPPING state before
				 * router session is closed.
				 */
				if (dcb->session != NULL)
				{
					ss_dassert(dcb->session->state == SESSION_STATE_STOPPING);
				}
#endif				
				/** Clean operation counter in bref and in SERVER */
                                while (BREF_IS_WAITING_RESULT(bref))
                                {
                                        bref_clear_state(bref, BREF_WAITING_RESULT);
                                }
                                bref_clear_state(bref, BREF_IN_USE);
                                bref_set_state(bref, BREF_CLOSED);
                                /**
                                 * closes protocol and dcb
                                 */
                                dcb_close(dcb);
                                /** decrease server current connection counters */
                                atomic_add(&bref->bref_backend->backend_server->stats.n_current, -1);
                                atomic_add(&bref->bref_backend->backend_conn_count, -1);
                        }
                }
                /** Unlock */
                rses_end_locked_router_action(router_cli_ses);                
        }
}

/**
 * When router session is closed, freeSession can be called to free allocated 
 * resources.
 * 
 * @param router_instance	The router instance the session belongs to
 * @param router_client_session	Client session
 * 
 */
void handle_freeSession(
        ROUTER* router_instance,
        void*   router_client_session)
{
        ROUTER_CLIENT_SES* router_cli_ses;
        ROUTER_INSTANCE*   router;
	int                i;
        
        router_cli_ses = (ROUTER_CLIENT_SES *)router_client_session;
        router         = (ROUTER_INSTANCE *)router_instance;
        
        spinlock_acquire(&router->lock);

        if (router->connections == router_cli_ses) {
                router->connections = router_cli_ses->next;
        } else {
                ROUTER_CLIENT_SES* ptr = router->connections;

                while (ptr && ptr->next != router_cli_ses) {
                        ptr = ptr->next;
                }
            
                if (ptr) {
                        ptr->next = router_cli_ses->next;
                }
        }
        spinlock_release(&router->lock);
        
	/** 
	 * For each property type, walk through the list, finalize properties 
	 * and free the allocated memory. 
	 */
	for (i=RSES_PROP_TYPE_FIRST; i<RSES_PROP_TYPE_COUNT; i++)
	{
		rses_property_t* p = router_cli_ses->rses_properties[i];
		rses_property_t* q = p;
		
		while (p != NULL)
		{
			q = p->rses_prop_next;
			rses_property_done(p);
			p = q;
		}
	}
        /*
         * We are no longer in the linked list, free
         * all the memory and other resources associated
         * to the client session.
         */
        sescmdlist_free(router_cli_ses->rses_sescmd_list);
        free(router_cli_ses->rses_backend_ref);
	free(router_cli_ses);
        return;
}


/**
 * Get client DCB pointer of the router client session.
 * This routine must be protected by Router client session lock.
 * 
 * @param rses	Router client session pointer
 * 
 * @return Pointer to client DCB
 */
DCB* rses_get_client_dcb(
	ROUTER_CLIENT_SES* rses)
{
	DCB*	dcb = NULL;
	int	i;
	
	for (i=0; i<rses->rses_nbackends; i++)
	{
		if ((dcb = rses->rses_backend_ref[i].bref_dcb) != NULL &&
			BREF_IS_IN_USE(&rses->rses_backend_ref[i]) &&
			dcb->session != NULL &&
			dcb->session->client != NULL)
		{
			return dcb->session->client;
		}
	}
	return NULL;
}

/** 
 * Create a generic router session property strcture.
 */
rses_property_t* rses_property_init(
	rses_property_type_t prop_type)
{
	rses_property_t* prop;
	
	prop = (rses_property_t*)calloc(1, sizeof(rses_property_t));
	if (prop == NULL)
	{
		goto return_prop;
	}
	prop->rses_prop_type = prop_type;
#if defined(SS_DEBUG)
	prop->rses_prop_chk_top = CHK_NUM_ROUTER_PROPERTY;
	prop->rses_prop_chk_tail = CHK_NUM_ROUTER_PROPERTY;
#endif
	
return_prop:
	CHK_RSES_PROP(prop);
	return prop;
}

/**
 * Property is freed at the end of router client session.
 */
void rses_property_done(
	rses_property_t* prop)
{
	CHK_RSES_PROP(prop);
	
	switch (prop->rses_prop_type) {
	case RSES_PROP_TYPE_SESCMD:
		//mysql_sescmd_done(&prop->rses_prop_data.sescmd);
		break;
		
	case RSES_PROP_TYPE_TMPTABLES:
		hashtable_free(prop->rses_prop_data.temp_tables);
		break;
		
	default:
		LOGIF(LD, (skygw_log_write(
                                   LOGFILE_DEBUG,
                                   "%lu [rses_property_done] Unknown property type %d "
                                   "in property %p",
                                   pthread_self(),
                                   prop->rses_prop_type,
                                   prop)));
		
		ss_dassert(false);
		break;
	}
	free(prop);
}

/**
 * Add property to the router_client_ses structure's rses_properties
 * array. The slot is determined by the type of property.
 * In each slot there is a list of properties of similar type.
 * 
 * Router client session must be locked.
 */
void rses_property_add(
        ROUTER_CLIENT_SES* rses,
        rses_property_t*   prop)
{
        rses_property_t* p;
        
        CHK_CLIENT_RSES(rses);
        CHK_RSES_PROP(prop);
        ss_dassert(SPINLOCK_IS_LOCKED(&rses->rses_lock));
        
        prop->rses_prop_rsession = rses;
        p = rses->rses_properties[prop->rses_prop_type];
        
        if (p == NULL)
        {
                rses->rses_properties[prop->rses_prop_type] = prop;
        }
        else
        {
                while (p->rses_prop_next != NULL)
                {
                        p = p->rses_prop_next;
                }
                p->rses_prop_next = prop;
        }
}

/** 
 * @node Acquires lock to router client session if it is not closed.
 *
 * Parameters:
 * @param rses - in, use
 *          
 *
 * @return true if router session was not closed. If return value is true
 * it means that router is locked, and must be unlocked later. False, if
 * router was closed before lock was acquired.
 *
 * 
 * @details (write detailed description here)
 *
 */
bool rses_begin_locked_router_action(
        ROUTER_CLIENT_SES* rses)
{
        bool succp = false;
        
        CHK_CLIENT_RSES(rses);

        if (rses->rses_closed) {
                
                goto return_succp;
        }       
        spinlock_acquire(&rses->rses_lock);
        if (rses->rses_closed) {
                spinlock_release(&rses->rses_lock);
                goto return_succp;
        }       
        succp = true;
        
return_succp:
        return succp;
}

/** to be inline'd */
/** 
 * @node Releases router client session lock.
 *
 * Parameters:
 * @param rses - <usage>
 *          <description>
 *
 * @return void
 *
 * 
 * @details (write detailed description here)
 *
 */
void rses_end_locked_router_action(
        ROUTER_CLIENT_SES* rses)
{
        CHK_CLIENT_RSES(rses);
        spinlock_release(&rses->rses_lock);
}
