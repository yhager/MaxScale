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
 * Copyright MariaDB Corporation Ab 2014
 */

/**
 * @file readwriteroutersession.c  - The MaxScale read-write router session class
 *
 * When a MaxScale service is created from a definition in the configuration
 * file, a router is specified and a router instance is also created.
 * 
 * When a user connects to the service, a router session is created, and this
 * class represents the router session. 
 *
 * @verbatim
 * Revision History
 *
 * Date		Who			Description
 * 04/03/15	Martin Brampton
 *              and Markus Makela	Initial implementation
 *
 * @endverbatim
 */

#include <my_config.h>
#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include <router.h>
#include <readwritesplit2.h>
#include <readwritesplitsession.h>

/** Defined in log_manager.cc */
extern int            lm_enabled_logfiles_bitmask;
extern size_t         log_ses_count[];
extern __thread       log_info_t tls_log_info;

/**
 * Calls hang-up function for DCB if it is not both running and in 
 * master/slave/joined/ndb role. Called by DCB's callback routine.
 */
int router_handle_state_switch(
        DCB*       dcb,
        DCB_REASON reason,
        void*      data)
{
        backend_ref_t*     bref;
        int                rc = 1;
        ROUTER_CLIENT_SES* rses;
        SESSION*           ses;
        SERVER*            srv;
        
        CHK_DCB(dcb);
        bref = (backend_ref_t *)data;
        CHK_BACKEND_REF(bref);
       
	srv = bref->bref_backend->backend_server;
	
        if (SERVER_IS_RUNNING(srv) && SERVER_IS_IN_CLUSTER(srv))
        {
                goto return_rc;
        }
        
        LOGIF(LD, (skygw_log_write(LOGFILE_DEBUG,
			"%lu [router_handle_state_switch] %s %s:%d in state %s",
			pthread_self(),
			STRDCBREASON(reason),
			srv->name,
			srv->port,
				STRSRVSTATUS(srv))));
	ses = dcb->session;
        CHK_SESSION(ses);

        rses = (ROUTER_CLIENT_SES *)dcb->session->router_session;
        CHK_CLIENT_RSES(rses);

        switch (reason) {
                case DCB_REASON_NOT_RESPONDING:
                        dcb->func.hangup(dcb);
                        break;
                        
                default:
                        break;
        }
        
return_rc:
        return rc;
}

void handle_error_reply_client(
	SESSION*           ses,
	ROUTER_CLIENT_SES* rses,
	DCB*               backend_dcb,
	GWBUF*             errmsg)
{
	session_state_t sesstate;
	DCB*            client_dcb;
	backend_ref_t*  bref;
	
	spinlock_acquire(&ses->ses_lock);
	sesstate = ses->state;
	client_dcb = ses->client;
	spinlock_release(&ses->ses_lock);

	/**
	 * If bref exists, mark it closed
	 */
	if ((bref = get_bref_from_dcb(rses, backend_dcb)) != NULL)
	{
		CHK_BACKEND_REF(bref);
		bref_clear_state(bref, BREF_IN_USE);
		bref_set_state(bref, BREF_CLOSED);
	}
	
	if (sesstate == SESSION_STATE_ROUTER_READY)
	{
		CHK_DCB(client_dcb);
		client_dcb->func.write(client_dcb, gwbuf_clone(errmsg));
	}
}

/**
 * Check if there is backend reference pointing at failed DCB, and reset its
 * flags. Then clear DCB's callback and finally : try to find replacement(s) 
 * for failed slave(s).
 * 
 * This must be called with router lock. 
 * 
 * @param inst		router instance
 * @param rses		router client session
 * @param dcb		failed DCB
 * @param errmsg	error message which is sent to client if it is waiting
 * 
 * @return true if there are enough backend connections to continue, false if not
 */
bool handle_error_new_connection(
	ROUTER_INSTANCE*   inst,
	ROUTER_CLIENT_SES* rses,
	DCB*               backend_dcb,
	GWBUF*             errmsg)
{
	SESSION*       ses;
	int            router_nservers;
	int            max_nslaves;
	int            max_slave_rlag;
	backend_ref_t* bref;
	bool           succp;
	
	ss_dassert(SPINLOCK_IS_LOCKED(&rses->rses_lock));
	
	ses = backend_dcb->session;
	CHK_SESSION(ses);
	
	/**
	 * If bref == NULL it has been replaced already with another one.
	 */
	if ((bref = get_bref_from_dcb(rses, backend_dcb)) == NULL)
	{
		succp = true;
		goto return_succp;
	}
	CHK_BACKEND_REF(bref);
	
	/** 
	 * If query was sent through the bref and it is waiting for reply from
	 * the backend server it is necessary to send an error to the client
	 * because it is waiting for reply.
	 */
	if (BREF_IS_WAITING_RESULT(bref))
	{
		DCB* client_dcb;
		client_dcb = ses->client;
		client_dcb->func.write(client_dcb, gwbuf_clone(errmsg));
		bref_clear_state(bref, BREF_WAITING_RESULT);
	}
	bref_clear_state(bref, BREF_IN_USE);
	bref_set_state(bref, BREF_CLOSED);

	/** 
	 * Error handler is already called for this DCB because
	 * it's not polling anymore. It can be assumed that
	 * it succeed because rses isn't closed.
	 */
	if (backend_dcb->state != DCB_STATE_POLLING)
	{
		succp = true;
		goto return_succp;
	}	
	/**
	 * Remove callback because this DCB won't be used 
	 * unless it is reconnected later, and then the callback
	 * is set again.
	 */
	dcb_remove_callback(backend_dcb, 
			DCB_REASON_NOT_RESPONDING, 
			&router_handle_state_switch, 
			(void *)bref);
	
	router_nservers = router_get_servercount(inst);
	max_nslaves     = rses_get_max_slavecount(rses, router_nservers);
	max_slave_rlag  = rses_get_max_replication_lag(rses);
	/** 
	 * Try to get replacement slave or at least the minimum 
	 * number of slave connections for router session.
	 */
	succp = select_connect_backend_servers(
			&rses->rses_master_ref,
			rses->rses_backend_ref,
			router_nservers,
			max_nslaves,
			max_slave_rlag,
			rses->rses_config.rw_slave_select_criteria,
			ses,
                        rses,
			inst);
	
return_succp:
	return succp;        
}


void print_error_packet(
        ROUTER_CLIENT_SES* rses, 
        GWBUF*             buf, 
        DCB*               dcb)
{
#if defined(SS_DEBUG)
        if (GWBUF_IS_TYPE_MYSQL(buf))
        {
                while (gwbuf_length(buf) > 0)
                {
                        /** 
                         * This works with MySQL protocol only ! 
                         * Protocol specific packet print functions would be nice.
                         */
                        uint8_t* ptr = GWBUF_DATA(buf);
                        size_t   len = MYSQL_GET_PACKET_LEN(ptr);
                        
                        if (MYSQL_GET_COMMAND(ptr) == 0xff)
                        {
                                SERVER*        srv = NULL;
                                backend_ref_t* bref = rses->rses_backend_ref;
                                int            i;
                                char*          bufstr;
                                
                                for (i=0; i<rses->rses_nbackends; i++)
                                {
                                        if (bref[i].bref_dcb == dcb)
                                        {
                                                srv = bref[i].bref_backend->backend_server;
                                        }
                                }
                                ss_dassert(srv != NULL);
                                char* str = (char*)&ptr[7]; 
                                bufstr = strndup(str, len-3);
                                
                                LOGIF(LE, (skygw_log_write_flush(
                                        LOGFILE_ERROR,
                                        "Error : Backend server %s:%d responded with "
                                        "error : %s",
                                        srv->name,
                                        srv->port,
                                        bufstr)));                
                                free(bufstr);
                        }
                        buf = gwbuf_consume(buf, len+4);
                }
        }
        else
        {
                while ((buf = gwbuf_consume(buf, GWBUF_LENGTH(buf))) != NULL);
        }
#endif /*< SS_DEBUG */
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

