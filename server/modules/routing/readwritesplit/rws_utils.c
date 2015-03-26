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

/** Compare number of connections from this router in backend servers */
int bref_cmp_router_conn(
        const void* bref1,
        const void* bref2)
{
        BACKEND* b1 = ((backend_ref_t *)bref1)->bref_backend;
        BACKEND* b2 = ((backend_ref_t *)bref2)->bref_backend;

        return ((1000 * b1->backend_conn_count) / b1->weight)
			  - ((1000 * b2->backend_conn_count) / b2->weight);
}

/** Compare number of global connections in backend servers */
int bref_cmp_global_conn(
        const void* bref1,
        const void* bref2)
{
        BACKEND* b1 = ((backend_ref_t *)bref1)->bref_backend;
        BACKEND* b2 = ((backend_ref_t *)bref2)->bref_backend;
        
        return ((1000 * b1->backend_server->stats.n_current) / b1->weight)
		  - ((1000 * b2->backend_server->stats.n_current) / b2->weight);
}


/** Compare replication lag between backend servers */
int bref_cmp_behind_master(
        const void* bref1, 
        const void* bref2)
{
        BACKEND* b1 = ((backend_ref_t *)bref1)->bref_backend;
        BACKEND* b2 = ((backend_ref_t *)bref2)->bref_backend;
        
        return ((b1->backend_server->rlag < b2->backend_server->rlag) ? -1 :
        ((b1->backend_server->rlag > b2->backend_server->rlag) ? 1 : 0));
}

/** Compare number of current operations in backend servers */
int bref_cmp_current_load(
        const void* bref1,
        const void* bref2)
{
        SERVER*  s1 = ((backend_ref_t *)bref1)->bref_backend->backend_server;
        SERVER*  s2 = ((backend_ref_t *)bref2)->bref_backend->backend_server;
        BACKEND* b1 = ((backend_ref_t *)bref1)->bref_backend;
        BACKEND* b2 = ((backend_ref_t *)bref2)->bref_backend;
        
        return ((1000 * s1->stats.n_current_ops) - b1->weight)
			- ((1000 * s2->stats.n_current_ops) - b2->weight);
}
        
void bref_clear_state(
        backend_ref_t* bref,
        bref_state_t   state)
{
        if (state != BREF_WAITING_RESULT)
        {
                bref->bref_state &= ~state;
        }
        else
        {
                int prev1;
                int prev2;
                
                /** Decrease waiter count */
                prev1 = atomic_add(&bref->bref_num_result_wait, -1);
                
                if (prev1 <= 0) {
                        atomic_add(&bref->bref_num_result_wait, 1);
                }
                else
                {
                        /** Decrease global operation count */
                        prev2 = atomic_add(
                                &bref->bref_backend->backend_server->stats.n_current_ops, -1);
                        ss_dassert(prev2 > 0);
                }       
        }
}

void bref_set_state(        
        backend_ref_t* bref,
        bref_state_t   state)
{
        if (state != BREF_WAITING_RESULT)
        {
                bref->bref_state |= state;
        }
        else
        {
                int prev1;
                int prev2;
                
                /** Increase waiter count */
                prev1 = atomic_add(&bref->bref_num_result_wait, 1);
                ss_dassert(prev1 >= 0);
                
                /** Increase global operation count */
                prev2 = atomic_add(
                        &bref->bref_backend->backend_server->stats.n_current_ops, 1);
                ss_dassert(prev2 >= 0);                
        }
}

void tracelog_routed_query(
        ROUTER_CLIENT_SES* rses,
        char*              funcname,
        backend_ref_t*     bref,
        GWBUF*             buf)
{
        uint8_t*       packet = GWBUF_DATA(buf);
        unsigned char  packet_type = packet[4];
        size_t         len;
        size_t         buflen = GWBUF_LENGTH(buf);
        char*          querystr;
        char*          startpos = (char *)&packet[5];
        BACKEND*       b;
        backend_type_t be_type;
        DCB*           dcb;
        
        CHK_BACKEND_REF(bref);
        b = bref->bref_backend;
        CHK_BACKEND(b);
        dcb = bref->bref_dcb;
        CHK_DCB(dcb);
        
        be_type = BACKEND_TYPE(b);

        if (GWBUF_IS_TYPE_MYSQL(buf))
        {
                len  = packet[0];
                len += 256*packet[1];
                len += 256*256*packet[2];
                
                if (packet_type == '\x03') 
                {
                        querystr = (char *)malloc(len);
                        memcpy(querystr, startpos, len-1);
                        querystr[len-1] = '\0';
                        LOGIF(LD, (skygw_log_write_flush(
                                LOGFILE_DEBUG,
                                "%lu [%s] %d bytes long buf, \"%s\" -> %s:%d %s dcb %p",
                                pthread_self(),
                                funcname,
                                buflen,
                                querystr,
                                b->backend_server->name,
                                b->backend_server->port, 
                                STRBETYPE(be_type),
                                dcb)));
                        free(querystr);
                }
                else if (packet_type == '\x22' || 
                        packet_type == 0x22 || 
                        packet_type == '\x26' || 
                        packet_type == 0x26 ||
                        true)
                {
                        querystr = (char *)malloc(len);
                        memcpy(querystr, startpos, len-1);
                        querystr[len-1] = '\0';
                        LOGIF(LD, (skygw_log_write_flush(
                                LOGFILE_DEBUG,
                                "%lu [%s] %d bytes long buf, \"%s\" -> %s:%d %s dcb %p",
                                pthread_self(),
                                funcname,
                                buflen,
                                querystr,
                                b->backend_server->name,
                                b->backend_server->port, 
                                STRBETYPE(be_type),
                                dcb)));
                        free(querystr);                        
                }
        }
        gwbuf_free(buf);
}


int router_get_servercount(
        ROUTER_INSTANCE* inst)
{
        int       router_nservers = 0;
        BACKEND** b = inst->servers;
        /** count servers */
        while (*(b++) != NULL) router_nservers++;
                                                                
        return router_nservers;
}

bool have_enough_servers(
        ROUTER_CLIENT_SES** p_rses,
        const int           min_nsrv,
        int                 router_nsrv,
        ROUTER_INSTANCE*    router)
{
        bool succp;
        
        /** With too few servers session is not created */
        if (router_nsrv < min_nsrv || 
                MAX((*p_rses)->rses_config.rw_max_slave_conn_count, 
                    (router_nsrv*(*p_rses)->rses_config.rw_max_slave_conn_percent)/100)
                        < min_nsrv)
        {
                if (router_nsrv < min_nsrv)
                {
                        LOGIF(LE, (skygw_log_write_flush(
                                LOGFILE_ERROR,
                                "Error : Unable to start %s service. There are "
                                "too few backend servers available. Found %d "
                                "when %d is required.",
                                router->service->name,
                                router_nsrv,
                                min_nsrv)));
                }
                else
                {
                        int pct = (*p_rses)->rses_config.rw_max_slave_conn_percent/100;
                        int nservers = router_nsrv*pct;
                        
                        if ((*p_rses)->rses_config.rw_max_slave_conn_count < min_nsrv)
                        {
                                LOGIF(LE, (skygw_log_write_flush(
                                        LOGFILE_ERROR,
                                        "Error : Unable to start %s service. There are "
                                        "too few backend servers configured in "
                                        "MaxScale.cnf. Found %d when %d is required.",
                                        router->service->name,
                                        (*p_rses)->rses_config.rw_max_slave_conn_count,
                                        min_nsrv)));
                        }
                        if (nservers < min_nsrv)
                        {
                            double dbgpct = ((double)min_nsrv/(double)router_nsrv)*100.0;
                            LOGIF(LE, (skygw_log_write_flush(
                                        LOGFILE_ERROR,
                                        "Error : Unable to start %s service. There are "
                                        "too few backend servers configured in "
                                        "MaxScale.cnf. Found %d%% when at least %.0f%% "
                                        "would be required.",
                                        router->service->name,
                                        (*p_rses)->rses_config.rw_max_slave_conn_percent,
                                        dbgpct)));
                        }
                }
                free(*p_rses);
                *p_rses = NULL;
                succp = false;
        }
        else
        {
                succp = true;
        }
        return succp;
}
/**
 * Finds out if there is a backend reference pointing at the DCB given as 
 * parameter. 
 * @param rses	router client session
 * @param dcb	DCB
 * 
 * @return backend reference pointer if succeed or NULL
 */
backend_ref_t* get_bref_from_dcb(
        ROUTER_CLIENT_SES* rses,
        DCB*               dcb)
{
        backend_ref_t* bref;
        int            i = 0;
        CHK_DCB(dcb);
        CHK_CLIENT_RSES(rses);
        
        bref = rses->rses_backend_ref;
        
        while (i<rses->rses_nbackends)
        {
                if (bref->bref_dcb == dcb)
                {
                        break;
                }
                bref++;
                i += 1;
        }
        
        if (i == rses->rses_nbackends)
        {
                bref = NULL;
        }
        return bref;
}

/********************************
 * This routine returns the root master server from MySQL replication tree
 * Get the root Master rule:
 *
 * find server with the lowest replication depth level
 * and the SERVER_MASTER bitval
 * Servers are checked even if they are in 'maintenance'
 *
 * @param	servers		The list of servers
 * @param	router_nservers	The number of servers
 * @return			The Master found
 *
 */
BACKEND *get_root_master(
	backend_ref_t *servers, 
	int            router_nservers) 
{
        int i = 0;
        BACKEND * master_host = NULL;

        for (i = 0; i< router_nservers; i++) 
	{
		BACKEND* b;
		
		if (servers[i].bref_backend == NULL)
		{
			continue;
		}
		
		b = servers[i].bref_backend;

		if ((b->backend_server->status & 
			(SERVER_MASTER|SERVER_MAINT)) == SERVER_MASTER) 
		{
			if (master_host == NULL || 
				(b->backend_server->depth < master_host->backend_server->depth))
			{
				master_host = b;
                        }
                }
        }
	return master_host;
}


/********************************
 * This routine returns the root master server from MySQL replication tree
 * Get the root Master rule:
 *
 * find server with the lowest replication depth level
 * and the SERVER_MASTER bitval
 * Servers are checked even if they are in 'maintenance'
 *
 * @param	rses pointer to router session
 * @return	pointer to backend reference of the root master or NULL
 *
 */
backend_ref_t* get_root_master_bref(
	ROUTER_CLIENT_SES* rses)
{
	backend_ref_t* bref;
	backend_ref_t* candidate_bref = NULL;
	int            i = 0;
	
	bref = rses->rses_backend_ref;
	
	while (i<rses->rses_nbackends)
	{
		if ((bref->bref_backend->backend_server->status &
			(SERVER_MASTER|SERVER_MAINT)) == SERVER_MASTER)
		{
			if (bref->bref_backend->backend_server->status & SERVER_MASTER)
			{
				if (candidate_bref == NULL ||
					(bref->bref_backend->backend_server->depth <
					candidate_bref->bref_backend->backend_server->depth))
				{
					candidate_bref = bref;
				}
			}
		}
		bref++;
		i += 1;
	}
	if (candidate_bref == NULL)
	{
		LOGIF(LE, (skygw_log_write_flush(
			LOGFILE_ERROR,
			"Error : Could not find master among the backend "
			"servers. Previous master's state : %s",
			STRSRVSTATUS(BREFSRV(rses->rses_master_ref)))));	
	}
	return candidate_bref;
}


int hashkeyfun(
		void* key)
{
  if(key == NULL){
    return 0;
  }
  unsigned int hash = 0,c = 0;
  char* ptr = (char*)key;
  while((c = *ptr++)){
    hash = c + (hash << 6) + (hash << 16) - hash;
  }
  return hash;
}

int hashcmpfun(
	void* v1,
	void* v2)
{
  char* i1 = (char*) v1;
  char* i2 = (char*) v2;

  return strcmp(i1,i2);
}

void* hstrdup(void* fval)
{
  char* str = (char*)fval;
  return strdup(str);
}


void* hfree(void* fval)
{
  free (fval);
  return NULL;
}
