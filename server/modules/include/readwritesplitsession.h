#ifndef _RWSPLITROUTERSESSION_H
#define _RWSPLITROUTERSESSION_H
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

/**
 * @file router.h - The read write split router module heder file
 *
 * @verbatim
 * Revision History
 *
 * See GitHub https://github.com/skysql/MaxScale
 *
 * @endverbatim
 */
#include <readwritesplit2.h>

struct router_instance;
struct router_client_session;

typedef enum rses_property_type_t {
        RSES_PROP_TYPE_UNDEFINED=-1,
        RSES_PROP_TYPE_SESCMD=0,
        RSES_PROP_TYPE_FIRST = RSES_PROP_TYPE_SESCMD,
        RSES_PROP_TYPE_TMPTABLES,
        RSES_PROP_TYPE_LAST=RSES_PROP_TYPE_TMPTABLES,
	RSES_PROP_TYPE_COUNT=RSES_PROP_TYPE_LAST+1
} rses_property_type_t;

typedef enum bref_state {
        BREF_IN_USE           = 0x01,
        BREF_WAITING_RESULT   = 0x02, /*< for session commands only */
        BREF_QUERY_ACTIVE     = 0x04, /*< for other queries */
        BREF_CLOSED           = 0x08
} bref_state_t;

typedef struct router_client_session  ROUTER_CLIENT_SES;

/**
 * Property structure
 */
typedef struct rses_property_st {
#if defined(SS_DEBUG)
        skygw_chk_t          rses_prop_chk_top;
#endif
        ROUTER_CLIENT_SES*   rses_prop_rsession; /*< parent router session */
        int                  rses_prop_refcount;
        rses_property_type_t rses_prop_type;
        union rses_prop_data {
		HASHTABLE*	temp_tables;
        } rses_prop_data;
        struct rses_property_st*     rses_prop_next; /*< next property of same type */
#if defined(SS_DEBUG)
        skygw_chk_t          rses_prop_chk_tail;
#endif
}rses_property_t;

/**
 * Reference to BACKEND.
 * 
 * Owned by router client session.
 */
typedef struct backend_ref_st {
#if defined(SS_DEBUG)
        skygw_chk_t     bref_chk_top;
#endif
        BACKEND*        bref_backend;
        DCB*            bref_dcb;
        bref_state_t    bref_state;
        int             bref_num_result_wait;
	GWBUF*          bref_pending_cmd; /*< For stmt which can't be routed due active sescmd execution */
#if defined(SS_DEBUG)
        skygw_chk_t     bref_chk_tail;
#endif
} backend_ref_t;

   
/**
 * The client session structure used within this router.
 */
struct router_client_session {
#if defined(SS_DEBUG)
        skygw_chk_t      rses_chk_top;
#endif
        SPINLOCK         rses_lock;      /*< protects rses_deleted                 */
        ROUTER           *instance;      /*< The router instance for which this is a session */
        int              rses_versno;    /*< even = no active update, else odd. not used 4/14 */
        bool             rses_closed;    /*< true when closeSession is called      */
	/** Properties listed by their type */
	rses_property_t* rses_properties[RSES_PROP_TYPE_COUNT];
        backend_ref_t*   rses_master_ref;
        backend_ref_t*   rses_backend_ref; /*< Pointer to backend reference array */
        rwsplit_config_t rses_config;    /*< copied config info from router instance */
        int              rses_nbackends;
        int              rses_capabilities; /*< input type, for example */
        bool             rses_autocommit_enabled;
        bool             rses_transaction_active;
        SCMDLIST*        rses_sescmd_list; /*< Session commands */
	struct router_instance	 *router;	/*< The router instance */
        struct router_client_session* next;
#if defined(SS_DEBUG)
        skygw_chk_t      rses_chk_tail;
#endif
} ROUTER_SESSION;
    
#endif /*< _RWSPLITROUTERSESSION_H */
