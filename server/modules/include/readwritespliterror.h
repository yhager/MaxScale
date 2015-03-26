#ifndef RWSPLIT_ERROR_HG
#define RWSPLIT_ERROR_HG

static  void           handleError(
        ROUTER*        instance,
        void*          router_session,
        GWBUF*         errmsgbuf,
        DCB*           backend_dcb,
        error_action_t action,
        bool*          succp);

int  router_handle_state_switch(DCB* dcb, DCB_REASON reason, void* data);
bool handle_error_new_connection(
        ROUTER_INSTANCE*   inst,
        ROUTER_CLIENT_SES* rses,
        DCB*               backend_dcb,
        GWBUF*             errmsg);
void handle_error_reply_client(
		SESSION*           ses, 
		ROUTER_CLIENT_SES* rses, 
		DCB*               backend_dcb,
		GWBUF*             errmsg);
void print_error_packet(ROUTER_CLIENT_SES* rses, GWBUF* buf, DCB* dcb);
#endif
