#include <sescmd.h>
#include <strings.h>

void sescmd_cursor_set_active(SCMDCURSOR* cursor, bool value);
bool cursor_waiting_result(SCMDCURSOR* cursor);

/**
 * Get the GWBUF of the current command.
 * @param cursor Cursor to use
 * @return Pointer to the active command buffer or NULL if no session command is active
 */
GWBUF* sescmd_cursor_get_command(SCMDCURSOR* cursor)
{
    if(cursor->current_cmd == NULL)
    {
        return NULL;
    }
    return cursor->current_cmd->buffer;
}

/**
 * Execute a pending session command in the backend server.
 * @param dcb Backend DCB where the command is executed
 * @param buffer GWBUF containing the session command
 * @return True if execution was successful or false if the write to the backend DCB failed.
 */
bool
sescmdlist_execute(SCMDCURSOR* cursor)
{
	GWBUF* buffer;
	DCB* dcb;
	bool succp = true;
	int rc = 0;
	unsigned char packet_type;

	if(cursor == NULL)
	{
	    return false;
	}

	dcb = cursor->backend_dcb;
	buffer = sescmd_get_next(cursor);

	if(buffer == NULL)
	{
	    /** No more commands to execute */
	    sescmd_cursor_set_active(cursor,false);
	    return true;
	}

	if(cursor_waiting_result(cursor))
	    return true;

	packet_type = *((unsigned char*)buffer->start + 4);
	

#if defined(SS_DEBUG)
		{
			GWBUF* tmpbuf = gwbuf_clone(buffer);
			uint8_t* ptr = GWBUF_DATA(tmpbuf);
			unsigned char cmd = MYSQL_GET_COMMAND(ptr);

			skygw_log_write(
					LOGFILE_DEBUG,
					"%lu [execute_sescmd_in_backend] Just before write, fd "
					"%d : cmd %s.",
					pthread_self(),
					cursor->backend_dcb->fd,
					STRPACKETTYPE(cmd));
			gwbuf_free(tmpbuf);
		}
#endif /*< SS_DEBUG */

		switch(packet_type)
		{
		case MYSQL_COM_CHANGE_USER:
			/** This makes it possible to handle replies correctly */
			gwbuf_set_type(buffer, GWBUF_TYPE_SESCMD);
			rc = dcb->func.auth(
					    dcb,
					    NULL,
					    dcb->session,
					    gwbuf_clone(buffer));
			break;

		case MYSQL_COM_INIT_DB:
		{
			/** Record database name and store to session. */
			GWBUF* tmpbuf;
			MYSQL_session* data;
			unsigned int qlen;
			
			data = dcb->session->data;
			tmpbuf = buffer;
			qlen = MYSQL_GET_PACKET_LEN((unsigned char*) tmpbuf->start);
			memset(data->db, 0, MYSQL_DATABASE_MAXLEN + 1);
			if(qlen > 0 && qlen < MYSQL_DATABASE_MAXLEN + 1)
				strncpy(data->db, tmpbuf->start + 5, qlen - 1);
		}
			/** Fallthrough */
		case MYSQL_COM_QUERY:
		default:
			/** 
			 * Mark session command buffer, it triggers writing 
			 * MySQL command to protocol
			 */
			gwbuf_set_type(buffer, GWBUF_TYPE_SESCMD);
			rc = dcb->func.write(
					     dcb,
					     gwbuf_clone(buffer));
			break;
		}

		if(rc == 1)
		{
			succp = true;
		}
		else
		{
			succp = false;
		}
		
		cursor->replied_to = false;
		sescmd_cursor_set_active(cursor,true);

	return succp;
}

/**
 * See if the requirements to reply to the client are met.
 * @param list Session command list
 * @param dcb Backend server DCB
 * @return True if the packet should be returned to the client, otherwise false.
 */
bool check_reply_semantics(SCMDCURSOR* cursor)
{
    SCMDLIST* list = cursor->scmd_list;
    DCB* master = list->semantics.master_dcb;
    SCMD* cmd;
    sescmd_return_response_t respond_on;
    if(cursor == NULL || cursor->current_cmd == NULL)
	return false;

    cmd =  cursor->current_cmd;
    respond_on = cursor->scmd_list->semantics.reply_on;
    if(respond_on == SRES_DCB && master)
    {
	/** The Master server has replied, this should be returned to the client */
	if(cursor->backend_dcb == master)
	{
	    return true;
	}
	else
	{
	    return false;
	}
    }

    if(respond_on == SRES_FIRST ||
       (respond_on == SRES_LAST &&
	cmd->n_replied >= cursor->scmd_list->n_cursors) ||
       (respond_on == SRES_MIN &&
	cmd->n_replied >= cursor->scmd_list->semantics.min_nreplies))
    {
	return true;
    }
    
    return false;
}

/**
 * All cases where backend message starts at least with one response to session
 * command are handled here.
 * Read session commands from session command list. If command is already replied,
 * discard packet. Else send reply to client if the semantics of the list match. 
 * In both cases move cursor forward until all session command replies are handled. 
 * @param list Session command list
 * @param dcb Backend DCB
 * @param rbuf Pointer to a  pointer of a GWBUF containing the reply from the backend server
 * @return True if the reply was processed successfully and false if the response
 * from this backend DCB was different from the others. 
 */
bool sescmdlist_process_replies(
        SCMDCURSOR* scur,
        GWBUF** rbuf)
{

	SCMDLIST* list;
        SCMD*  cmd;
        DCB* master;
	DCB* dcb;
	GWBUF* replybuf;
	bool rval = true;
	unsigned char command;

	if(rbuf == NULL || *rbuf == NULL)
	    return false;

	if(scur == NULL || scur->scmd_list == NULL)
	    return false;

	list = scur->scmd_list;
	replybuf = *rbuf;
        cmd =  scur->current_cmd;
	master = list->semantics.master_dcb;
        dcb = scur->backend_dcb;
        CHK_GWBUF(replybuf);
        
        /** 
         * Walk through packets in the message and the list of session 
         * commands. 
         */
        while (cmd != NULL && replybuf != NULL && rval != false)
        {

	    command = MYSQL_GET_COMMAND(((unsigned char*)replybuf->start));

	    /** Set response status received */
	    scur->replied_to = true;

	    /** Faster backend has already responded to client : discard */
	    if (cmd->reply_sent)
	    {
		CHK_GWBUF(replybuf);

		/** This might be a bit too optimistic, there could be
		 * situations where we still want to return a packet to
		 * the client even though the first */
		*rbuf = NULL;
		replybuf = gwbuf_consume(replybuf, GWBUF_LENGTH(replybuf));
		
		while (replybuf && !GWBUF_IS_TYPE_RESPONSE_END(replybuf))
		{
		    replybuf = gwbuf_consume(replybuf, GWBUF_LENGTH(replybuf));
		}

		if(cmd->reply_type != command)
		{
		    skygw_log_write(LOGFILE_TRACE,"Server '%s:%u' Returned: %x instead of %x",
			     dcb->server->name,
			     dcb->server->port,
			     command,
			     cmd->reply_type);
		    if(replybuf)
		    {
			free(replybuf);
			replybuf = NULL;
		    }
		    *rbuf = NULL;
		    rval = false;
		}
	    }
	    /** Response is in the buffer and it will be sent to client. */
	    else
	    {
		/** Mark the session command as replied */
		atomic_add(&cmd->n_replied,1);

		if(check_reply_semantics(scur))
		{
		    cmd->reply_type = command;
		    cmd->reply_sent = true;
		    break;
		}
		else
		{
		    *rbuf = NULL;
		    replybuf = gwbuf_consume(replybuf, GWBUF_LENGTH(replybuf));

		    while (replybuf && !GWBUF_IS_TYPE_RESPONSE_END(replybuf))
		    {
			replybuf = gwbuf_consume(replybuf, GWBUF_LENGTH(replybuf));
		    }
		}
	    }


	    /** Get the next packet if one exists */
	    if(*rbuf)
	    {
		replybuf = gwbuf_consume(
			replybuf,
			gwbuf_length(replybuf));
	    }
        }
        
        return rval;
}

/**
 * To be implemented...
 * @param list
 * @param dcb
 * @return 
 */
bool sescmd_handle_failure(SCMDLIST* list, DCB* dcb)
{
    return false;
}
