#include <sescmd.h>
#include <strings.h>

SCMD* sescmd_allocate();
void sescmd_free(SCMD*);

/**
 * Allocate a new session command list.
 * @return Pointer to the session command list or NULL if an error occurred.
 */
SCMDLIST* sescmdlist_allocate()
{
    SCMDLIST* list;
    
    if((list = calloc(1,sizeof(SCMDLIST))) == NULL)
    {
        skygw_log_write(LOGFILE_ERROR,"Error : Memory allocation failed.");
        return NULL;
    }
    
    spinlock_init(&list->lock);

    list->semantics.reply_on = SRES_FIRST;
    list->semantics.must_reply = SNUM_ONE;
    list->semantics.on_error = SERR_DROP;

    /** Don't set a maximum length on the list */
    list->properties.max_len = 0;
    list->properties.on_mlen_err = DROP_FIRST;
    return list;
}

/**
 * Allocates a new session command.
 * @return Pointer to the newly allocated session command or NULL if an error occurred.
 */
SCMD* sescmd_allocate()
{
SCMD* cmd;

   if((cmd = calloc(1,sizeof(SCMD))) == NULL)
   {
       skygw_log_write(LOGFILE_ERROR,"Error : Memory allocation failed at sescmd_add_command.");
       return NULL;
   }

   spinlock_init(&cmd->lock);
   return cmd;
}

/**
 * Free a session command. This frees the associated GWBUF and the session
 * command itself.
 * @param cmd Session command to free
 */
void sescmd_free(SCMD* cmd)
{
    gwbuf_free(cmd->buffer);
    free(cmd);
}

/**
 * Free the session command list. This frees all commands and cursors associated
 * with this list.
 * @param list Session command list to free
 */
void sescmdlist_free(SCMDLIST*  list)
{
    SCMDCURSOR* cursor;
    SCMD* cmd;
    
    spinlock_acquire(&list->lock);
    cursor = list->cursors;
    cmd = list->first;
    list->cursors = NULL;
    list->first = NULL;
    list->last = NULL;
    spinlock_release(&list->lock);
    
    while(cmd)
    {
        SCMD* tmp = cmd;
        cmd = cmd->next;
        sescmd_free(tmp);
    }
    
    while(cursor)
    {
        SCMDCURSOR* tmp = cursor;
        cursor = cursor->next;
        free(tmp);
    }
    
    free(list);
}

/**
 * Add a command to the list of session commands. This allocates a 
 * new SCMD structure that contains all the information the client side needs 
 * about this command.
 * @param scmdlist Session command list
 * @param buf Buffer with the session command to add
 * @return True if adding the command was successful. False on all errors.
 */
bool sescmdlist_add_command (SCMDLIST* scmdlist, GWBUF* buf)
{
   SCMD* cmd;
   
   if((cmd = sescmd_allocate()) == NULL)
   {
       skygw_log_write(LOGFILE_ERROR,"Error : Memory allocation failed at sescmd_add_command.");
       return false;
   }
   
   cmd->buffer = gwbuf_clone(buf);
   cmd->packet_type = *((unsigned char*)buf->start + 4);
   cmd->reply_sent = false;
   
   if(scmdlist->first == NULL)
   {
       scmdlist->first = cmd;
       scmdlist->last = cmd;
   }
   else
   {
       scmdlist->last->next = cmd;
       scmdlist->last = cmd;
   }
   
   return true;
}

/**
 * Get the session command cursor associated with this DCB.
 * @param scmdlist Session command list
 * @param dcb DCB whose cursor we are looking for
 * @return Pointer to the cursor associated with this DCB or NULL if it was not found.
 */
SCMDCURSOR* get_cursor(SCMDLIST* scmdlist, DCB* dcb)
{
    SCMDCURSOR* cursor = scmdlist->cursors;
    SCMDCURSOR* rval = NULL;

    spinlock_acquire(&scmdlist->lock);

    while(cursor)
    {
        if(cursor->backend_dcb == dcb)
        {
            rval = cursor;
	    break;
        }
        cursor = cursor->next;
    }
    spinlock_release(&scmdlist->lock);

    return rval;
}

/**
 * Get the GWBUF of the current command.
 * @param cursor Cursor to use
 * @return Pointer to the active command buffer or NULL if no session command is active
 */
GWBUF* sescmd_cursor_get_command(SCMDCURSOR* cursor)
{
    if(cursor->scmd_cur_cmd == NULL)
    {
        return NULL;
    }
    return cursor->scmd_cur_cmd->buffer;
}

/**
 * Check if the cursor is active.
 * @param cursor Cursor to check
 * @return True if the cursor is active. False if it is not.
 */
bool
sescmd_cursor_is_active(SCMDCURSOR* cursor)
{
    bool rval;
    spinlock_acquire(&cursor->lock);
    rval = cursor->scmd_cur_active;
    spinlock_release(&cursor->lock);
    return rval;
}

/**
 * Change the active state of the cursor
 * @param cursor Cursor to modify
 * @param value Activate or deactivate the cursor
 */
void
sescmd_cursor_set_active(SCMDCURSOR* cursor, bool value)
{
    spinlock_acquire(&cursor->lock);
    cursor->scmd_cur_active = value;
    spinlock_release(&cursor->lock);
}

/**
 * Check if the session command cursor associated with this backend DCB is already
 * executing session commands. If this is true, the backend server will automatically
 * repeat all the session commands after which it will go into inactive state.
 * @param list Session command list
 * @param dcb Backend server DCB
 * @return True if the backend server is already executing session commands and
 * false if it is inactive 
 */
bool sescmdlist_is_active(SCMDLIST* list, DCB* dcb)
{
    SCMDCURSOR* cursor = get_cursor(list,dcb);
    
    if(cursor == NULL)
	return false;
    
    return sescmd_cursor_is_active(cursor);
}

/**
 * See if the cursor has pending commands.
 * @param cursor Cursor to inspect
 * @return True if the cursor has pending commands. False if it has reached the end of the list.
 */
bool sescmd_has_next(SCMDLIST* list, DCB* dcb)
{
    SCMD* cmd;
    SCMDCURSOR* cursor;
    bool replied;
    
    cursor = get_cursor(list,dcb);
    
    if(cursor == NULL)
	return false;
    
    if(list->first == NULL)
    {
	/** No commands to execute */
	return false;
    }
    
    if(cursor->scmd_cur_cmd == NULL)
    {
        /** This is the first time this cursor is activated*/
        
        return true;
    }
    
    spinlock_acquire(&cursor->lock);
    
    cmd = cursor->scmd_cur_cmd ? cursor->scmd_cur_cmd->next : NULL;
    replied = cursor->replied_to;
    spinlock_release(&cursor->lock);
    if(cmd != NULL)
    {
        /** There are more commands to execute*/    
        
        return true;
    }
    
    if(replied == false)
    {
        /** The current command hasn't been replied to */
        return true;
    }
    
    /** This cursor has reached the end of the list*/
    
    return false;
}


/**
 * Move the cursor forward if it has not yet reached the end of the list.
 * @param list Session command list
 * @param dcb Backend DCB
 * @return Pointer to the next GWBUF containing the next command in the list or 
 * NULL if there are no commands to execute.
 */
GWBUF* sescmd_get_next(SCMDLIST* list, DCB* dcb)
{
    GWBUF* rval = NULL;
    SCMDCURSOR* cursor = get_cursor(list,dcb);
    
    if(cursor == NULL)
	return NULL;
    
    spinlock_acquire(&cursor->lock);
    
      if(cursor->scmd_list->first == NULL)
      {
	  /** No commands to execute */
	      rval = NULL;
	      goto retblock;
      }
    
    if(cursor->scmd_cur_cmd == NULL)
    {
        /** This is the first time this cursor is advanced */
        
        cursor->scmd_cur_cmd = cursor->scmd_list->first;
        rval = sescmd_cursor_get_command(cursor);
        goto retblock;
    }
    
    if(cursor->scmd_cur_cmd->next && 
       cursor->replied_to)
    {
        /** There are pending commands and the current one received a response */    
        
        cursor->scmd_cur_cmd = cursor->scmd_cur_cmd->next;
        rval = sescmd_cursor_get_command(cursor);
        goto retblock;
    }
    
    if(cursor->replied_to == false)
    {
        /** The current command is still active.
	 * Question: return NULL instead and wait for a response?
	 */

        rval = sescmd_cursor_get_command(cursor);
    }

    retblock:
    
    spinlock_release(&cursor->lock);
    
    return rval;
}

/**
 * Check if the cursor is waiting a result. If the cursor is waiting for a result,
 * don't send additional commands until a reply has been received.
 * @param cursor Cursor to inspect
 * @return True if the cursor is waiting for a result. False if all sent commands
 * have been replied.
 */
bool cursor_waiting_result(SCMDCURSOR* cursor)
{
    if(!cursor->replied_to &&
       cursor->scmd_cur_active)
	return true;

    return false;
}

/**
 * Execute a pending session command in the backend server.
 * @param dcb Backend DCB where the command is executed
 * @param buffer GWBUF containing the session command
 * @return True if execution was successful or false if the write to the backend DCB failed.
 */
bool
sescmdlist_execute(SCMDLIST* list, DCB* backend_dcb)
{
	DCB* dcb = backend_dcb;
	bool succp = true;
	int rc = 0;
	unsigned char packet_type;
	if(dcb == NULL || list == NULL)
	    return false;
	CHK_DCB(dcb);
	SCMDCURSOR* cursor = get_cursor(list,backend_dcb);
	GWBUF* buffer = sescmd_get_next(list,backend_dcb);

	if(cursor == NULL)
	{
	    return false;
	}

	if(buffer == NULL)
	{
	    /** No more commands to execute */
	    sescmd_cursor_set_active(cursor,false);
	    return true;
	}

	if(cursor_waiting_result(cursor))
	    return true;

	packet_type = MYSQL_GET_COMMAND(((unsigned char*)buffer->start));
	

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
					dcb->fd,
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
 *
 * @param list
 * @return
 */
bool sescmdlist_execute_all(SCMDLIST* list)
{
   SCMDCURSOR* cursor = list->cursors;
   while(cursor)
   {
       sescmdlist_execute(list,cursor->backend_dcb);
       cursor = cursor->next;
   }
}

/**
 * See if the requirements to reply to the client are met.
 * @param list Session command list
 * @param dcb Backend server DCB
 * @return True if the packet should be returned to the client, otherwise false.
 */
bool check_reply_semantics(SCMDLIST* list, DCB* dcb)
{
    DCB* master = list->semantics.master_dcb;
    SCMDCURSOR* scur = get_cursor(list, dcb);
    SCMD* cmd;

    if(scur == NULL)
	return false;

    cmd =  scur->scmd_cur_cmd;

    if(master)
    {
	/** The Master server has replied, this should be returned to the client */
	if(dcb == master)
	{
	    return true;
	}
	else
	{
	    return false;
	}
    }

    if(scur->scmd_list->semantics.reply_on == SRES_FIRST ||
       (scur->scmd_list->semantics.reply_on == SRES_LAST &&
	cmd->n_replied >= scur->scmd_list->n_cursors) ||
       (scur->scmd_list->semantics.reply_on == SRES_MIN &&
	cmd->n_replied >= scur->scmd_list->semantics.min_nreplies))
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
        SCMDLIST* list,
        DCB* dcb,                            
        GWBUF** rbuf)
{
    
        SCMD*  cmd;
        SCMDCURSOR* scur;
        DCB* master;
	GWBUF* replybuf;
	bool rval = true;
	unsigned char command;
	if(rbuf == NULL)
	    return false;

	replybuf = *rbuf;
        scur = get_cursor(list,dcb);
        cmd =  scur->scmd_cur_cmd;
	master = list->semantics.master_dcb;
        
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
			free(replybuf);
		    *rbuf = NULL;
		    rval = false;
		}
	    }
	    /** Response is in the buffer and it will be sent to client. */
	    else
	    {
		/** Mark the session command as replied */
		atomic_add(&cmd->n_replied,1);

		if(check_reply_semantics(list,dcb))
		{
		    cmd->reply_type = command;
		    cmd->reply_sent = true;
		    break;
		}
	    }


	    /** Get the next packet if one exists */
	    if(*rbuf)
	    {
		replybuf = gwbuf_consume(
			replybuf,
			MYSQL_GET_PACKET_LEN(((unsigned char*)replybuf->start)));
	    }
        }
        
        return rval;
}

/**
 * Add a DCB to the session command list. This allocates a new session command
 * cursor for this DCB and starts the execution of pending commands.
 * @param list Session command list
 * @param dcb DCB to add
 * @return True if adding the DCB was successful or the DCB was already in the list. 
 * False on all errors.
 */
bool sescmdlist_add_dcb (SCMDLIST* scmdlist, DCB* dcb)
{
    SCMDLIST* list = scmdlist;
    SCMDCURSOR* cursor;
    
    if(get_cursor(scmdlist,dcb) != NULL)
    {
	return true;
    }
    
    if((cursor = calloc(1,sizeof(SCMDCURSOR))) == NULL)
    {
        skygw_log_write(LOGFILE_ERROR,"Error : Memory allocation failed.");
        return false;
    }
    
    spinlock_init(&cursor->lock);
    cursor->backend_dcb = dcb;
    cursor->scmd_list = list;
    cursor->scmd_cur_cmd = list->first;
    cursor->next = list->cursors;
    list->cursors = cursor;
    atomic_add(&list->n_cursors,1);
    
    return true;
}

/**
 * Remove a DCB from the session command list.
 * @param list Session command list
 * @param dcb DCB to remove
 * @return True if removing the DCB was successful. False on all errors.
 */
bool sescmdlist_remove_dcb (SCMDLIST* scmdlist, DCB* dcb)
{
    SCMDLIST* list = scmdlist;
    SCMDCURSOR *cursor, *tmp;
    
    if((cursor = get_cursor(scmdlist,dcb)) == NULL)
    {
	return false;
    }
    
    spinlock_acquire(&cursor->lock);
    cursor->scmd_cur_active = false;
    cursor->scmd_cur_cmd = NULL;
    spinlock_release(&cursor->lock);
    
    spinlock_acquire(&list->lock);
    
    tmp = list->cursors;
    
    if(tmp == cursor)
    {
        list->cursors = cursor->next;
    }
    else
    {
        while(tmp && tmp->next != cursor)
            tmp = tmp->next;
        
        if(tmp)
        {
            tmp->next = cursor->next;
        }
        
    }
    spinlock_release(&list->lock);
    atomic_add(&list->n_cursors,-1);
    
    free(cursor);
    
    return true;
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