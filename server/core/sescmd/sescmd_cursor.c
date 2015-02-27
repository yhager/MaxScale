#include <sescmd.h>
#include <strings.h>

/**
 * Get the session command cursor associated with this DCB.
 * @param scmdlist Session command list
 * @param dcb DCB whose cursor we are looking for
 * @return Pointer to the cursor associated with this DCB or NULL if it was not found.
 */
SCMDCURSOR* get_cursor(SCMDLIST* scmdlist, DCB* dcb)
{
    return dcb->cursor;
}

/**
 * Check if the cursor is active.
 * @param cursor Cursor to check
 * @return True if the cursor is active. False if it is not.
 */
bool
sescmd_cursor_is_active(SCMDCURSOR* cursor)
{
    return cursor->scmd_cur_active;
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
 * Move the cursor forward if it has not yet reached the end of the list.
 * @param list Session command list
 * @param dcb Backend DCB
 * @return Pointer to the next GWBUF containing the next command in the list or 
 * NULL if there are no commands to execute.
 */
GWBUF* sescmd_get_next(SCMDCURSOR* cursor)
{
    GWBUF* rval = NULL;
    
    if(cursor == NULL)
	return NULL;
    
    spinlock_acquire(&cursor->lock);
    
      if(cursor->scmd_list->first == NULL)
      {
	  /** No commands to execute */
	      rval = NULL;
	      goto retblock;
      }
    
    if(cursor->current_cmd == NULL)
    {
        /** This is the first time this cursor is advanced */
        
        cursor->current_cmd = cursor->scmd_list->first;
        rval = cursor->current_cmd->buffer;
        goto retblock;
    }
    
    if(cursor->current_cmd->next &&
       cursor->replied_to)
    {
        /** There are pending commands and the current one has received a response */
        
        cursor->current_cmd = cursor->current_cmd->next;
        rval = cursor->current_cmd->buffer;
        goto retblock;
    }
    
    if(cursor->replied_to == false)
    {
        /** The current command is still active.
	 * Question: return NULL instead and wait for a response?
	 */

        rval = cursor->current_cmd->buffer;
    }

    retblock:
    
    spinlock_release(&cursor->lock);
    
    return rval;
}

/**
 * See if the cursor has pending commands.
 * @param cursor Cursor to inspect
 * @return True if the cursor has pending commands. False if it has reached the end of the list.
 */
bool sescmd_has_next(SCMDCURSOR* cursor)
{
    SCMD* cmd;
    bool replied;
    
    if(cursor == NULL)
	return false;
    
    if(cursor->scmd_list->first == NULL)
    {
	/** No commands to execute */
	return false;
    }
    
    if(cursor->current_cmd == NULL)
    {
        /** This is the first time this cursor is activated*/
        
        return true;
    }
    
    spinlock_acquire(&cursor->lock);
    
    cmd = cursor->current_cmd ? cursor->current_cmd->next : NULL;
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
