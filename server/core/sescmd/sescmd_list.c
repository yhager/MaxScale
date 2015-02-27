#include <sescmd.h>
#include <strings.h>

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
 * Free the session command list. This frees all commands and cursors associated
 * with this list.
 * @param list Session command list to free
 */
void sescmdlist_free(SCMDLIST*  list)
{
    SCMD* cmd;
    
    spinlock_acquire(&list->lock);
    cmd = list->first;
    list->first = NULL;
    list->last = NULL;
    spinlock_release(&list->lock);
    
    while(cmd)
    {
        SCMD* tmp = cmd;
        cmd = cmd->next;
        sescmd_free(tmp);
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
    
    if(dcb->cursor != NULL)
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
    cursor->current_cmd = list->first;
    dcb->cursor = cursor;
    atomic_add(&list->n_cursors,1);
    
    return true;
}
