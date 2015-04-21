#include <modinfo.h>
#include <modutil.h>
#include <filter.h>
#include <log_manager.h>

#include <dlfcn.h>

#include "mongofilter.h"
#include "query_classifier.h"

/* defined in log_manager.cc */
extern int lm_enabled_logfiles_bitmask;
extern size_t log_ses_count[];
extern __thread log_info_t tls_log_info;

MODULE_INFO info = {
    MODULE_API_FILTER,
    MODULE_IN_DEVELOPMENT,
    FILTER_VERSION,
    "MongoDB Filter"
};

typedef struct mongolibrary_object {
    void* (*createInstance)(char *address, int port);
    void  (*destroyInstance)(void *instance); /* is this ever called? */
    void* (*createSession)(void* instance);
    void  (*destroySession)(void *session);
    void  (*runQuery)(void* session, char* sql, void* lex, unsigned char** data, size_t* len);
} MONGO_OBJECT;

typedef struct {
    void* instance;
    MONGO_OBJECT* object;
} MONGO_INSTANCE;

typedef struct {
    SESSION* session;
    void* mongo_session;
    DOWNSTREAM down;
} MONGO_SESSION;

static FILTER *createInstance(char **options,
                              FILTER_PARAMETER **params)
{
    MONGO_INSTANCE* my_instance;
    char *address, *lib;
    void *handle;
    int port;
    int i;
    void* (*get_mongo_sql_object)();

    if ((my_instance = (MONGO_INSTANCE*)calloc(1, sizeof(MONGO_INSTANCE))) != NULL)
    {
        address = "localhost";
        port = 27017;
        lib = NULL;
        for (i = 0; params && params[i]; ++i)
        {
            if (!strcmp(params[i]->name, "address"))
                address = params[i]->value;
            else if (!strcmp(params[i]->name, "port"))
                port = atoi(params[i]->value);
            else if (!strcmp(params[i]->name, "library"))
                lib = params[i]->value;
            else if (!filter_standard_parameter(params[i]->name))
            {
                LOGIF(LE, (skygw_log_write_flush(
                               LOGFILE_ERROR,
                               "mongofilter: Unexpected parameter '%s'.\n",
                               params[i]->name)));
            }
        }

        if (port <= 0)
        {
            LOGIF(LE, skygw_log_write_flush(LOGFILE_ERROR,
                                            "mongofilter: Invalid port number %d\n",
                                            port));
            return NULL;
        }

        if (lib == NULL)
        {
            LOGIF(LE, skygw_log_write_flush(LOGFILE_ERROR,
                                            "mongofilter: missing library parameter\n"));
            return NULL;
        }
        char library[64];
        snprintf(library, 64, "lib%s.so", lib);
        library[63] = '\0';
        if ((handle = dlopen(library, RTLD_NOW | RTLD_GLOBAL)) == NULL)
        {
            skygw_log_write_flush(LOGFILE_ERROR,
                                  "mongofilter: error loading library %s: %s\n",
                                  library, dlerror());
            return NULL;
        }

        if ((get_mongo_sql_object = dlsym(handle, "GetModuleObject")) == NULL)
        {
            LOGIF(LE, skygw_log_write_flush(LOGFILE_ERROR,
                                            "mongofilter: error finding symbol GetModuleObject in library %s: %s\n",
                                            library, dlerror()));
            dlclose(handle);
        }

        my_instance->object = get_mongo_sql_object();
        my_instance->instance = my_instance->object->createInstance(address, port);
    }

    return (FILTER *)my_instance;
}

static void *newSession(FILTER *instance,
                        SESSION *session)
{
    MONGO_INSTANCE* my_instance = (MONGO_INSTANCE*) instance;
    MONGO_SESSION* my_session;

    if ((my_session = calloc(1, sizeof(MONGO_SESSION))) != NULL)
    {
        my_session->session = session;
        my_session->mongo_session = my_instance->object->createSession(my_instance->instance);
    }
    return my_session;
}

static void closeSession(FILTER *instance,
                         void *session)
{
    MONGO_INSTANCE* my_instance = (MONGO_INSTANCE*) instance;
    MONGO_SESSION* my_session = (MONGO_SESSION*) session;
    my_instance->object->destroySession(my_session->mongo_session);
    my_session->mongo_session = NULL;
}

static void freeSession(FILTER *instance,
                        void *session)
{
    free(session);
}

static void setDownstream(FILTER *instance,
                          void *session,
                          DOWNSTREAM *downstream)
{
    ((MONGO_SESSION *)session)->down = *downstream;
}

static int routeQuery(FILTER *instance,
                      void *session,
                      GWBUF *queue)
{
    MONGO_INSTANCE* my_instance = (MONGO_INSTANCE*) instance;
    MONGO_SESSION* my_session = (MONGO_SESSION*) session;
    char* sql = modutil_get_SQL(queue);
    DCB* dcb = my_session->session->client;
    unsigned char* buf;
    size_t len;
    GWBUF *reply;
    void* lex = NULL;

    if (sql)
    {
        if (!query_is_parsed(queue))
        {
            bool success = parse_query(queue);
            if (!success)
            {
                skygw_log_write_flush(LOGFILE_ERROR,
                                      "Parsing query failed");
                /* @todo: downstream maybe? */
                return 0;
            }
            lex = get_lex(queue);
            if (!is_select_command(lex))
            {
                /* @todo: do we want to send downstream in this case? */
                return my_session->down.routeQuery(my_session->down.instance,
                                                   my_session->down.session, queue);
            }
        }
        my_instance->object->runQuery(my_session->mongo_session, sql, lex, &buf, &len);
        /* @TODO: move data from buf to GWBUF
        * reply = BUF_TO_GWBUF(buf, len);
        **/
        free(buf);
        return dcb->func.write(dcb, reply);
    }
    return 1;
}

static void diagnostic(FILTER *instance, void *fsession, DCB *dcb) {}

static FILTER_OBJECT MyObject = {
    createInstance,
    newSession,
    closeSession,
    freeSession,
    setDownstream,
    NULL,  // No upstream requirement
    routeQuery,
    NULL,
    diagnostic,
};

char* version() { return "V1.0.0"; }
void ModuleInit() {}
FILTER_OBJECT* GetModuleObject() { return &MyObject; }
