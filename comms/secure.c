#include <errno.h>
#include <string.h>

#include "comms/comms.h"

typedef struct comms_state {
    int initialized;
    char endpoint_url[1024];
} comms_state_t;

static comms_state_t g_comms_state;

int comms_init(const char *endpoint_url)
{
    size_t len = 0U;

    memset(&g_comms_state, 0, sizeof(g_comms_state));

    if (endpoint_url != NULL) {
        len = strlen(endpoint_url);
        if (len >= sizeof(g_comms_state.endpoint_url)) {
            errno = EINVAL;
            return -1;
        }
        (void)memcpy(g_comms_state.endpoint_url, endpoint_url, len + 1U);
    }

    g_comms_state.initialized = 1;
    return 0;
}

int comms_internal_get_stream(FILE **out_stream)
{
    if (out_stream == NULL || !g_comms_state.initialized) {
        errno = EINVAL;
        return -1;
    }

    /*
     * MVP transport: endpoint selection is deferred; all output is local JSONL
     * to stdout for both empty/"stdout" and non-empty URLs.
     */
    *out_stream = stdout;
    return 0;
}

void comms_shutdown(void)
{
    memset(&g_comms_state, 0, sizeof(g_comms_state));
}
