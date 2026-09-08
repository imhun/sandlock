/* F16: the route-B worker-side client must be reachable from C, not just
 * Rust.  Connect stores the slot identity; the request opens the unix
 * connection, so against a slot that cannot exist (no registry root on this
 * host) the request must fail with err set.  The smoke proves the symbols
 * link and the err/err_msg contract surfaces a refused connect. */
#include <stdint.h>
#include <stdio.h>

#include "sandlock.h"

int main(void) {
    int err = 0;
    char *err_msg = NULL;

    void *h = sandlock_supervise_connect(
        "/nonexistent-sandlock-ctl/slot.d/control.sock",
        "tok",
        &err,
        &err_msg);
    if (h == NULL) {
        fprintf(stderr, "connect must succeed (identity is stored, not connected)\n");
        return 1;
    }
    if (err != 0) {
        fprintf(stderr, "a successful connect must leave err zero\n");
        return 1;
    }

    char *resp = sandlock_supervise_request(h, "stats", "{}", NULL, 0, &err, &err_msg);
    if (resp != NULL) {
        fprintf(stderr, "request to a nonexistent slot must fail, got: %s\n", resp);
        sandlock_string_free(resp);
        return 1;
    }
    if (err == 0) {
        fprintf(stderr, "a failed request must set err\n");
        return 1;
    }
    if (err_msg != NULL) {
        sandlock_string_free(err_msg);
    }
    sandlock_supervise_free(h);
    return 0;
}
