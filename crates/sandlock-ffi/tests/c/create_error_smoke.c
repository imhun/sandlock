/* B1 (SL-12): `sandlock_create_with_err` / `sandlock_instance_launch_with_err`
 * must be declared in sandlock.h and linkable from C, and the err/err_msg
 * contract must surface the reason.  A NULL policy is refused by the binding's
 * own prologue, so the smoke needs no fork and stays deterministic -- its job
 * is to pin the hand-maintained header declarations against the exported
 * symbols (a header typo would otherwise only show up in the wheel check).
 *
 * The expected strings are the prologue's *bare* reasons: the caller's own
 * face names the operation (`sandlock_create failed: <reason>` in Python), so
 * the FFI must not prefix the symbol a second time (B1 review, minor-1). */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "sandlock.h"

static int check(const char *what, int err, char *msg, const char *want) {
    if (err != -1) {
        fprintf(stderr, "%s: err must be -1, got %d\n", what, err);
        return 1;
    }
    if (msg == NULL) {
        fprintf(stderr, "%s: no reason published\n", what);
        return 1;
    }
    if (strcmp(msg, want) != 0) {
        fprintf(stderr, "%s: reason is %s\n", what, msg);
        sandlock_string_free(msg);
        return 1;
    }
    sandlock_string_free(msg);
    return 0;
}

int main(void) {
    char *argv[] = {"/bin/true", NULL};
    int err = 0;
    char *err_msg = NULL;

    void *h = sandlock_create_with_err(
        NULL, NULL, (const char *const *)argv, 1, &err, &err_msg);
    if (h != NULL) {
        fprintf(stderr, "create: a NULL policy must not produce a handle\n");
        return 1;
    }
    if (check("create", err, err_msg,
              "policy and argv are required") != 0) {
        return 1;
    }

    err = 0;
    err_msg = NULL;
    void *inst = sandlock_instance_launch_with_err(NULL, NULL, &err, &err_msg);
    if (inst != NULL) {
        fprintf(stderr, "launch: a NULL policy must not produce an instance\n");
        return 1;
    }
    if (check("launch", err, err_msg,
              "policy is required") != 0) {
        return 1;
    }
    return 0;
}
