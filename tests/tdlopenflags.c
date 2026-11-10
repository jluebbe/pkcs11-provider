/* SPDX-License-Identifier: Apache-2.0 */

/* Checks which flags the provider uses to load the PKCS#11 module.
 *
 * This executable exports its own dlopen(), which takes precedence over the
 * one in the C library when the provider is loaded. It records the flags used
 * for the PKCS#11 module and forwards the call. */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <openssl/evp.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"

#if defined(__SANITIZE_ADDRESS__)
#define ADDRESS_SANITIZER 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define ADDRESS_SANITIZER 1
#endif
#endif

static const char *module_path = NULL;
static bool module_loaded = false;
static int module_flags = 0;

void *dlopen(const char *filename, int flags)
{
    static void *(*real_dlopen)(const char *, int) = NULL;

    if (!real_dlopen) {
        real_dlopen = dlsym(RTLD_NEXT, "dlopen");
        if (!real_dlopen) {
            PRINTERR("Failed to find the real dlopen()\n");
            exit(EXIT_FAILURE);
        }
    }

    if (filename && module_path && strcmp(filename, module_path) == 0) {
        module_loaded = true;
        module_flags = flags;
    }

    return real_dlopen(filename, flags);
}

int main(int argc, char *argv[])
{
    bool expect_deepbind = false;
    bool deepbind = false;
    const char *uri;
    EVP_PKEY *key;

    if (argc != 2) {
        PRINTERR("Usage: %s <default|disabled>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

#ifndef RTLD_DEEPBIND
    fprintf(stderr, "RTLD_DEEPBIND is not available on this platform\n");
    exit(77);
#else
    if (strcmp(argv[1], "default") == 0) {
#ifndef ADDRESS_SANITIZER
        expect_deepbind = true;
#endif
    } else if (strcmp(argv[1], "disabled") != 0) {
        PRINTERR("Unknown mode '%s'\n", argv[1]);
        exit(EXIT_FAILURE);
    }

    module_path = getenv("P11LIB");
    if (!module_path) {
        PRINTERR("P11LIB is not set\n");
        exit(EXIT_FAILURE);
    }

    uri = getenv("PUBURI");
    if (!uri) {
        PRINTERR("PUBURI is not set\n");
        exit(EXIT_FAILURE);
    }

    /* the module is loaded on first use and needs to keep working */
    key = load_key(uri);
    EVP_PKEY_free(key);

    if (!module_loaded) {
        PRINTERR("dlopen() of %s not seen\n", module_path);
        exit(EXIT_FAILURE);
    }

    deepbind = (module_flags & RTLD_DEEPBIND) != 0;
    if (deepbind != expect_deepbind) {
        PRINTERR("%s loaded %s RTLD_DEEPBIND (flags 0x%x), expected %s\n",
                 module_path, deepbind ? "with" : "without", module_flags,
                 expect_deepbind ? "with" : "without");
        exit(EXIT_FAILURE);
    }

    fprintf(stderr, "%s loaded %s RTLD_DEEPBIND as expected\n", module_path,
            deepbind ? "with" : "without");
    exit(EXIT_SUCCESS);
#endif
}
