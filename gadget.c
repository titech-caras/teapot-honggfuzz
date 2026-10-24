/*
 * honggfuzz - Teapot gadget reporting channel
 * -----------------------------------------
 *
 * libcheckpoint reports each gadget as one "TPGADGET 1 <type> <site>" line on
 * the file descriptor named by HF_TEAPOT_REPORT_FD. This file creates that
 * channel, drains it after every iteration, and keeps the first input that
 * reaches each gadget site.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 */

#include "gadget.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libhfcommon/common.h"
#include "libhfcommon/files.h"
#include "libhfcommon/log.h"
#include "libhfcommon/util.h"

#define GADGET_SITE_TABLE_BITS 16
#define GADGET_SITE_TABLE_SIZE (1U << GADGET_SITE_TABLE_BITS)
#define GADGET_RECORD_PREFIX   "TPGADGET 1 "

/* Sites are deduplicated for the whole run, across all fuzzing threads. */
static uint64_t*       gadgetSitesSeen;
static pthread_mutex_t gadgetSitesMutex = PTHREAD_MUTEX_INITIALIZER;

static bool gadget_firstSighting(uint64_t site) {
    if (site == UINT64_MAX) {
        return false;
    }

    MX_LOCK(&gadgetSitesMutex);
    bool first = false;

    if (gadgetSitesSeen == NULL) {
        gadgetSitesSeen = util_Calloc(GADGET_SITE_TABLE_SIZE * sizeof(uint64_t));
    }

    size_t idx =
        (size_t)((site * 11400714819323198485ULL) >> (64 - GADGET_SITE_TABLE_BITS));
    for (size_t probe = 0; probe < GADGET_SITE_TABLE_SIZE; probe++) {
        uint64_t slot = gadgetSitesSeen[idx];
        if (slot == site + 1) {
            break;
        }
        if (slot == 0) {
            gadgetSitesSeen[idx] = site + 1;
            first                = true;
            break;
        }
        idx = (idx + 1) & (GADGET_SITE_TABLE_SIZE - 1);
    }

    MX_UNLOCK(&gadgetSitesMutex);
    return first;
}

static bool gadget_parseRecord(char* line, uint64_t* site, long* type) {
    static const char prefix[] = GADGET_RECORD_PREFIX;
    const size_t      prefixLen = sizeof(prefix) - 1;

    if (strncmp(line, prefix, prefixLen) != 0) {
        return false;
    }
    char* cursor = line + prefixLen;

    errno     = 0;
    char* end = NULL;
    long  parsedType = strtol(cursor, &end, 10);
    if (end == cursor || *end != ' ' || errno == ERANGE) {
        return false;
    }
    cursor = end + 1;
    if (cursor[0] != '0' || cursor[1] != 'x') {
        return false;
    }
    cursor += 2;

    errno = 0;
    unsigned long long parsedSite = strtoull(cursor, &end, 16);
    if (end == cursor || *end != '\0' || errno == ERANGE) {
        return false;
    }

    *site = (uint64_t)parsedSite;
    *type = parsedType;
    return true;
}

static void gadget_handleRecord(run_t* run, uint64_t site, long type) {
    if (!gadget_firstSighting(site)) {
        return;
    }

    ATOMIC_POST_INC(run->global->cnts.gadgetSitesCnt);

    uint64_t inputHash = util_hash((const char*)run->dynfile->data, run->dynfile->size);
    char     fname[PATH_MAX];
    int      len = snprintf(fname, sizeof(fname), "%s/GADGET.%016" PRIx64 ".%016" PRIx64 ".fuzz",
             run->global->io.workDir, site, inputHash);
    if (len < 0 || (size_t)len >= sizeof(fname)) {
        LOG_W("Couldn't build a gadget reproducer name for site 0x%016" PRIx64, site);
        return;
    }

    if (!files_writeBufToFile(
            fname, run->dynfile->data, run->dynfile->size, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC)) {
        LOG_W("Couldn't save the gadget reproducer '%s'", fname);
        return;
    }

    LOG_I("New gadget site type=%ld addr=0x%016" PRIx64 ", saved input as '%s'", type, site, fname);
}

/* Consume complete newline-terminated records, keeping any partial tail. */
static void gadget_processBuffer(run_t* run) {
    size_t start = 0;

    while (start < run->gadgetBufLen) {
        char*  base      = run->gadgetBuf + start;
        size_t remaining = run->gadgetBufLen - start;
        char*  newline   = memchr(base, '\n', remaining);
        if (newline == NULL) {
            break;
        }

        size_t lineLen = (size_t)(newline - base);
        *newline       = '\0';
        if (lineLen != 0) {
            uint64_t site;
            long     type;
            if (gadget_parseRecord(base, &site, &type)) {
                gadget_handleRecord(run, site, type);
            } else {
                LOG_W("Ignoring a malformed Teapot gadget record");
            }
        }
        start += lineLen + 1;
    }

    if (start != 0) {
        memmove(run->gadgetBuf, run->gadgetBuf + start, run->gadgetBufLen - start);
        run->gadgetBufLen -= start;
    }
}

void gadget_initRun(run_t* run) {
    run->gadgetReadFd  = -1;
    run->gadgetWriteFd = -1;
    run->gadgetBufLen  = 0;

#if defined(_HF_ARCH_LINUX)
    int fds[2];
    if (pipe2(fds, O_CLOEXEC | O_NONBLOCK) == -1) {
        PLOG_W("pipe2(teapot gadget channel)");
        return;
    }
    run->gadgetReadFd  = fds[0];
    run->gadgetWriteFd = fds[1];
#endif /* _HF_ARCH_LINUX */
}

void gadget_closeRun(run_t* run) {
    if (run->gadgetReadFd != -1) {
        close(run->gadgetReadFd);
        run->gadgetReadFd = -1;
    }
    if (run->gadgetWriteFd != -1) {
        close(run->gadgetWriteFd);
        run->gadgetWriteFd = -1;
    }
}

void gadget_drain(run_t* run) {
    if (run->gadgetReadFd == -1) {
        return;
    }

    for (;;) {
        if (run->gadgetBufLen == sizeof(run->gadgetBuf)) {
            LOG_W("Teapot gadget record buffer is full without a newline; dropping it");
            run->gadgetBufLen = 0;
        }

        ssize_t count = read(run->gadgetReadFd, run->gadgetBuf + run->gadgetBufLen,
            sizeof(run->gadgetBuf) - run->gadgetBufLen);
        if (count > 0) {
            run->gadgetBufLen += (size_t)count;
            gadget_processBuffer(run);
            continue;
        }
        if (count == 0) {
            return;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return;
        }
        PLOG_W("read(teapot gadget channel)");
        return;
    }
}
