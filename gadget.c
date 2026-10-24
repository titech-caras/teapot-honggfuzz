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
#define GADGET_DROP_PREFIX     "TPDROP 1 "
#define GADGET_PIPE_TARGET     (1024U * 1024U)

/* A site is the (gadget type, address) pair, matching the Teapot study. */
struct gadgetSite {
    uint64_t sitePlusOne;
    uint64_t type;
};

/* Sites are deduplicated for the whole run, across all fuzzing threads. The
 * table intentionally lives for the whole process and is never freed. */
static struct gadgetSite* gadgetSitesSeen;
static size_t             gadgetSitesUsed;
static size_t             gadgetSiteTableWarning;
static pthread_mutex_t    gadgetSitesMutex = PTHREAD_MUTEX_INITIALIZER;

static size_t gadget_siteHash(uint64_t site, long type) {
    uint64_t hash = site * 0x9e3779b97f4a7c15ULL;
    hash ^= (uint64_t)type * 0xc2b2ae3d27d4eb4fULL;
    hash ^= hash >> 33;
    hash *= 0xff51afd7ed558ccdULL;
    hash ^= hash >> 33;
    return (size_t)(hash >> (64 - GADGET_SITE_TABLE_BITS));
}

static bool gadget_firstSighting(uint64_t site, long type) {
    if (site == UINT64_MAX) {
        return false;
    }

    MX_LOCK(&gadgetSitesMutex);
    bool first = false;

    if (gadgetSitesSeen == NULL) {
        gadgetSitesSeen = util_Calloc(GADGET_SITE_TABLE_SIZE * sizeof(*gadgetSitesSeen));
    }

    size_t idx = gadget_siteHash(site, type);
    for (size_t probe = 0; probe < GADGET_SITE_TABLE_SIZE; probe++) {
        struct gadgetSite slot = gadgetSitesSeen[idx];
        if (slot.sitePlusOne == site + 1 && slot.type == (uint64_t)type) {
            break;
        }
        if (slot.sitePlusOne == 0) {
            gadgetSitesSeen[idx].sitePlusOne = site + 1;
            gadgetSitesSeen[idx].type        = (uint64_t)type;
            first                            = true;
            gadgetSitesUsed++;
            break;
        }
        idx = (idx + 1) & (GADGET_SITE_TABLE_SIZE - 1);
    }

    if (gadgetSiteTableWarning == 0 &&
        gadgetSitesUsed >= (GADGET_SITE_TABLE_SIZE / 4) * 3) {
        gadgetSiteTableWarning = 1;
        LOG_W("Teapot gadget site table is 75%% full (%zu of %u entries)",
            gadgetSitesUsed, GADGET_SITE_TABLE_SIZE);
    }
    if (gadgetSiteTableWarning < 2 && gadgetSitesUsed == GADGET_SITE_TABLE_SIZE) {
        gadgetSiteTableWarning = 2;
        LOG_W("Teapot gadget site table is full (%u entries); new gadget sites are no "
              "longer saved",
            GADGET_SITE_TABLE_SIZE);
    }

    MX_UNLOCK(&gadgetSitesMutex);
    return first;
}

static bool gadget_parseSigned(const char** cursor, long* value) {
    const char* s        = *cursor;
    bool        negative = false;
    if (*s == '-') {
        negative = true;
        s++;
    }
    if (*s < '0' || *s > '9') {
        return false;
    }
    uint64_t magnitude = 0;
    do {
        unsigned digit = (unsigned)(*s - '0');
        if (magnitude > (UINT64_MAX - digit) / 10) {
            return false;
        }
        magnitude = magnitude * 10 + digit;
        s++;
    } while (*s >= '0' && *s <= '9');
    if (magnitude > (uint64_t)LONG_MAX) {
        return false;
    }
    *value  = negative ? -(long)magnitude : (long)magnitude;
    *cursor = s;
    return true;
}

static bool gadget_parseSite(const char** cursor, uint64_t* value) {
    const char* s = *cursor;
    if (s[0] != '0' || s[1] != 'x') {
        return false;
    }
    s += 2;
    if (!((*s >= '0' && *s <= '9') || (*s >= 'a' && *s <= 'f'))) {
        return false;
    }
    uint64_t site = 0;
    for (;;) {
        unsigned digit;
        if (*s >= '0' && *s <= '9') {
            digit = (unsigned)(*s - '0');
        } else if (*s >= 'a' && *s <= 'f') {
            digit = (unsigned)(*s - 'a' + 10);
        } else {
            break;
        }
        if (site > (UINT64_MAX - digit) / 16) {
            return false;
        }
        site = site * 16 + digit;
        s++;
    }
    *value  = site;
    *cursor = s;
    return true;
}

static bool gadget_parseUnsigned(const char* s, uint64_t* value) {
    if (*s < '0' || *s > '9') {
        return false;
    }
    uint64_t result = 0;
    do {
        unsigned digit = (unsigned)(*s - '0');
        if (result > (UINT64_MAX - digit) / 10) {
            return false;
        }
        result = result * 10 + digit;
        s++;
    } while (*s >= '0' && *s <= '9');
    if (*s != '\0') {
        return false;
    }
    *value = result;
    return true;
}

static bool gadget_parseRecord(char* line, uint64_t* site, long* type) {
    static const char prefix[] = GADGET_RECORD_PREFIX;
    const size_t      prefixLen = sizeof(prefix) - 1;

    if (strncmp(line, prefix, prefixLen) != 0) {
        return false;
    }
    const char* cursor = line + prefixLen;

    long parsedType;
    if (!gadget_parseSigned(&cursor, &parsedType) || *cursor != ' ') {
        return false;
    }
    cursor++;
    if (!gadget_parseSite(&cursor, site) || *cursor != '\0') {
        return false;
    }

    *type = parsedType;
    return true;
}

static void gadget_handleRecord(run_t* run, uint64_t site, long type) {
    if (!gadget_firstSighting(site, type)) {
        return;
    }

    ATOMIC_POST_INC(run->global->cnts.gadgetSitesCnt);

    uint64_t inputHash = util_hash((const char*)run->dynfile->data, run->dynfile->size);
    char     fname[PATH_MAX];
    int      len = snprintf(fname, sizeof(fname),
             "%s/GADGET.%ld.%016" PRIx64 ".%016" PRIx64 ".fuzz", run->global->io.workDir, type,
             site, inputHash);
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

static void gadget_handleDrop(run_t* run, const char* line) {
    const size_t prefixLen = sizeof(GADGET_DROP_PREFIX) - 1;
    const char*  cursor    = line + prefixLen;

    uint64_t count;
    if (!gadget_parseUnsigned(cursor, &count)) {
        LOG_W("Ignoring a malformed Teapot dropped-record notice");
        return;
    }

    /* This counts lost record attempts, not unique sites. */
    ATOMIC_POST_ADD(run->global->cnts.gadgetDroppedCnt, count);
    LOG_W("Teapot gadget channel dropped %" PRIu64 " records before the reader drained it", count);
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
            if (strncmp(base, GADGET_DROP_PREFIX, sizeof(GADGET_DROP_PREFIX) - 1) == 0) {
                gadget_handleDrop(run, base);
            } else {
                uint64_t site;
                long     type;
                if (gadget_parseRecord(base, &site, &type)) {
                    gadget_handleRecord(run, site, type);
                } else {
                    LOG_W("Ignoring a malformed Teapot gadget record");
                }
            }
        }
        start += lineLen + 1;
    }

    if (start != 0) {
        memmove(run->gadgetBuf, run->gadgetBuf + start, run->gadgetBufLen - start);
        run->gadgetBufLen -= start;
    }
}

#if defined(_HF_ARCH_LINUX)
/* Grow the channel pipe so a single iteration can report many sites before
 * honggfuzz gets a chance to drain it. Never exceed the system-wide limit. */
static int gadget_pipeTargetSize(void) {
    int   target = (int)GADGET_PIPE_TARGET;
    char  buf[64];
    ssize_t len = files_readFileToBufMax(
        "/proc/sys/fs/pipe-max-size", (uint8_t*)buf, sizeof(buf) - 1);
    if (len > 0) {
        buf[len] = '\0';
        errno    = 0;
        char* end = NULL;
        long  limit = strtol(buf, &end, 10);
        if (end != buf && errno == 0 && limit > 0 && limit < target) {
            target = (int)limit;
        }
    }
    return target;
}
#endif /* _HF_ARCH_LINUX */

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

    int target = gadget_pipeTargetSize();
    if (fcntl(run->gadgetWriteFd, F_SETPIPE_SZ, target) == -1) {
        PLOG_W("fcntl(F_SETPIPE_SZ, %d) on the Teapot gadget channel", target);
    }
    int actual = fcntl(run->gadgetWriteFd, F_GETPIPE_SZ);
    if (actual > 0) {
        LOG_I("Teapot gadget channel pipe size: %d bytes (requested %d)", actual, target);
    } else {
        PLOG_W("fcntl(F_GETPIPE_SZ) on the Teapot gadget channel");
    }
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
        /* Accepted limitation: an oversized record with no newline in 4 KiB is
         * discarded rather than grown. */
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
