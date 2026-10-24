/*
 * honggfuzz - Teapot gadget reporting channel
 * -----------------------------------------
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef _HF_GADGET_H_
#define _HF_GADGET_H_

#include <stdbool.h>

#include "honggfuzz.h"

/* Create the per-thread pipe used by libcheckpoint gadget reports. */
extern void gadget_initRun(run_t* run);

/* Close the per-thread channel descriptors. */
extern void gadget_closeRun(run_t* run);

/* Drain all complete records currently available, without blocking. */
extern void gadget_drain(run_t* run);

#endif /* _HF_GADGET_H_ */
