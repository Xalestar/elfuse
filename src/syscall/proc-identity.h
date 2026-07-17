/*
 * Process identity state internals
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

void proc_identity_init(void);

/* Update only the parent identity after orphan reparenting. */
void proc_set_ppid(int64_t ppid);

void proc_set_child_subreaper(bool enabled);
bool proc_get_child_subreaper(void);
