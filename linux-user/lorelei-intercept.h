/* Lorelei address-based interception. SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef LINUX_USER_LORELEI_INTERCEPT_H
#define LINUX_USER_LORELEI_INTERCEPT_H

/* Read <exec_path>.lorelei.json and populate the redirect table. */
void lorelei_intercept_init(const char *exec_path);
/* Redirect target guest address for a marked entry PC, or 0 if none. */
uint64_t lorelei_redirect_lookup(uint64_t pc);

#endif
