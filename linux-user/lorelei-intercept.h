/* Lorelei address-based interception. SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef LINUX_USER_LORELEI_INTERCEPT_H
#define LINUX_USER_LORELEI_INTERCEPT_H

void lorelei_intercept_init(const char *exec_path);
uint64_t lorelei_redirect_lookup(uint64_t pc);
void lorelei_register_thunk(const char *id, uint64_t addr);
uint64_t lorelei_host_call(const char *name, int argc, const uint64_t *argv);

#endif
