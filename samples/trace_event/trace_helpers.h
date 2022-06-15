/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __TRACE_HELPER_H
#define __TRACE_HELPER_H

struct ksym {
	long addr;
	char *name;
};

int load_kallsyms(void);
struct ksym *ksym_search(long key);

#endif
