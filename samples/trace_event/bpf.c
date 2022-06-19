// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

/*
 * common eBPF ELF operations.
 *
 * Copyright (C) 2013-2015 Alexei Starovoitov <ast@kernel.org>
 * Copyright (C) 2015 Wang Nan <wangnan0@huawei.com>
 * Copyright (C) 2015 Huawei Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License (not later!)
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not,  see <http://www.gnu.org/licenses>
 */

#include <string.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <linux/bpf.h>
#include "bpf.h"

static inline __u64 ptr_to_u64(const void *ptr)
{
	return (__u64) (unsigned long) ptr;
}

static inline int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr,
			  unsigned int size)
{
	return syscall(__NR_bpf, cmd, attr, size);
}

int bpf_map_lookup_elem(int fd, const void *key, void *value)
{
	union bpf_attr attr;
	int ret;

	memset(&attr, 0, sizeof(attr));
	attr.map_fd = fd;
	attr.key = ptr_to_u64(key);
	attr.value = ptr_to_u64(value);

	ret = sys_bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));

	// The libbpf source calls libbpf_err_errno(ret) before actually returning,
	// to handle errors in the "errno" fashion.
	// Here we simplify it to either 0 or -1, which is the legacy way.
	return ret;
}

int bpf_map_delete_elem(int fd, const void *key)
{
	union bpf_attr attr;
	int ret;

	memset(&attr, 0, sizeof(attr));
	attr.map_fd = fd;
	attr.key = ptr_to_u64(key);

	ret = sys_bpf(BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
	// return libbpf_err_errno(ret);
	return ret;
}

int bpf_map_get_next_key(int fd, const void *key, void *next_key)
{
	union bpf_attr attr;
	int ret;

	memset(&attr, 0, sizeof(attr));
	attr.map_fd = fd;
	attr.key = ptr_to_u64(key);
	attr.next_key = ptr_to_u64(next_key);

	ret = sys_bpf(BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr));
	// return libbpf_err_errno(ret);
	return ret;
}
