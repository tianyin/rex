/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

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
#ifndef __LIBBPF_BPF_H
#define __LIBBPF_BPF_H

// LIBBPF_API is an attribute macro used in libbpf. Ignored here.

/*LIBBPF_API*/ int bpf_map_lookup_elem(int fd, const void *key, void *value);
/*LIBBPF_API*/ int bpf_map_delete_elem(int fd, const void *key);
/*LIBBPF_API*/ int bpf_map_get_next_key(int fd, const void *key, void *next_key);

#endif /* __LIBBPF_BPF_H */
