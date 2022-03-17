/*
 *  Software Name : bmc-cache
 *  SPDX-FileCopyrightText: Copyright (c) 2021 Orange
 *  SPDX-License-Identifier: LGPL-2.1-only
 *
 *  This software is distributed under the
 *  GNU Lesser General Public License v2.1 only.
 *
 *  Author: Yoann GHIGOFF <yoann.ghigoff@orange.com> et al.
 */

use crate::linux::bpf::*;

pub const BMC_MAX_KEY_LENGTH: u32 = 250;
pub const BMC_MAX_VAL_LENGTH: u32 = 1000;
pub const BMC_MAX_ADDITIONAL_PAYLOAD_BYTES: u32 = 53;
pub const BMC_MAX_CACHE_DATA_SIZE: u32 =
    BMC_MAX_KEY_LENGTH + BMC_MAX_VAL_LENGTH + BMC_MAX_ADDITIONAL_PAYLOAD_BYTES;
pub const BMC_MAX_KEY_IN_MULTIGET: u32 = 30;
pub const BMC_CACHE_ENTRY_COUNT: u32 = 3250000;
pub const BMC_MAX_PACKET_LENGTH: u32 = 1500;
pub const BMC_MAX_KEY_IN_PACKET: u32 = BMC_MAX_KEY_IN_MULTIGET;

pub const FNV_OFFSET_BASIS_32: u32 = 2166136261;
pub const FNV_PRIME_32: u32 = 16777619;

pub const BMC_PROG_XDP_HASH_KEYS: u32 = 0;
pub const BMC_PROG_XDP_PREPARE_PACKET: u32 = 1;
pub const BMC_PROG_XDP_WRITE_REPLY: u32 = 2;
pub const BMC_PROG_XDP_INVALIDATE_CACHE: u32 = 3;
pub const BMC_PROG_XDP_MAX: u32 = 4;

pub const BMC_PROG_TC_UPDATE_CACHE: u32 = 0;
pub const BMC_PROG_TC_MAX: u32 = 1;

struct bmc_cache_entry {
    pub lock: bpf_spin_lock,
    pub len: u32,
    valid: i8,
    hash: i32,
    pub data: [i8; BMC_MAX_CACHE_DATA_SIZE as usize],
}

struct bmc_stats {
    get_recv_count: u32,     // Number of GET command received
    set_recv_count: u32,     // Number of SET command received
    get_resp_count: u32,     // Number of GET command reply analyzed
    hit_misprediction: u32, // Number of keys that were expected to hit but did not (either because of a hash colision or a race with an invalidation/update)
    hit_count: u32,         // Number of HIT in kernel cache
    miss_count: u32,        // Number of MISS in kernel cache
    update_count: u32,      // Number of kernel cache updates
    invalidation_count: u32, // Number of kernel cache entry invalidated
}
