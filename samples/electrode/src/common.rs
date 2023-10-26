/*
 *  Software Name : fast-paxos
 *  SPDX-FileCopyrightText: Copyright (c) 2022 Orange
 *  SPDX-License-Identifier: LGPL-2.1-only
 *
 *  This software is distributed under the
 *  GNU Lesser General Public License v2.1 only.
 *
 *  Author: asd123www <wzz@pku.edu.cn> et al.
 *  Author: asd123www <ruowenq2@illinois.edu> et al.
 */

// Software Name: fast-paxos
// SPDX-FileCopyrightText: Copyright (c) 2022 Orange
// SPDX-License-Identifier: LGPL-2.1-only
//
// This software is distributed under the
// GNU Lesser General Public License v2.1 only.
//
// Author: asd123www <wzz@pku.edu.cn> et al.

const ETH_ALEN: usize = 6; // Octets in one ethernet addr

const CLUSTER_SIZE: i32 = 3;
const FAST_REPLICA_MAX: i32 = 100; // max # of replicas.
const NONFRAG_MAGIC: i32 = 0x20050318;
const FRAG_MAGIC: i32 = 0x20101010;

const MAGIC_LEN: i32 = 4;
const REQUEST_TYPE_LEN: i32 = 33;
const PREPARE_TYPE_LEN: i32 = 33;
const PREPAREOK_TYPE_LEN: i32 = 35;
const MYPREPAREOK_TYPE_LEN: i32 = 24;

const FAST_PAXOS_DATA_LEN: i32 = 12;
const BROADCAST_SIGN_BIT: i32 = 1 << 31;
const QUORUM_SIZE: i32 = (CLUSTER_SIZE + 1) >> 1;
const QUORUM_BITSET_ENTRY: i32 = 1024; // must be 2^t

#[derive(Debug, PartialEq, Eq)]
enum ReplicaStatus {
    STATUS_NORMAL,
    STATUS_VIEW_CHANGE,
    STATUS_RECOVERING,
}

#[derive(Debug, PartialEq, Eq)]
enum FastProgXdp {
    FAST_PROG_XDP_HANDLE_PREPARE = 0,
    FAST_PROG_XDP_HANDLE_REQUEST,
    FAST_PROG_XDP_HANDLE_PREPAREOK,
    FAST_PROG_XDP_WRITE_BUFFER,
    FAST_PROG_XDP_PREPARE_REPLY,
    FAST_PROG_XDP_MAX,
}

#[derive(Debug, PartialEq, Eq)]
enum FastProgTc {
    FAST_PROG_TC_BROADCAST = 0,
    FAST_PROG_TC_MAX,
}

#[repr(C)]
struct PaxosConfigure {
    addr: u32, // ipv4.
    port: u16,
    eth: [u8; ETH_ALEN],
}
