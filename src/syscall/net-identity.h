/*
 * Host-backed network identity helpers
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#define NET_IDENTITY_MAC_LEN 6
#define NET_IDENTITY_IFNAME_MAX 16

typedef struct {
    uint64_t rx_bytes;
    uint64_t rx_packets;
    uint64_t rx_errs;
    uint64_t rx_drop;
    uint64_t rx_fifo;
    uint64_t rx_frame;
    uint64_t rx_compressed;
    uint64_t rx_multicast;
    uint64_t tx_bytes;
    uint64_t tx_packets;
    uint64_t tx_errs;
    uint64_t tx_drop;
    uint64_t tx_fifo;
    uint64_t tx_colls;
    uint64_t tx_carrier;
    uint64_t tx_compressed;
} linux_netdev_stats_t;

typedef struct {
    bool eth0_from_host;
    char eth0_host_name[NET_IDENTITY_IFNAME_MAX];
    uint8_t eth0_mac[NET_IDENTITY_MAC_LEN];
    linux_netdev_stats_t lo_stats;
    linux_netdev_stats_t eth0_stats;
} linux_net_identity_t;

void net_identity_snapshot(linux_net_identity_t *out);
int net_identity_hwaddr(const char *ifname,
                        uint16_t *family_out,
                        uint8_t mac_out[NET_IDENTITY_MAC_LEN]);
