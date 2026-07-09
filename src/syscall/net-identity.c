/*
 * Host-backed network identity helpers
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_var.h>
#include <ifaddrs.h>
#include <sys/socket.h>

#include "syscall/abi.h"
#include "syscall/net-identity.h"
#include "utils.h"

static const uint8_t fallback_eth0_mac[NET_IDENTITY_MAC_LEN] = {0x02, 0, 0,
                                                                0,    0, 1};

static bool mac_valid(const uint8_t mac[NET_IDENTITY_MAC_LEN])
{
    bool any = false;
    bool all_ff = true;

    for (int i = 0; i < NET_IDENTITY_MAC_LEN; i++) {
        any |= mac[i] != 0;
        all_ff &= mac[i] == 0xff;
    }
    return any && !all_ff;
}

static bool sockaddr_dl_mac(const struct sockaddr *sa,
                            uint8_t mac[NET_IDENTITY_MAC_LEN])
{
    if (!sa || sa->sa_family != AF_LINK)
        return false;

    const struct sockaddr_dl *sdl = (const struct sockaddr_dl *) sa;
    if (sdl->sdl_alen != NET_IDENTITY_MAC_LEN)
        return false;

    memcpy(mac, LLADDR(sdl), NET_IDENTITY_MAC_LEN);
    return mac_valid(mac);
}

static bool ifname_skipped_as_eth0(const char *name)
{
    return !strncmp(name, "awdl", 4) || !strncmp(name, "llw", 3) ||
           !strncmp(name, "utun", 4) || !strncmp(name, "bridge", 6) ||
           !strncmp(name, "vmenet", 6) || !strncmp(name, "anpi", 4) ||
           !strncmp(name, "ap", 2);
}

static bool ifa_has_ip(const struct ifaddrs *ifalist, const char *name)
{
    for (const struct ifaddrs *ifa = ifalist; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || strcmp(ifa->ifa_name, name))
            continue;
        if (ifa->ifa_addr->sa_family == AF_INET ||
            ifa->ifa_addr->sa_family == AF_INET6)
            return true;
    }
    return false;
}

static int eth0_candidate_score(const struct ifaddrs *ifalist,
                                const struct ifaddrs *ifa)
{
    if (!ifa || !ifa->ifa_name || !ifa->ifa_addr ||
        ifa->ifa_addr->sa_family != AF_LINK ||
        (ifa->ifa_flags & IFF_LOOPBACK) ||
        ifname_skipped_as_eth0(ifa->ifa_name))
        return -1;

    uint8_t mac[NET_IDENTITY_MAC_LEN];
    if (!sockaddr_dl_mac(ifa->ifa_addr, mac))
        return -1;

    int score = 0;
    if (ifa->ifa_flags & IFF_UP)
        score += 1000;
    if (ifa->ifa_flags & IFF_RUNNING)
        score += 1000;
    if (ifa_has_ip(ifalist, ifa->ifa_name))
        score += 500;
    if (!strcmp(ifa->ifa_name, "en0"))
        score += 300;
    else if (!strncmp(ifa->ifa_name, "en", 2))
        score += 200;
    return score;
}

static void stats_from_if_data(linux_netdev_stats_t *out, const void *data)
{
    if (!out || !data)
        return;

    const struct if_data *ifd = data;
    out->rx_bytes = ifd->ifi_ibytes;
    out->rx_packets = ifd->ifi_ipackets;
    out->rx_errs = ifd->ifi_ierrors;
    out->rx_drop = ifd->ifi_iqdrops;
    out->rx_multicast = ifd->ifi_imcasts;
    out->tx_bytes = ifd->ifi_obytes;
    out->tx_packets = ifd->ifi_opackets;
    out->tx_errs = ifd->ifi_oerrors;
    out->tx_colls = ifd->ifi_collisions;
}

static bool copy_exact_host_hwaddr(const char *ifname,
                                   uint16_t *family_out,
                                   uint8_t mac_out[NET_IDENTITY_MAC_LEN])
{
    struct ifaddrs *ifalist;
    if (getifaddrs(&ifalist) < 0)
        return false;

    bool found = false;
    for (const struct ifaddrs *ifa = ifalist; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_name || strcmp(ifa->ifa_name, ifname))
            continue;
        if (!sockaddr_dl_mac(ifa->ifa_addr, mac_out))
            continue;
        *family_out = (ifa->ifa_flags & IFF_LOOPBACK) ? LINUX_ARPHRD_LOOPBACK
                                                      : LINUX_ARPHRD_ETHER;
        found = true;
        break;
    }

    freeifaddrs(ifalist);
    return found;
}

void net_identity_snapshot(linux_net_identity_t *out)
{
    memset(out, 0, sizeof(*out));
    memcpy(out->eth0_mac, fallback_eth0_mac, sizeof(out->eth0_mac));

    struct ifaddrs *ifalist;
    if (getifaddrs(&ifalist) < 0)
        return;

    int best_score = -1;
    for (const struct ifaddrs *ifa = ifalist; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_name || !ifa->ifa_addr)
            continue;

        if (!strcmp(ifa->ifa_name, "lo0") &&
            ifa->ifa_addr->sa_family == AF_LINK)
            stats_from_if_data(&out->lo_stats, ifa->ifa_data);

        int score = eth0_candidate_score(ifalist, ifa);
        if (score < 0 || score <= best_score)
            continue;

        uint8_t mac[NET_IDENTITY_MAC_LEN];
        if (!sockaddr_dl_mac(ifa->ifa_addr, mac))
            continue;

        best_score = score;
        out->eth0_from_host = true;
        str_copy_trunc(out->eth0_host_name, ifa->ifa_name,
                       sizeof(out->eth0_host_name));
        memcpy(out->eth0_mac, mac, sizeof(out->eth0_mac));
        stats_from_if_data(&out->eth0_stats, ifa->ifa_data);
    }

    freeifaddrs(ifalist);
}

int net_identity_hwaddr(const char *ifname,
                        uint16_t *family_out,
                        uint8_t mac_out[NET_IDENTITY_MAC_LEN])
{
    if (!ifname || !family_out || !mac_out)
        return -1;

    memset(mac_out, 0, NET_IDENTITY_MAC_LEN);
    if (!strcmp(ifname, "lo") || !strcmp(ifname, "lo0")) {
        *family_out = LINUX_ARPHRD_LOOPBACK;
        return 0;
    }

    if (!strcmp(ifname, "eth0")) {
        linux_net_identity_t ident;
        net_identity_snapshot(&ident);
        *family_out = LINUX_ARPHRD_ETHER;
        memcpy(mac_out, ident.eth0_mac, NET_IDENTITY_MAC_LEN);
        return 0;
    }

    return copy_exact_host_hwaddr(ifname, family_out, mac_out) ? 0 : -1;
}
