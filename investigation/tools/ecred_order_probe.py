"""Probe pinned ECRED functions or compile native objects; never load a kernel."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shutil
import struct
import subprocess
import tempfile
import urllib.request


REVISION = '359f37f0faefb712add32a39f98751aea67d5c1f'
SOURCE_SHA256 = '40b71702ffee7a0e47d3f3c12861d3fc1cb235a67fa3e1bd3407fd56a860aaa8'
SOURCE_URL = f'https://raw.githubusercontent.com/raspberrypi/linux/{REVISION}/net/bluetooth/l2cap_core.c'
HEADER_URL = f'https://raw.githubusercontent.com/raspberrypi/linux/{REVISION}/include/net/bluetooth/l2cap.h'
HEADER_SHA256 = '552aa2caaf8b3e874050ee5d20c4c8016251acc1bf7b8a5b8ea39cdb630031fc'

SHIM = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint16_t __le16;
#define __packed __attribute__((packed))
#define cpu_to_le16(value) (value)
#define __le16_to_cpu(value) (value)
#define BT_DBG(...) ((void)0)
#define FLAG_DEFER_SETUP 0
#define FLAG_ECRED_CONN_REQ_SENT 1
#define L2CAP_MODE_EXT_FLOWCTL 3
#define BT_CONNECT 1
#define BT_CONNECTED 2
#define L2CAP_ECRED_CONN_REQ 23
#define L2CAP_DISCONN_RSP 7
#define L2CAP_CR_LE_AUTHENTICATION 5
#define L2CAP_CR_LE_ENCRYPTION 8
#define L2CAP_CR_LE_BAD_PSM 2
#define BT_SECURITY_MEDIUM 2
struct pid { int unused; };
struct mutex { int unused; };
struct hci_conn { int sec_level; };
struct l2cap_chan;
struct channel_list { struct l2cap_chan *items[5]; int count; };
struct l2cap_conn {
    struct channel_list chan_l;
    struct hci_conn *hcon;
    u8 tx_ident;
    struct mutex ident_lock;
};
struct l2cap_ops {
    struct pid *(*get_peer_pid)(struct l2cap_chan *);
    void (*set_shutdown)(struct l2cap_chan *);
    void (*close)(struct l2cap_chan *);
};
struct l2cap_chan {
    struct l2cap_conn *conn;
    struct l2cap_ops *ops;
    unsigned long flags;
    u16 scid, dcid, psm, imtu, mps, rx_credits, omtu, remote_mps, tx_credits;
    int ident, mode, state, sec_level, deleted, delete_error;
    u8 ecred_tx_index;
    struct pid *peer;
};
struct l2cap_ecred_conn_req_hdr { u16 psm, mtu, mps, credits; };
struct l2cap_ecred_conn_rsp { u16 mtu, mps, credits, result, dcid[]; };
struct l2cap_disconn_req { u16 dcid, scid; };
struct l2cap_disconn_rsp { u16 dcid, scid; };
struct l2cap_cmd_hdr { u8 ident; };
static struct pid peer_pid;
static u16 sent_scids[5];
static int sent_count;
static u8 request_ident = 7;
static bool allocate_identifiers;
static int security_calls;
static bool reverse_list;
static struct l2cap_chan *disconnect_target;
static struct l2cap_disconn_rsp disconnect_response;
static int disconnect_steps;
static struct pid *get_peer_pid(struct l2cap_chan *chan) { return chan->peer ? chan->peer : &peer_pid; }
static void set_shutdown(struct l2cap_chan *chan) { assert(chan == disconnect_target); disconnect_steps++; }
static void close_channel(struct l2cap_chan *chan) { assert(chan == disconnect_target); disconnect_steps++; }
static int test_bit(int bit, unsigned long *flags) { return !!(*flags & (1ul << bit)); }
static int test_and_clear_bit(int bit, unsigned long *flags) {
    int result = test_bit(bit, flags); *flags &= ~(1ul << bit); return result;
}
static int test_and_set_bit(int bit, unsigned long *flags) {
    int result = test_bit(bit, flags); *flags |= 1ul << bit; return result;
}
static void clear_bit(int bit, unsigned long *flags) { *flags &= ~(1ul << bit); }
static void l2cap_ecred_init(struct l2cap_chan *chan, u16 credits) { (void)chan; (void)credits; }
static void mutex_lock(struct mutex *lock) { (void)lock; }
static void mutex_unlock(struct mutex *lock) { (void)lock; }
static u8 pinned_l2cap_get_ident(struct l2cap_conn *conn);
static u8 l2cap_get_ident(struct l2cap_conn *conn) {
    return allocate_identifiers ? pinned_l2cap_get_ident(conn) : request_ident;
}
static void __l2cap_chan_list(struct l2cap_conn *conn,
    void (*callback)(struct l2cap_chan *, void *), void *data) {
    for (int index = 0; index < conn->chan_l.count; index++) {
        if (!conn->chan_l.items[index]->deleted) { callback(conn->chan_l.items[index], data); }
    }
}
static void l2cap_send_cmd(struct l2cap_conn *conn, u8 ident, u8 code, u16 length, void *data) {
    (void)conn; assert(ident != 0);
    if (code == L2CAP_DISCONN_RSP) {
        assert(length == sizeof(disconnect_response));
        memcpy(&disconnect_response, data, length);
        disconnect_steps++;
        return;
    }
    assert(code == L2CAP_ECRED_CONN_REQ);
    sent_count = (length - sizeof(struct l2cap_ecred_conn_req_hdr)) / sizeof(u16);
    assert(sent_count > 0 && sent_count <= 5);
    memcpy(sent_scids, (u8 *)data + sizeof(struct l2cap_ecred_conn_req_hdr), sent_count * sizeof(u16));
}
#define list_for_each_entry_safe(entry, next, head, member) \
    for (int channel_index = 0; channel_index < (head)->count && \
        ((entry) = (head)->items[channel_index], (next) = (entry), (void)(next), 1); channel_index++) \
        if ((entry)->deleted) {} else
static void l2cap_chan_lock(struct l2cap_chan *chan) { (void)chan; }
static void l2cap_chan_unlock(struct l2cap_chan *chan) { (void)chan; }
static void l2cap_chan_del(struct l2cap_chan *chan, int error) {
    assert(!chan->deleted);
    chan->deleted = 1;
    chan->delete_error = error;
    chan->state = 0;
    if (chan == disconnect_target) { assert(error == ECONNRESET); disconnect_steps++; }
}
static void l2cap_chan_put(struct l2cap_chan *chan) { assert(chan == disconnect_target); disconnect_steps++; }
static void l2cap_chan_ready(struct l2cap_chan *chan) { chan->state = BT_CONNECTED; }
static void smp_conn_security(struct hci_conn *conn, int level) {
    (void)conn; assert(level == 1); security_calls++;
}
static struct l2cap_chan *__l2cap_get_chan_by_dcid(struct l2cap_conn *conn, u16 dcid) {
    for (int index = 0; index < conn->chan_l.count; index++) {
        if (!conn->chan_l.items[index]->deleted && conn->chan_l.items[index]->dcid == dcid) {
            return conn->chan_l.items[index];
        }
    }
    return NULL;
}
static struct l2cap_chan *l2cap_get_chan_by_scid(struct l2cap_conn *conn, u16 scid) {
    for (int index = 0; index < conn->chan_l.count; index++) {
        if (!conn->chan_l.items[index]->deleted && conn->chan_l.items[index]->scid == scid) {
            return conn->chan_l.items[index];
        }
    }
    return NULL;
}
static void cmd_reject_invalid_cid(struct l2cap_conn *conn, u8 ident, u16 dcid, u16 scid) {
    (void)conn; (void)ident; (void)dcid; (void)scid; assert(0);
}
'''

CASES = r'''
static void run_case(int count, int trigger, bool expect_mismatch) {
    struct hci_conn hcon = {0};
    struct l2cap_conn conn = {.hcon = &hcon};
    struct l2cap_ops ops = {.get_peer_pid = get_peer_pid, .set_shutdown = set_shutdown, .close = close_channel};
    struct l2cap_chan channels[5] = {0};
    request_ident = 7;
    disconnect_target = NULL;
    conn.chan_l.count = count;
    for (int index = 0; index < count; index++) {
        channels[index] = (struct l2cap_chan){.conn = &conn, .ops = &ops,
            .flags = index == trigger ? 0 : 1ul << FLAG_DEFER_SETUP,
            .scid = 64 + index, .psm = 39, .imtu = 64, .mps = 64,
            .mode = L2CAP_MODE_EXT_FLOWCTL, .state = BT_CONNECT};
        conn.chan_l.items[index] = &channels[reverse_list ? count - index - 1 : index];
    }
    l2cap_ecred_connect(&channels[trigger]);
    assert(sent_count == count);
    assert(sent_scids[0] == 64 + trigger);
    expect_mismatch = expect_mismatch && !PROPOSED;
    u16 response_storage[9] = {64, 64, 10, 0};
    struct l2cap_ecred_conn_rsp *response = (void *)response_storage;
    struct l2cap_cmd_hdr command = {.ident = 7};
    for (int index = 0; index < count; index++) { response->dcid[index] = 64 + index; }
    assert(l2cap_ecred_conn_rsp(&conn, &command, 8 + count * sizeof(u16), (u8 *)response) == 0);
    bool mismatch = false;
    for (int index = 0; index < count; index++) {
        struct l2cap_chan *channel = &channels[sent_scids[index] - 64];
        assert(channel->state == BT_CONNECTED);
        mismatch |= channel->dcid != response->dcid[index];
    }
    assert(mismatch == expect_mismatch);
    printf("count=%d trigger=%d mismatch=%d request=", count, 64 + trigger, mismatch);
    for (int index = 0; index < count; index++) { printf("%s%u", index ? "," : "", sent_scids[index]); }
    printf(" assignments=");
    for (int index = 0; index < count; index++) {
        printf("%s%u:%u", index ? "," : "", channels[index].scid, channels[index].dcid);
    }
    puts("");
    disconnect_target = &channels[trigger];
    disconnect_steps = 0;
    u16 advertised_peer = 0;
    for (int index = 0; index < count; index++) {
        if (sent_scids[index] == disconnect_target->scid) { advertised_peer = response->dcid[index]; }
    }
    assert(advertised_peer != 0);
    struct l2cap_disconn_req request = {.dcid = disconnect_target->scid, .scid = advertised_peer};
    assert(l2cap_disconnect_req(&conn, &command, sizeof(request), (u8 *)&request) == 0);
    assert(disconnect_steps == 5);
    assert(disconnect_response.dcid == disconnect_target->scid);
    assert(disconnect_response.scid == disconnect_target->dcid);
    assert((disconnect_response.scid != request.scid) == expect_mismatch);
    printf("disconnect_request=%u:%u disconnect_response=%u:%u association_mismatch=%d\n",
        request.dcid, request.scid, disconnect_response.dcid, disconnect_response.scid, expect_mismatch);
}
static void pending_removal_case(void) {
    struct hci_conn hcon = {0};
    struct l2cap_conn conn = {.hcon = &hcon};
    struct l2cap_ops ops = {.get_peer_pid = get_peer_pid};
    struct l2cap_chan channels[2] = {0};
    conn.chan_l.count = 2;
    for (int index = 0; index < 2; index++) {
        channels[index] = (struct l2cap_chan){.conn = &conn, .ops = &ops,
            .flags = index ? 1ul << FLAG_DEFER_SETUP : 0, .scid = 64 + index,
            .psm = 39, .imtu = 64, .mps = 64, .mode = L2CAP_MODE_EXT_FLOWCTL, .state = BT_CONNECT};
        conn.chan_l.items[index] = &channels[index];
    }
    l2cap_ecred_connect(&channels[0]);
    assert(sent_scids[0] == 64 && sent_scids[1] == 65);
    conn.chan_l.items[0] = &channels[1];
    conn.chan_l.count = 1;
    u16 response[] = {64, 64, 10, 0, 64, 65};
    struct l2cap_cmd_hdr command = {.ident = 7};
    assert(l2cap_ecred_conn_rsp(&conn, &command, sizeof(response), (u8 *)response) == 0);
    assert(channels[1].dcid == (PROPOSED ? 65 : 64));
    printf("pending_removed_wrong_peer=%d\n", !PROPOSED);
}
static void response_case(const char *name, u16 result, int slots, const u16 *dcids,
                          int security_level, bool retry) {
    struct hci_conn hcon = {.sec_level = security_level};
    struct l2cap_conn conn = {.hcon = &hcon};
    struct l2cap_ops ops = {.get_peer_pid = get_peer_pid};
    struct l2cap_chan channels[3] = {0};
    disconnect_target = NULL;
    request_ident = 7;
    security_calls = 0;
    conn.chan_l.count = 3;
    for (int index = 0; index < 3; index++) {
        channels[index] = (struct l2cap_chan){.conn = &conn, .ops = &ops,
            .flags = index == 2 ? 0 : 1ul << FLAG_DEFER_SETUP, .scid = 64 + index,
            .psm = 39, .imtu = 64, .mps = 64, .mode = L2CAP_MODE_EXT_FLOWCTL, .state = BT_CONNECT};
        conn.chan_l.items[index] = &channels[index];
    }
    l2cap_ecred_connect(&channels[2]);
    assert(sent_count == 3 && sent_scids[0] == 66 && sent_scids[1] == 64 && sent_scids[2] == 65);
    u16 storage[] = {64, 64, 10, result, 0, 0, 0};
    struct l2cap_ecred_conn_rsp *response = (void *)storage;
    for (int index = 0; index < slots; index++) { response->dcid[index] = dcids[index]; }
    struct l2cap_cmd_hdr command = {.ident = 8};
    assert(l2cap_ecred_conn_rsp(&conn, &command, 8 + slots * 2, (u8 *)response) == 0);
    for (int index = 0; index < 3; index++) {
        assert(channels[index].state == BT_CONNECT && !channels[index].deleted && !channels[index].dcid);
    }
    command.ident = 7;
    assert(l2cap_ecred_conn_rsp(&conn, &command, 7, (u8 *)response) == -EPROTO);
    assert(l2cap_ecred_conn_rsp(&conn, &command, 8 + slots * 2, (u8 *)response) == 0);
    for (int index = 0; index < 3; index++) {
        int position = index;
        if (PROPOSED) {
            for (int wire_index = 0; wire_index < 3; wire_index++) {
                if (sent_scids[wire_index] == channels[index].scid) { position = wire_index; }
            }
            assert(channels[index].ecred_tx_index == position);
        }
        bool refused = position >= slots || result == L2CAP_CR_LE_BAD_PSM ||
            ((result == L2CAP_CR_LE_AUTHENTICATION || result == L2CAP_CR_LE_ENCRYPTION) ?
                security_level > BT_SECURITY_MEDIUM : !dcids[position]);
        assert(!!channels[index].deleted == refused);
        if (refused) { assert(channels[index].delete_error == ECONNREFUSED); }
        else if (retry) {
            assert(channels[index].state == BT_CONNECT);
            assert(!test_bit(FLAG_ECRED_CONN_REQ_SENT, &channels[index].flags));
        } else {
            assert(channels[index].state == BT_CONNECTED);
            assert(channels[index].dcid == dcids[position]);
        }
    }
    if (retry) {
        assert(security_calls == 3);
        request_ident = 8;
        for (int index = 0; index < 3; index++) { channels[index].flags |= 1ul << FLAG_DEFER_SETUP; }
        channels[1].ecred_tx_index = 99;
        l2cap_ecred_connect(&channels[1]);
        assert(channels[1].ident == 7);
        clear_bit(FLAG_DEFER_SETUP, &channels[1].flags);
        l2cap_ecred_connect(&channels[1]);
        assert(sent_count == 1 && sent_scids[0] == 65);
        if (PROPOSED) { assert(channels[1].ecred_tx_index == 0); }
        response->result = 0;
        for (int index = 0; index < 3; index++) { response->dcid[index] = 90 + index; }
        assert(l2cap_ecred_conn_rsp(&conn, &command, sizeof(storage), (u8 *)response) == 0);
        assert(channels[1].state == BT_CONNECT);
        assert(channels[0].state == (PROPOSED ? BT_CONNECT : BT_CONNECTED));
        assert(channels[2].state == (PROPOSED ? BT_CONNECT : BT_CONNECTED));
        command.ident = 8;
        for (int index = 0; index < 3; index++) { response->dcid[index] = 80 + index; }
        assert(l2cap_ecred_conn_rsp(&conn, &command, sizeof(storage), (u8 *)response) == 0);
        for (int index = 0; index < sent_count; index++) {
            struct l2cap_chan *channel = &channels[sent_scids[index] - 64];
            assert(channel->dcid == 80 + index);
        }
        request_ident = 7;
    }
    printf("response_case=%s passed\n", name);
}
static void grouping_case(int exclusion) {
    struct hci_conn hcon = {0};
    struct l2cap_conn conn = {.hcon = &hcon};
    struct l2cap_ops ops = {.get_peer_pid = get_peer_pid};
    struct pid different_peer = {0};
    struct l2cap_chan channels[2] = {0};
    disconnect_target = NULL;
    request_ident = 7;
    conn.chan_l.count = 2;
    for (int index = 0; index < 2; index++) {
        channels[index] = (struct l2cap_chan){.conn = &conn, .ops = &ops,
            .flags = 1ul << FLAG_DEFER_SETUP, .scid = 64 + index, .ecred_tx_index = 99,
            .psm = 39, .imtu = 64, .mps = 64, .mode = L2CAP_MODE_EXT_FLOWCTL, .state = BT_CONNECT};
        conn.chan_l.items[index] = &channels[index];
    }
    switch (exclusion) {
    case 0: channels[0].peer = &different_peer; break;
    case 1: channels[0].psm = 40; break;
    case 2: channels[0].ident = 9; break;
    case 3: channels[0].mode = 0; break;
    case 4: channels[0].state = BT_CONNECTED; break;
    case 5: channels[0].flags |= 1ul << FLAG_ECRED_CONN_REQ_SENT; break;
    case 6: channels[0].flags = 0; break;
    }
    sent_count = -1;
    l2cap_ecred_connect(&channels[1]);
    assert(sent_count == -1);
    clear_bit(FLAG_DEFER_SETUP, &channels[1].flags);
    l2cap_ecred_connect(&channels[1]);
    assert(sent_count == 1 && sent_scids[0] == 65);
    assert(channels[0].ecred_tx_index == 99);
    if (PROPOSED) { assert(channels[1].ecred_tx_index == 0); }
    sent_count = -1;
    l2cap_ecred_connect(&channels[1]);
    assert(sent_count == -1);
    u16 response[] = {64, 64, 10, 0, 80};
    struct l2cap_cmd_hdr command = {.ident = 7};
    assert(l2cap_ecred_conn_rsp(&conn, &command, sizeof(response), (u8 *)response) == 0);
    assert(channels[1].dcid == 80 && channels[1].state == BT_CONNECTED);
    assert(channels[0].ecred_tx_index == 99 && !channels[0].dcid);
    channels[1] = (struct l2cap_chan){.conn = &conn, .ops = &ops, .scid = 65,
        .ecred_tx_index = 99, .psm = 39, .imtu = 64, .mps = 64,
        .mode = L2CAP_MODE_EXT_FLOWCTL, .state = BT_CONNECT};
    request_ident = 8;
    l2cap_ecred_connect(&channels[1]);
    assert(sent_count == 1 && sent_scids[0] == 65);
    response[4] = 81;
    assert(l2cap_ecred_conn_rsp(&conn, &command, sizeof(response), (u8 *)response) == 0);
    assert(!channels[1].dcid && channels[1].state == BT_CONNECT);
    command.ident = 8;
    assert(l2cap_ecred_conn_rsp(&conn, &command, sizeof(response), (u8 *)response) == 0);
    assert(channels[1].dcid == 81 && channels[1].state == BT_CONNECTED);
    if (PROPOSED) { assert(channels[1].ecred_tx_index == 0); }
    printf("grouping_exclusion=%d reuse=passed\n", exclusion);
}
static void duplicate_case(void) {
    struct hci_conn hcon = {0};
    struct l2cap_conn conn = {.hcon = &hcon};
    struct l2cap_ops ops = {.get_peer_pid = get_peer_pid};
    struct l2cap_chan channels[2] = {0};
    disconnect_target = NULL;
    request_ident = 7;
    conn.chan_l.count = 2;
    for (int index = 0; index < 2; index++) {
        channels[index] = (struct l2cap_chan){.conn = &conn, .ops = &ops,
            .flags = index ? 1ul << FLAG_DEFER_SETUP : 0, .scid = 64 + index,
            .psm = 39, .imtu = 64, .mps = 64, .mode = L2CAP_MODE_EXT_FLOWCTL, .state = BT_CONNECT};
        conn.chan_l.items[index] = &channels[index];
    }
    l2cap_ecred_connect(&channels[0]);
    u16 response[] = {64, 64, 10, 0, 80, 80};
    struct l2cap_cmd_hdr command = {.ident = 7};
    assert(l2cap_ecred_conn_rsp(&conn, &command, sizeof(response), (u8 *)response) == 0);
    assert(channels[0].deleted && channels[0].delete_error == ECONNRESET);
    assert(channels[1].deleted && channels[1].delete_error == ECONNREFUSED);
    puts("duplicate-dcid=passed");
}
static void identifier_reuse_case(void) {
    struct hci_conn hcon = {0};
    struct l2cap_conn conn = {.hcon = &hcon, .tx_ident = 6};
    struct l2cap_ops ops = {.get_peer_pid = get_peer_pid};
    struct l2cap_chan channels[2] = {0};
    disconnect_target = NULL;
    request_ident = 7;
    allocate_identifiers = true;
    conn.chan_l.count = 2;
    for (int index = 0; index < 2; index++) {
        channels[index] = (struct l2cap_chan){.conn = &conn, .ops = &ops, .scid = 64 + index,
            .psm = 39, .imtu = 64, .mps = 64, .mode = L2CAP_MODE_EXT_FLOWCTL, .state = BT_CONNECT};
        conn.chan_l.items[index] = &channels[index];
    }
    for (int index = 0; index < 2; index++) {
        l2cap_ecred_connect(&channels[index]);
        assert(sent_count == 1 && sent_scids[0] == 64 + index && channels[index].ident == 7);
        if (!index) {
            for (int allocation = 0; allocation < 127; allocation++) {
                assert(l2cap_get_ident(&conn) != 7);
            }
            assert(channels[0].state == BT_CONNECT && channels[0].ident == 7 && conn.tx_ident == 6);
        }
    }
    u16 response[] = {64, 64, 10, 0, 80};
    struct l2cap_cmd_hdr command = {.ident = 7};
    assert(l2cap_ecred_conn_rsp(&conn, &command, sizeof(response), (u8 *)response) == 0);
    assert(channels[0].dcid == 80);
    assert(channels[1].deleted);
    assert(channels[0].state == BT_CONNECTED && !channels[0].deleted);
    assert(channels[1].delete_error == ECONNREFUSED);
    allocate_identifiers = false;
    printf("identifier-reuse-isolation=NOT_SATISFIED proposed=%d collateral-regression=0 allocator-wrap=128\n", PROPOSED);
}
int main(void) {
    run_case(1, 0, false);
    run_case(2, 0, false);
    run_case(2, 1, true);
    run_case(3, 2, true);
    pending_removal_case();
    run_case(3, 1, true);
    run_case(4, 3, true);
    run_case(5, 4, true);
    const u16 accepted[] = {80, 81, 82};
    const u16 partial[] = {80, 0, 82};
    const u16 rejected[] = {0, 0, 0};
    response_case("partial-zero", 4, 3, partial, 0, false);
    response_case("all-zero", 4, 3, rejected, 0, false);
    response_case("short-array", 0, 1, accepted, 0, false);
    response_case("empty-rejection", L2CAP_CR_LE_BAD_PSM, 0, rejected, 0, false);
    response_case("bad-psm", L2CAP_CR_LE_BAD_PSM, 3, rejected, 0, false);
    response_case("authentication-retry", L2CAP_CR_LE_AUTHENTICATION, 3, rejected, 0, true);
    response_case("encryption-retry", L2CAP_CR_LE_ENCRYPTION, 3, rejected, 0, true);
    response_case("authentication-exhausted", L2CAP_CR_LE_AUTHENTICATION, 3, rejected, 3, false);
    for (int exclusion = 0; exclusion < 7; exclusion++) { grouping_case(exclusion); }
    duplicate_case();
    reverse_list = true;
    run_case(3, 0, true);
    identifier_reuse_case();
    return 0;
}
'''


def program(source: bytes, proposed: bool = False, header: bytes | None = None) -> str:
    """Reject changed source before extracting the complete controlling functions."""
    if hashlib.sha256(source).hexdigest() != SOURCE_SHA256:
        raise ValueError('Kernel source does not match the package-named revision')
    if proposed:
        if header is None or hashlib.sha256(header).hexdigest() != HEADER_SHA256:
            raise ValueError('Kernel header does not match the package-named revision')
        patch = Path(__file__).resolve().parents[1] / 'patches/ecred-request-index.patch'
        with tempfile.TemporaryDirectory(prefix='ecred-patch-', dir='/dev/shm') as directory:
            kernel = Path(directory) / 'net/bluetooth/l2cap_core.c'
            kernel.parent.mkdir(parents=True)
            kernel.write_bytes(source)
            channel_header = Path(directory) / 'include/net/bluetooth/l2cap.h'
            channel_header.parent.mkdir(parents=True)
            channel_header.write_bytes(header)
            subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-d', directory, '-i', str(patch)],
                check=True, capture_output=True, text=True)
            assert '__u8\t\tecred_tx_index;' in channel_header.read_text()
            source = kernel.read_bytes()
    text = source.decode()
    allocator_start = text.index('static u8 l2cap_get_ident(')
    allocator = text[allocator_start:text.index('\n}', allocator_start) + 2]
    allocator = allocator.replace('l2cap_get_ident(', 'pinned_l2cap_get_ident(', 1)
    grouping = text[text.index('struct l2cap_ecred_conn_data {'):text.index('\nstatic void l2cap_le_start(')]
    response = text[text.index('static inline int l2cap_ecred_conn_rsp('):text.index('\nstatic inline int l2cap_ecred_reconf_req(')]
    disconnect = text[text.index('static inline int l2cap_disconnect_req('):text.index('\nstatic inline int l2cap_disconnect_rsp(')]
    return f'#define PROPOSED {int(proposed)}\n' + SHIM + allocator + grouping + response + disconnect + CASES


def negotiations(path: Path) -> list[dict]:
    """Validate only ordered ECRED metadata from the six historical captures."""
    records = json.loads(path.read_text())
    if sorted(row['attempt'] for row in records) != [2, 3, 5, 6, 7, 8]:
        raise ValueError('Expected exactly the six original attempts')
    result = []
    for record in records:
        events = [event for event in record['events'] if any(
            'Enhanced Credit Connection' in line for line in event['metadata'])]
        if len(events) != 2:
            raise ValueError('Expected one ECRED request and response')
        request, response = events
        if not any('Enhanced Credit Connection Request' in line for line in request['metadata']):
            raise ValueError('First event must be the ECRED request')
        if not any('Enhanced Credit Connection Response' in line for line in response['metadata']):
            raise ValueError('Second event must be the ECRED response')
        request_ident = re.search(r'ident (\d+) len 12$', request['metadata'][0])
        response_ident = re.search(r'ident (\d+) len 12$', response['metadata'][0])
        if not request_ident or not response_ident or request_ident[1] != response_ident[1]:
            raise ValueError('ECRED identifiers or lengths do not match')
        if request['direction'] != 'RX' or response['direction'] != 'TX':
            raise ValueError('Expected DUT request and controller response')
        if 'PSM: 39 (0x0027)' not in request['metadata']:
            raise ValueError('Expected the EATT PSM')
        if 'Result: Connection successful (0x0000)' not in response['metadata']:
            raise ValueError('Expected a successful ECRED response')
        if not 0 < request['frame'] < response['frame']:
            raise ValueError('ECRED frame order is invalid')
        source = [int(match[1]) for line in request['metadata']
            if (match := re.search(r'Source CID: (\d+)', line))]
        destination = [int(match[1]) for line in response['metadata']
            if (match := re.search(r'Destination CID: (\d+)', line))]
        if source != [65, 64] or destination != [64, 65]:
            raise ValueError('Historical ordered CID pair differs from the native probe')
        result.append({'attempt': record['attempt'], 'request_frame': request['frame'],
            'response_frame': response['frame'], 'scids': source, 'dcids': destination})
    return result


def decode_teardowns(content: bytes) -> list[dict]:
    """Extract only complete disconnect fields from Bluetooth Monitor snoops."""
    if len(content) < 16 or content[:8] != b'btsnoop\0' or struct.unpack_from('>II', content, 8) != (1, 2001):
        raise ValueError('Expected version 1 Bluetooth Monitor snoop, not H4')
    offset, frame = 16, 0
    result = []
    while offset < len(content):
        if len(content) - offset < 24:
            raise ValueError('Truncated snoop record header')
        original, included, flags, drops, timestamp = struct.unpack_from('>IIIIQ', content, offset)
        offset += 24
        if included != original or included > len(content) - offset or drops:
            raise ValueError('Incomplete capture record or recorded drops')
        packet = content[offset:offset + included]
        offset += included
        frame += 1
        opcode = flags & 0xffff
        if opcode not in (4, 5):
            continue
        if len(packet) < 4:
            raise ValueError('Truncated ACL header')
        handle_flags, acl_length = struct.unpack_from('<HH', packet)
        if acl_length != len(packet) - 4:
            raise ValueError('ACL length mismatch')
        if (handle_flags >> 12) & 3 == 1:
            continue
        if len(packet) < 8:
            raise ValueError('Truncated L2CAP header')
        length, cid = struct.unpack_from('<HH', packet, 4)
        if cid != 5:
            continue
        if length != len(packet) - 8:
            raise ValueError('This probe requires complete unfragmented LE signaling')
        command_offset = 8
        while command_offset < len(packet):
            if len(packet) - command_offset < 4:
                raise ValueError('Truncated signaling command header')
            code, ident, command_length = struct.unpack_from('<BBH', packet, command_offset)
            command_offset += 4
            if command_length > len(packet) - command_offset:
                raise ValueError('Truncated signaling command')
            if code in (6, 7):
                if command_length != 4:
                    raise ValueError('Unexpected disconnect command length')
                dcid, scid = struct.unpack_from('<HH', packet, command_offset)
                seconds, microseconds = divmod(timestamp - 0x00E03AB44A676000, 1000000)
                utc = datetime.fromtimestamp(seconds + 946684800, timezone.utc).replace(microsecond=microseconds)
                result.append({'frame': frame, 'utc': utc.isoformat(), 'direction': 'TX' if opcode == 4 else 'RX',
                    'adapter': flags >> 16, 'handle': handle_flags & 0x0fff, 'code': code,
                    'ident': ident, 'dcid': dcid, 'scid': scid})
            command_offset += command_length
    return result


def historical_teardowns(root: Path) -> list[dict]:
    """Check the exact six original request/response signatures without values."""
    expected = {2: (161, 167, 10), 3: (91, 103, 4), 5: (88, 100, 4),
        6: (92, 105, 4), 7: (82, 94, 4), 8: (84, 97, 4)}
    result = []
    for attempt, (request_frame, response_frame, ident) in expected.items():
        content = (root / f'wifi-primary-smokes-01-a{attempt:02}/pi/hci.btsnoop').read_bytes()
        events = decode_teardowns(content)
        request = [event for event in events if event['frame'] == request_frame]
        response = [event for event in events if event['frame'] == response_frame]
        if len(request) != 1 or len(response) != 1:
            raise ValueError('Expected exactly one original teardown command in each selected frame')
        for event, direction, code, scid in ((request[0], 'TX', 6, 64), (response[0], 'RX', 7, 65)):
            fields = tuple(event[key] for key in ('direction', 'adapter', 'handle', 'code', 'ident', 'dcid', 'scid'))
            if fields != (direction, 0, 64, code, ident, 65, scid):
                raise ValueError('Original teardown signature does not match')
        result.append({'attempt': attempt, 'capture_sha256': hashlib.sha256(content).hexdigest(),
            'request': request[0], 'response': response[0]})
    return result


def check_teardown_decoder() -> None:
    """Require typed positive controls and reject malformed or incomplete input."""
    header = struct.pack('>8sII', b'btsnoop\0', 1, 2001)
    packet = struct.pack('<HHHHBBHHH', 0x2040, 12, 8, 5, 6, 7, 4, 65, 64)

    def record(payload: bytes, flags: int = 4, original: int | None = None, drops: int = 0) -> bytes:
        return struct.pack('>IIIIQ', len(payload) if original is None else original,
            len(payload), flags, drops, 0x00E03AB44A676000) + payload

    expected = {'frame': 2, 'utc': '2000-01-01T00:00:00+00:00', 'direction': 'TX',
        'adapter': 0, 'handle': 64, 'code': 6, 'ident': 7, 'dcid': 65, 'scid': 64}
    valid = header + record(b'PRIVATE_VALUE_MUST_NOT_EXPORT', flags=12) + record(packet)
    assert decode_teardowns(valid) == [expected]
    assert 'PRIVATE_VALUE' not in json.dumps(decode_teardowns(valid))
    response = packet[:8] + struct.pack('<BBHHH', 7, 7, 4, 65, 65)
    assert decode_teardowns(header + record(response, flags=(2 << 16) | 5)) == [
        dict(expected, frame=1, direction='RX', adapter=2, code=7, scid=65)]
    malformed = [b'btsnoop', header[:12] + struct.pack('>I', 1002), valid[:-1], header + b'123',
        header + record(packet, original=len(packet) + 1), header + record(packet, drops=1),
        header + record(b'123'), header + record(packet[:2] + struct.pack('<H', 11) + packet[4:]),
        header + record(packet[:4] + struct.pack('<H', 9) + packet[6:]),
        header + record(packet[:10] + struct.pack('<H', 5) + packet[12:]),
        header + record(packet[:10] + struct.pack('<H', 3) + packet[12:])]
    for content in malformed:
        try:
            decode_teardowns(content)
        except ValueError:
            continue
        raise AssertionError('Malformed monitor record was accepted')


def kernel_check(source: bytes, build: Path) -> str:
    """Compile actual pinned objects against the matching native Pi prepared headers."""
    release = '6.12.47+rpt-rpi-2712'
    if os.uname().machine != 'aarch64' or os.uname().release != release:
        raise ValueError('Native matching Raspberry Pi kernel required')
    if hashlib.sha256(source).hexdigest() != SOURCE_SHA256:
        raise ValueError('Kernel source hash mismatch')
    if shutil.disk_usage('/dev/shm').free < 1024**3:
        raise ValueError('RAM-only compile requires at least 1 GiB free tmpfs')
    available = re.search(r'^MemAvailable:\s+(\d+) kB$', Path('/proc/meminfo').read_text(), re.M)
    if not available or int(available.group(1)) * 1024 < 2 * 1024**3:
        raise ValueError('RAM-only compile requires at least 2 GiB available memory')
    boot_config = Path('/boot/config-' + release).read_bytes()
    if hashlib.sha256(boot_config).hexdigest() != 'b87716441ed8c1c5906418037569c76be8ed2fe01bcf220b55abd6faeae08f0f':
        raise ValueError('Boot config hash mismatch')
    prepared_config = (build / '.config').read_bytes()
    if hashlib.sha256(prepared_config).hexdigest() != '9bb549d81cc44c5420e50027882088ba83e862013e976f10f976901255c7c4fc':
        raise ValueError('Prepared config hash mismatch')
    files = {'net/bluetooth/l2cap_core.c': source}
    pending = ['include/net/bluetooth/l2cap.h', 'net/bluetooth/l2cap_sock.c']
    pending += ['net/bluetooth/' + name.decode() for name in re.findall(rb'^#include "([^"]+)"', source, re.M)]
    while pending:
        name = pending.pop()
        if name in files:
            continue
        if '..' in name or not name.startswith(('net/bluetooth/', 'include/net/bluetooth/')):
            raise ValueError('Unexpected local kernel include')
        with urllib.request.urlopen(f'https://raw.githubusercontent.com/raspberrypi/linux/{REVISION}/{name}', timeout=30) as stream:
            files[name] = stream.read(1000000)
        pending += [str(Path(name).parent / relative.decode()) for relative in re.findall(rb'^#include "([^"]+)"', files[name], re.M)]
    if hashlib.sha256(files['include/net/bluetooth/l2cap.h']).hexdigest() != HEADER_SHA256:
        raise ValueError('Kernel header hash mismatch')

    def limits() -> None:
        os.nice(19)
        resource.setrlimit(resource.RLIMIT_AS, (1024**3, 1024**3))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    records = []
    with tempfile.TemporaryDirectory(prefix='ecred-kbuild-', dir='/dev/shm') as directory:
        for variant in ('original', 'proposed'):
            work = Path(directory) / variant
            work.mkdir()
            for name, data in files.items():
                destination = work / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(data)
            if variant == 'proposed':
                subprocess.run(['patch', '--batch', '--fuzz=0', '-p1'], cwd=work,
                    input=Path(__file__).resolve().parents[1].joinpath('patches/ecred-request-index.patch').read_bytes(),
                    check=True, capture_output=True)
            for name in files:
                if name.startswith('net/bluetooth/'):
                    shutil.copyfile(work / name, work / Path(name).name)
            (work / 'Makefile').write_text('obj-m := ecred_qualification.o\n'
                'ecred_qualification-y := l2cap_core.o l2cap_sock.o layout.o\n'
                'LINUXINCLUDE := -I$(src)/include $(LINUXINCLUDE)\n')
            fields = ['ident', 'conf_req', 'conf_len', 'flags']
            (work / 'layout.c').write_text('#include <linux/module.h>\n#include <net/bluetooth/bluetooth.h>\n'
                '#include <net/bluetooth/hci_core.h>\n#include <net/bluetooth/l2cap.h>\n'
                'unsigned long ecred_layout[] = {sizeof(struct l2cap_chan), ' +
                ', '.join(f'offsetof(struct l2cap_chan, {field})' for field in fields) + '};\n')
            command = ['make', '-C', str(build), 'M=' + str(work), '-j1', 'V=1', 'l2cap_core.o', 'l2cap_sock.o', 'layout.o']
            result = subprocess.run(command, text=True, capture_output=True, timeout=180, preexec_fn=limits)
            result.check_returncode()
            compile_commands = {}
            for name in ('l2cap_core', 'l2cap_sock', 'layout'):
                dependency = (work / ('.' + name + '.o.cmd')).read_text()
                if str(work / 'include/net/bluetooth/l2cap.h') not in dependency:
                    raise AssertionError('Object did not use the private exact header')
                compile_commands[name] = next(line for line in dependency.splitlines() if line.startswith('savedcmd_')).replace(str(work), '$WORK')
            subprocess.run(['objcopy', '-O', 'binary', '--only-section=.data', str(work / 'layout.o'), str(work / 'layout.bin')],
                check=True, capture_output=True)
            layout = struct.unpack('<5Q', (work / 'layout.bin').read_bytes())
            records.append({'variant': variant, 'compile_exit': result.returncode, 'stderr': result.stderr,
                'layout': dict(zip(['sizeof_l2cap_chan'] + ['offset_' + field for field in fields], layout)),
                'real_header_verified': True, 'compile_commands': compile_commands})
        generated_bytes = sum(path.stat().st_size for path in Path(directory).rglob('*') if path.is_file())
    return json.dumps({'kernel': release, 'compiled_not_linked_or_loaded': True, 'records': records,
        'generated_bytes_removed': generated_bytes,
        'source_hashes': {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}}, sort_keys=True) + '\n'


def check(source: bytes, compiler: str, sanitize: bool = False) -> str:
    """Compile the pinned functions with ordered-list stubs, not a kernel or BlueZ."""
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    check_teardown_decoder()
    native = program(source)
    with urllib.request.urlopen(HEADER_URL, timeout=30) as stream:
        header = stream.read(100000)
    try:
        program(source, proposed=True, header=header + b'\n')
    except ValueError:
        pass
    else:
        raise AssertionError('Changed header was accepted')
    try:
        program(source + b'\n')
    except ValueError:
        pass
    else:
        raise AssertionError('Changed source was accepted')
    flags = ['-std=gnu11', '-Wall', '-Wextra', '-Werror']
    if sanitize:
        flags += ['-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-fno-omit-frame-pointer', '-g']
    runtime = os.environ.copy()
    sanitizer_options = {'ASAN_OPTIONS': 'detect_leaks=1:halt_on_error=1', 'UBSAN_OPTIONS': 'halt_on_error=1:print_stacktrace=1'} if sanitize else {}
    runtime.update(sanitizer_options)
    executions = []
    with tempfile.TemporaryDirectory(prefix='ecred-order-', dir='/dev/shm') as directory:
        def execute(name: str, content: str) -> subprocess.CompletedProcess:
            binary = str(Path(directory) / name)
            compiled = subprocess.run([compiler, *flags, '-x', 'c', '-', '-o', binary],
                input=content, text=True, check=True, capture_output=True)
            result = subprocess.run([binary], text=True, capture_output=True, env=runtime)
            findings = bool(re.search(r'AddressSanitizer|UndefinedBehaviorSanitizer|runtime error:', result.stderr))
            scenarios = len(re.findall(r'^(?:count=|pending_removed_wrong_peer=|response_case=|'
                r'grouping_exclusion=|duplicate-dcid=|identifier-reuse-isolation=)', result.stdout, re.M))
            executions.append({'variant': name, 'translation_unit_sha256': hashlib.sha256(content.encode()).hexdigest(),
                'compile_exit': compiled.returncode, 'executed': True, 'run_exit': result.returncode,
                'sanitizer_findings': findings, 'reported_scenarios': scenarios})
            if findings:
                raise AssertionError(f'{name}: sanitizer findings: {result.stderr}')
            return result

        original_run = execute('original', native)
        original_run.check_returncode()
        output = original_run.stdout
        proposed = program(source, proposed=True, header=header)
        proposed_run = execute('proposed', proposed)
        proposed_run.check_returncode()
        corrected = proposed_run.stdout
        if any(record['reported_scenarios'] != 26 for record in executions):
            raise AssertionError('Expected all 26 diagnostic scenarios in each positive variant')
        if any('identifier-reuse-isolation=NOT_SATISFIED' not in result.stdout
                for result in (original_run, proposed_run)):
            raise AssertionError('Missing pending-identifier collision qualification result')
        negative = execute('original-with-corrective-assertions', native.replace('#define PROPOSED 0', '#define PROPOSED 1', 1))
        if negative.returncode == 0 or 'mismatch == expect_mismatch' not in negative.stderr:
            raise AssertionError('Uncorrected source did not fail the corrective assertion after execution')
        unguarded = proposed.replace('\tunsigned long dcid_used = 0;\n', '', 1)
        unguarded = unguarded.replace(' ||\n\t\t    test_and_set_bit(chan->ecred_tx_index, &dcid_used)', '', 1)
        if unguarded == proposed or 'dcid_used' in unguarded:
            raise AssertionError('Collision negative control did not remove exactly the response-slot guard')
        collision_negative = execute('unguarded-index-with-collision-assertions', unguarded)
        if collision_negative.returncode == 0 or 'channels[0].state == BT_CONNECTED && !channels[0].deleted' not in collision_negative.stderr:
            raise AssertionError('Unguarded proposal did not fail the collateral regression after execution')
    if 'count=2 trigger=65 mismatch=1 request=65,64 assignments=64:64,65:65' not in output:
        raise AssertionError('Native probe did not reproduce the predicted assignment')
    if 'disconnect_request=65:64 disconnect_response=65:65 association_mismatch=1' not in output:
        raise AssertionError('Native probe did not reproduce the historical teardown fields')
    if 'association_mismatch=1' in corrected or 'mismatch=1' in corrected:
        raise AssertionError('Proposed correction still misassigns positional pairs')
    if 'disconnect_request=65:64 disconnect_response=65:64 association_mismatch=0' not in corrected:
        raise AssertionError('Proposed correction did not repair the historical teardown signature')
    return ('ORIGINAL\n' + output + 'PROPOSED (not deployed)\n' + corrected +
        'NEGATIVE CONTROL: uncorrected source compiled, executed, rejected by corrective assertion\n' +
        json.dumps({'compiler': compiler, 'compiler_flags': flags, 'sanitized': sanitize,
            'compiler_version': subprocess.check_output([compiler, '--version'], text=True).splitlines()[0],
            'sanitizer_options': sanitizer_options,
            'identifier_reuse_isolation': 'NOT_SATISFIED', 'collision_collateral_regression': False,
            'production_qualified': False,
            'kernel_source_sha256': SOURCE_SHA256, 'kernel_header_sha256': HEADER_SHA256,
            'executions': executions}, sort_keys=True) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, help='Use a local hash-matching kernel source instead of HTTPS')
    parser.add_argument('--compiler', default='cc')
    parser.add_argument('--sanitize', action='store_true', help='Run host variants with ASan and UBSan')
    parser.add_argument('--kernel-build', type=Path, help='Native Pi prepared headers: bounded RAM-only Kbuild instead of host stubs')
    parser.add_argument('--metadata', type=Path, help='Optional private value-free btmon reconstruction')
    parser.add_argument('--captures', type=Path, help='Optional original captures root; emit only teardown headers')
    args = parser.parse_args()
    if args.kernel_build and args.sanitize:
        parser.error('--sanitize is for host execution, not the native kernel object compile')
    if args.source:
        content = args.source.read_bytes()
    else:
        with urllib.request.urlopen(SOURCE_URL, timeout=30) as stream:
            content = stream.read(300000)
    try:
        print(kernel_check(content, args.kernel_build) if args.kernel_build else check(content, args.compiler, args.sanitize), end='')
    except subprocess.CalledProcessError as error:
        raise SystemExit(error.stderr or str(error)) from error
    if args.metadata:
        print(json.dumps({'historical_negotiations': negotiations(args.metadata)}, sort_keys=True))
    if args.captures:
        print(json.dumps({'historical_teardowns': historical_teardowns(args.captures)}, sort_keys=True))
    print('PASS: bounded kernel object compile' if args.kernel_build else
        'PASS: pinned-function host probe; not live kernel, socket, BlueZ, or corrective hardware validation')
