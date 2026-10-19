"""Execute pinned kernel ECRED functions with host stubs, never a live fixture."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import urllib.request


REVISION = '359f37f0faefb712add32a39f98751aea67d5c1f'
SOURCE_SHA256 = '40b71702ffee7a0e47d3f3c12861d3fc1cb235a67fa3e1bd3407fd56a860aaa8'
SOURCE_URL = f'https://raw.githubusercontent.com/raspberrypi/linux/{REVISION}/net/bluetooth/l2cap_core.c'

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
#define L2CAP_CR_LE_AUTHENTICATION 5
#define L2CAP_CR_LE_ENCRYPTION 8
#define L2CAP_CR_LE_BAD_PSM 2
#define BT_SECURITY_MEDIUM 2
struct pid { int unused; };
struct hci_conn { int sec_level; };
struct l2cap_chan;
struct channel_list { struct l2cap_chan *items[5]; int count; };
struct l2cap_conn { struct channel_list chan_l; struct hci_conn *hcon; };
struct l2cap_ops { struct pid *(*get_peer_pid)(struct l2cap_chan *); };
struct l2cap_chan {
    struct l2cap_conn *conn;
    struct l2cap_ops *ops;
    unsigned long flags;
    u16 scid, dcid, psm, imtu, mps, rx_credits, omtu, remote_mps, tx_credits;
    int ident, mode, state, sec_level;
};
struct l2cap_ecred_conn_req_hdr { u16 psm, mtu, mps, credits; };
struct l2cap_ecred_conn_rsp { u16 mtu, mps, credits, result, dcid[]; };
struct l2cap_cmd_hdr { u8 ident; };
static struct pid peer_pid;
static u16 sent_scids[5];
static int sent_count;
static struct pid *get_peer_pid(struct l2cap_chan *chan) { (void)chan; return &peer_pid; }
static int test_bit(int bit, unsigned long *flags) { return !!(*flags & (1ul << bit)); }
static int test_and_clear_bit(int bit, unsigned long *flags) {
    int result = test_bit(bit, flags); *flags &= ~(1ul << bit); return result;
}
static int test_and_set_bit(int bit, unsigned long *flags) {
    int result = test_bit(bit, flags); *flags |= 1ul << bit; return result;
}
static void clear_bit(int bit, unsigned long *flags) { *flags &= ~(1ul << bit); }
static void l2cap_ecred_init(struct l2cap_chan *chan, u16 credits) { (void)chan; (void)credits; }
static u8 l2cap_get_ident(struct l2cap_conn *conn) { (void)conn; return 7; }
static void __l2cap_chan_list(struct l2cap_conn *conn,
    void (*callback)(struct l2cap_chan *, void *), void *data) {
    for (int index = 0; index < conn->chan_l.count; index++) {
        callback(conn->chan_l.items[index], data);
    }
}
static void l2cap_send_cmd(struct l2cap_conn *conn, u8 ident, u8 code, u16 length, void *data) {
    (void)conn; assert(ident == 7); assert(code == L2CAP_ECRED_CONN_REQ);
    sent_count = (length - sizeof(struct l2cap_ecred_conn_req_hdr)) / sizeof(u16);
    assert(sent_count > 0 && sent_count <= 5);
    memcpy(sent_scids, (u8 *)data + sizeof(struct l2cap_ecred_conn_req_hdr), sent_count * sizeof(u16));
}
#define list_for_each_entry_safe(entry, next, head, member) \
    for (int channel_index = 0; channel_index < (head)->count && \
        ((entry) = (head)->items[channel_index], (next) = (entry), (void)(next), 1); channel_index++)
static void l2cap_chan_lock(struct l2cap_chan *chan) { (void)chan; }
static void l2cap_chan_unlock(struct l2cap_chan *chan) { (void)chan; }
static void l2cap_chan_del(struct l2cap_chan *chan, int error) { (void)chan; (void)error; assert(0); }
static void l2cap_chan_ready(struct l2cap_chan *chan) { chan->state = BT_CONNECTED; }
static void smp_conn_security(struct hci_conn *conn, int level) { (void)conn; (void)level; assert(0); }
static struct l2cap_chan *__l2cap_get_chan_by_dcid(struct l2cap_conn *conn, u16 dcid) {
    for (int index = 0; index < conn->chan_l.count; index++) {
        if (conn->chan_l.items[index]->dcid == dcid) { return conn->chan_l.items[index]; }
    }
    return NULL;
}
'''

CASES = r'''
static void run_case(int count, int trigger, bool expect_mismatch) {
    struct hci_conn hcon = {0};
    struct l2cap_conn conn = {.hcon = &hcon};
    struct l2cap_ops ops = {.get_peer_pid = get_peer_pid};
    struct l2cap_chan channels[5] = {0};
    conn.chan_l.count = count;
    for (int index = 0; index < count; index++) {
        channels[index] = (struct l2cap_chan){.conn = &conn, .ops = &ops,
            .flags = index == trigger ? 0 : 1ul << FLAG_DEFER_SETUP,
            .scid = 64 + index, .psm = 39, .imtu = 64, .mps = 64,
            .mode = L2CAP_MODE_EXT_FLOWCTL, .state = BT_CONNECT};
        conn.chan_l.items[index] = &channels[index];
    }
    l2cap_ecred_connect(&channels[trigger]);
    assert(sent_count == count);
    assert(sent_scids[0] == 64 + trigger);
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
}
int main(void) {
    run_case(1, 0, false);
    run_case(2, 0, false);
    run_case(2, 1, true);
    run_case(3, 2, true);
    return 0;
}
'''


def program(source: bytes) -> str:
    """Reject changed source before extracting the complete controlling functions."""
    if hashlib.sha256(source).hexdigest() != SOURCE_SHA256:
        raise ValueError('Kernel source does not match the package-named revision')
    text = source.decode()
    grouping = text[text.index('struct l2cap_ecred_conn_data {'):text.index('\nstatic void l2cap_le_start(')]
    response = text[text.index('static inline int l2cap_ecred_conn_rsp('):text.index('\nstatic inline int l2cap_ecred_reconf_req(')]
    return SHIM + grouping + response + CASES


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


def check(source: bytes, compiler: str) -> str:
    """Compile the pinned functions with ordered-list stubs, not a kernel or BlueZ."""
    native = program(source)
    try:
        program(source + b'\n')
    except ValueError:
        pass
    else:
        raise AssertionError('Changed source was accepted')
    with tempfile.TemporaryDirectory(prefix='ecred-order-', dir='/dev/shm') as directory:
        binary = str(Path(directory) / 'probe')
        subprocess.run([compiler, '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-x', 'c', '-', '-o', binary],
            input=native, text=True, check=True, capture_output=True)
        output = subprocess.check_output([binary], text=True)
    if 'count=2 trigger=65 mismatch=1 request=65,64 assignments=64:64,65:65' not in output:
        raise AssertionError('Native probe did not reproduce the predicted assignment')
    return output


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, help='Use a local hash-matching kernel source instead of HTTPS')
    parser.add_argument('--compiler', default='cc')
    parser.add_argument('--metadata', type=Path, help='Optional private value-free btmon reconstruction')
    args = parser.parse_args()
    if args.source:
        content = args.source.read_bytes()
    else:
        with urllib.request.urlopen(SOURCE_URL, timeout=30) as stream:
            content = stream.read(300000)
    try:
        print(check(content, args.compiler), end='')
    except subprocess.CalledProcessError as error:
        raise SystemExit(error.stderr or str(error)) from error
    if args.metadata:
        print(json.dumps({'historical_negotiations': negotiations(args.metadata)}, sort_keys=True))
    print('PASS: pinned-function host probe; not live kernel, socket, BlueZ, or corrective hardware validation')
