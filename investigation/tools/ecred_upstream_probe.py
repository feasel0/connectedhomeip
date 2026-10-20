"""Exercise pinned current ECRED functions using the existing ordering cases."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import subprocess
import tempfile

import ecred_order_probe as previous


REVISION = '27731ba091954eccddb2657053b590d2113e8d98'
SOURCE_SHA256 = '3a879ac792f6f97245ed5ef93b1f8dd6ff0fd234b00f08ffcfdfe57f1460be77'
HEADER_SHA256 = '703a53f5573c9f1d99140f13d0d53009ee00561b059f1ded314fe0ff1777405f'

IDA = r'''
#define LE_LINK 1
#define L2CAP_ECRED_CONN_SCID_MAX 5
#define GFP_ATOMIC 0
#define READ_ONCE(value) (value)
#define WRITE_ONCE(target, value) ((target) = (value))
#define BT_ERR(...) ((void)0)
#define ARRAY_SIZE(array) ((int)(sizeof(array) / sizeof((array)[0])))
#define WARN_ON_ONCE(condition) (condition)
#define __must_hold(...)
#define lockdep_assert_held(...) ((void)0)
#define L2CAP_COMMAND_REJ 1
#define L2CAP_CONN_RSP 3
#define L2CAP_CONF_RSP 5
#define L2CAP_ECHO_RSP 9
#define L2CAP_INFO_RSP 11
#define L2CAP_CONN_PARAM_UPDATE_RSP 19
#define L2CAP_LE_CONN_RSP 21
#define L2CAP_ECRED_CONN_RSP 24
#define L2CAP_ECRED_RECONF_RSP 26
struct ida { bool used[256]; };
static int ida_alloc_range(struct ida *ida, unsigned int first,
                           unsigned int last, int flags) {
    (void)flags;
    for (unsigned int ident = first; ident <= last; ident++) {
        if (!ida->used[ident]) { ida->used[ident] = true; return ident; }
    }
    return -ENOSPC;
}
static int ida_find_first_range(struct ida *ida, unsigned int first,
                                unsigned int last) {
    for (unsigned int ident = first; ident <= last; ident++) {
        if (ida->used[ident]) { return ident; }
    }
    return -ENOENT;
}
static void ida_free(struct ida *ida, unsigned int ident) {
    assert(ida->used[ident]); ida->used[ident] = false;
}
'''

ALLOCATOR_CASE = r'''
static void identifier_reuse_case(void) {
    struct hci_conn hcon = {.type = LE_LINK};
    struct l2cap_conn conn = {.hcon = &hcon, .tx_ident = 6};
    struct l2cap_ops ops = {.get_peer_pid = get_peer_pid};
    struct l2cap_chan channels[2] = {0};
    disconnect_target = NULL;
    allocate_identifiers = true;
    conn.chan_l.count = 2;
    for (int index = 0; index < 2; index++) {
        channels[index] = (struct l2cap_chan){.conn = &conn, .ops = &ops,
            .scid = 64 + index, .psm = 39, .imtu = 64, .mps = 64,
            .mode = L2CAP_MODE_EXT_FLOWCTL, .state = BT_CONNECT};
        conn.chan_l.items[index] = &channels[index];
    }
    for (int index = 0; index < 2; index++) {
        l2cap_ecred_connect(&channels[index]);
        assert(sent_count == 1 && channels[index].ident == 7 + index);
    }
    for (int count = 0; count < 253; count++) {
        int ident = l2cap_get_ident(&conn);
        assert(ident > 0 && ident != 7 && ident != 8);
    }
    assert(l2cap_get_ident(&conn) == 0);
    u16 response[] = {64, 64, 10, 0, 80};
    struct l2cap_cmd_hdr command = {.ident = 7};
    l2cap_put_ident(&conn, L2CAP_ECRED_CONN_RSP, command.ident);
    assert(l2cap_ecred_conn_rsp(&conn, &command, sizeof(response), (u8 *)response) == 0);
    assert(channels[0].state == BT_CONNECTED && channels[0].dcid == 80);
    assert(channels[1].state == BT_CONNECT && !channels[1].deleted);
    assert(l2cap_get_ident(&conn) == 7);
    assert(l2cap_get_ident(&conn) == 0);
    allocate_identifiers = false;
    puts("identifier-ida-isolation=passed reservation-release-exhaustion");
}
'''

LIFETIME = r'''
static int response_holds;
static void l2cap_chan_hold(struct l2cap_chan *chan) {
    chan->test_holds++; response_holds++;
}
static void __set_chan_timer(struct l2cap_chan *chan, int timeout) {
    assert(timeout == 0); chan->test_timer = true;
}
static void l2cap_chan_put(struct l2cap_chan *chan) {
    if (chan->test_holds) { chan->test_holds--; response_holds--; return; }
    assert(chan == disconnect_target); disconnect_steps++;
}
'''

WRAPPER = r'''
static int l2cap_ecred_conn_rsp(struct l2cap_conn *conn,
                               struct l2cap_cmd_hdr *cmd, u16 length, u8 *data) {
    int result = pinned_response(conn, cmd, length, data);
    assert(response_holds == 0);
    for (int index = 0; index < conn->chan_l.count; index++) {
        struct l2cap_chan *chan = conn->chan_l.items[index];
        assert(chan->test_holds == 0);
        if (chan->test_timer) {
            chan->test_timer = false;
            l2cap_chan_del(chan, ECONNRESET);
        }
    }
    return result;
}
'''


def extract(text: str, start: str, end: str | None = None) -> str:
    """Extract one complete pinned function or adjacent function group."""
    position = text.index(start)
    return text[position:text.index(end, position) if end else text.index('\n}', position) + 2]


def program(source: bytes, header: bytes, proposed: bool) -> str:
    """Apply the reviewed target patch before extracting current functions."""
    if hashlib.sha256(source).hexdigest() != SOURCE_SHA256:
        raise ValueError('Unexpected upstream source')
    if hashlib.sha256(header).hexdigest() != HEADER_SHA256:
        raise ValueError('Unexpected upstream header')
    if proposed:
        patch = Path(__file__).resolve().parents[1] / 'patches/ecred-request-index-upstream.patch'
        with tempfile.TemporaryDirectory(prefix='upstream-ecred-') as directory:
            for name, content in [('net/bluetooth/l2cap_core.c', source), ('include/net/bluetooth/l2cap.h', header)]:
                path = Path(directory) / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
            subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-d', directory, '-i', str(patch)],
                           check=True, capture_output=True)
            source = (Path(directory) / 'net/bluetooth/l2cap_core.c').read_bytes()
    text = source.decode()
    shim = previous.SHIM.replace('struct hci_conn { int sec_level; };', 'struct hci_conn { int sec_level; int type; };')
    shim = shim.replace('struct pid { int unused; };', IDA + '\nstruct pid { int unused; };')
    shim = shim.replace('struct channel_list chan_l;', 'struct channel_list chan_l; struct ida tx_ida;')
    shim = shim.replace('int ident, mode, state, sec_level, deleted, delete_error;',
                        'int ident, mode, state, sec_level, deleted, delete_error, test_holds; bool test_timer;')
    shim = shim.replace('static u8 pinned_l2cap_get_ident', 'static int pinned_l2cap_get_ident')
    shim = shim.replace('static u8 l2cap_get_ident', 'static int l2cap_get_ident')
    shim = re.sub(r'static void l2cap_chan_put\(.*?\n', '', shim)
    shim = re.sub(r'static void mutex_(?:lock|unlock)\(.*?\n', '', shim)
    allocator = extract(text, 'static int l2cap_get_ident(').replace('l2cap_get_ident(', 'pinned_l2cap_get_ident(', 1)
    release = extract(text, 'static void l2cap_put_ident(')
    grouping = extract(text, 'struct l2cap_ecred_conn_data {', '\nstatic void l2cap_le_start(')
    response = extract(text, 'static inline int l2cap_ecred_conn_rsp(', '\nstatic inline int l2cap_ecred_reconf_req(')
    response = response.replace('l2cap_ecred_conn_rsp(', 'pinned_response(', 1)
    disconnect = extract(text, 'static inline int l2cap_disconnect_req(', '\nstatic inline int l2cap_disconnect_rsp(')
    cases = previous.CASES
    start = cases.index('static void identifier_reuse_case(')
    cases = cases[:start] + ALLOCATOR_CASE + cases[cases.index('int main(void)', start):]
    return f'#define PROPOSED {int(proposed)}\n' + shim + LIFETIME + allocator + release + grouping + response + WRAPPER + disconnect + cases


def main() -> None:
    """Compile normal/sanitized variants and require a compiling fail-before control."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--compiler', default='cc')
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    args.output.mkdir(mode=0o700, exist_ok=False)
    source = (args.baseline / 'net/bluetooth/l2cap_core.c').read_bytes()
    header = (args.baseline / 'include/net/bluetooth/l2cap.h').read_bytes()
    records = []
    for sanitize in (False, True):
        for proposed, negative in ((False, False), (True, False), (False, True)):
            name = ('proposed' if proposed else 'original') + ('-negative' if negative else '') + ('-sanitized' if sanitize else '')
            content = program(source, header, proposed)
            if negative:
                content = content.replace('#define PROPOSED 0', '#define PROPOSED 1', 1)
            translation = args.output / (name + '.c')
            translation.write_text(content)
            binary = args.output / name
            flags = ['-std=gnu11', '-Wall', '-Wextra', '-Werror', '-g']
            if sanitize:
                flags += ['-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-fno-omit-frame-pointer', '-no-pie']
            compiled = subprocess.run([args.compiler, *flags, str(translation), '-o', str(binary)], capture_output=True, text=True)
            (args.output / (name + '.compile.log')).write_text(compiled.stderr)
            if compiled.returncode:
                raise RuntimeError(compiled.stderr)
            environment = dict(os.environ, ASAN_OPTIONS='detect_leaks=1:halt_on_error=1', UBSAN_OPTIONS='halt_on_error=1')
            result = subprocess.run([str(binary)], capture_output=True, text=True, env=environment)
            (args.output / (name + '.run.log')).write_text(result.stdout + result.stderr)
            if negative:
                assert result.returncode != 0 and 'mismatch == expect_mismatch' in result.stderr
            else:
                assert result.returncode == 0, result.stderr
                assert len(re.findall(r'^(?:count=|pending_removed_wrong_peer=|response_case=|grouping_exclusion=|duplicate-dcid=|identifier-ida-isolation=)', result.stdout, re.M)) == 26
                assert 'identifier-ida-isolation=passed' in result.stdout
            assert not re.search(r'AddressSanitizer|runtime error:', result.stderr)
            records.append({'variant': name, 'compile_exit': compiled.returncode, 'run_exit': result.returncode,
                            'negative_control': negative, 'source_sha256': hashlib.sha256(content.encode()).hexdigest()})
    document = {'revision': REVISION, 'records': records, 'kernel_runtime': False,
                'timer_delivery': 'host model: after response traversal', 'ida_primitives': 'host occupancy model; allocator/release functions extracted verbatim'}
    (args.output / 'summary.json').write_text(json.dumps(document, indent=2) + '\n')
    print(json.dumps(document, indent=2))


if __name__ == '__main__':
    main()
