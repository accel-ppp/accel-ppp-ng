import hashlib
import hmac
import re
import socket
import struct
import threading
import time

import pytest

from common import process


RADIUS_ACCESS_REQUEST = 1
RADIUS_ACCESS_ACCEPT = 2
RADIUS_ACCESS_REJECT = 3
RADIUS_ACCOUNTING_REQUEST = 4
RADIUS_ACCOUNTING_RESPONSE = 5
RADIUS_MESSAGE_AUTHENTICATOR = 80
RADIUS_FRAMED_IP_ADDRESS = 8

RADIUS_SECRET = b"radiusSecretMA"
RADIUS_BACKUP_SECRET = b"radiusBackupSecretMA"
RADIUS_WRONG_SECRET = b"notTheRadiusSecret"
ASSIGNED_IP = "192.0.2.42"
USERNAME = "loginMA"

# accel-pppd radius timeout (sec); negative tests must wait longer than this
RADIUS_TIMEOUT = 1
MAX_WAIT_TIME = 10.0

# Response Message-Authenticator variants produced by the mock server
MA_VALID = "valid"  # correct HMAC-MD5
MA_NONE = "none"  # attribute omitted
MA_BAD = "bad"  # HMAC computed with a wrong secret
MA_DUP = "dup"  # two Message-Authenticator attributes
MA_SHORT = "short"  # attribute value is 15 bytes instead of 16


def radius_attr(attr_type, value):
    return bytes([attr_type, len(value) + 2]) + value


def radius_attrs(packet):
    pos = 20
    while pos < len(packet):
        attr_type = packet[pos]
        attr_len = packet[pos + 1]
        assert attr_len >= 2
        yield attr_type, pos, packet[pos + 2 : pos + attr_len]
        pos += attr_len


def find_message_authenticators(packet):
    return [
        (pos, value)
        for attr_type, pos, value in radius_attrs(packet)
        if attr_type == RADIUS_MESSAGE_AUTHENTICATOR
    ]


def verify_request_message_authenticator(packet, secret):
    found = find_message_authenticators(packet)
    assert len(found) == 1, "Access-Request must carry exactly one Message-Authenticator"
    ma_pos, recv_ma = found[0]
    assert len(recv_ma) == 16
    assert recv_ma != bytes(16)

    check_packet = bytearray(packet)
    check_packet[ma_pos + 2 : ma_pos + 18] = bytes(16)
    expected = hmac.new(secret, check_packet, hashlib.md5).digest()
    assert recv_ma == expected, "Access-Request Message-Authenticator mismatch"


def verify_request_has_no_message_authenticator(packet):
    assert (
        find_message_authenticators(packet) == []
    ), "Access-Request must not carry Message-Authenticator"


def make_radius_response(
    code, req_packet, attrs, secret, ma_mode=MA_NONE, bad_response_auth=False
):
    req_id = req_packet[1]
    req_auth = req_packet[4:20]

    if ma_mode == MA_SHORT:
        ma_attrs = radius_attr(RADIUS_MESSAGE_AUTHENTICATOR, bytes(15))
    elif ma_mode == MA_DUP:
        # The second attribute holds a fixed value, and the first one is signed
        # over the packet as sent. Only the duplicate check can reject this
        # packet, because the first MA would otherwise verify.
        ma_attrs = radius_attr(RADIUS_MESSAGE_AUTHENTICATOR, bytes(16)) + radius_attr(
            RADIUS_MESSAGE_AUTHENTICATOR, b"\x55" * 16
        )
    elif ma_mode in (MA_VALID, MA_BAD):
        ma_attrs = radius_attr(RADIUS_MESSAGE_AUTHENTICATOR, bytes(16))
    else:
        ma_attrs = b""

    body = ma_attrs + attrs
    response = bytearray(
        struct.pack("!BBH", code, req_id, 20 + len(body)) + req_auth + body
    )

    if ma_mode != MA_NONE:
        # RFC 3579: HMAC over the packet with Request Authenticator in the
        # header and the (first) Message-Authenticator value zeroed.
        ma_secret = RADIUS_WRONG_SECRET if ma_mode == MA_BAD else secret
        ma_len = 15 if ma_mode == MA_SHORT else 16
        digest = hmac.new(ma_secret, response, hashlib.md5).digest()
        response[22 : 22 + ma_len] = digest[:ma_len]

    response_auth = bytearray(
        hashlib.md5(response[:4] + req_auth + response[20:] + secret).digest()
    )
    if bad_response_auth:
        response_auth[0] ^= 0xFF
    response[4:20] = response_auth
    return bytes(response)


class RadiusServer:
    """Minimal RADIUS auth/acct server.

    reply_code:  RADIUS_ACCESS_ACCEPT, RADIUS_ACCESS_REJECT or None (silent)
    ma_mode:     one of MA_* for the Access-* response
    expect_request_ma: True/False - Access-Request must/must not carry MA
    """

    def __init__(
        self,
        secret=RADIUS_SECRET,
        reply_code=RADIUS_ACCESS_ACCEPT,
        ma_mode=MA_VALID,
        bad_response_auth=False,
        expect_request_ma=True,
    ):
        self.secret = secret
        self.reply_code = reply_code
        self.ma_mode = ma_mode
        self.bad_response_auth = bad_response_auth
        self.expect_request_ma = expect_request_ma

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.1)
        self.port = self.sock.getsockname()[1]
        self.running = True
        self.lock = threading.Lock()
        self.access_requests = []
        self.access_responses_sent = 0
        self.error = None
        self.thread = threading.Thread(target=self.run)
        self.thread.start()

    def handle_access_request(self, packet, addr):
        if self.expect_request_ma:
            verify_request_message_authenticator(packet, self.secret)
        else:
            verify_request_has_no_message_authenticator(packet)

        with self.lock:
            self.access_requests.append(packet)

        if self.reply_code is None:
            return

        attrs = b""
        if self.reply_code == RADIUS_ACCESS_ACCEPT:
            attrs = radius_attr(RADIUS_FRAMED_IP_ADDRESS, socket.inet_aton(ASSIGNED_IP))

        self.sock.sendto(
            make_radius_response(
                self.reply_code,
                packet,
                attrs,
                self.secret,
                self.ma_mode,
                self.bad_response_auth,
            ),
            addr,
        )
        with self.lock:
            self.access_responses_sent += 1

    def run(self):
        while self.running:
            try:
                packet, addr = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break

            try:
                if packet[0] == RADIUS_ACCESS_REQUEST:
                    self.handle_access_request(packet, addr)
                elif packet[0] == RADIUS_ACCOUNTING_REQUEST:
                    self.sock.sendto(
                        make_radius_response(
                            RADIUS_ACCOUNTING_RESPONSE, packet, b"", self.secret
                        ),
                        addr,
                    )
            except Exception as error:  # surface any mock-server failure to the test
                if self.error is None:
                    self.error = error

    def stop(self):
        self.running = False
        self.sock.close()
        self.thread.join()


def radius_server_line(server, backup=False):
    return (
        "server=127.0.0.1,"
        + server.secret.decode()
        + ",auth-port="
        + str(server.port)
        + ",acct-port="
        + str(server.port)
        + (",backup" if backup else "")
    )


def make_accel_pppd_config(veth_pair_netns, server_lines, include_ma, require_ma):
    return (
        """
    [modules]
    radius
    pppoe
    auth_pap
    ippool

    [core]
    log-error=/dev/stderr

    [log]
    log-debug=/dev/stdout
    log-file=/dev/stdout
    log-emerg=/dev/stderr
    level=5

    [ip-pool]
    gw-ip-address=192.0.2.1
    192.0.2.2-255

    [cli]
    tcp=127.0.0.1:2001

    [radius]
    nas-identifier=accel-ppp-test
    gw-ip-address=192.0.2.1
    """
        + "\n    ".join(server_lines)
        + """
    timeout="""
        + str(RADIUS_TIMEOUT)
        + """
    max-try=1
    verbose=1
    message-authenticator-include-access-request="""
        + str(include_ma)
        + """
    message-authenticator-require-access-response="""
        + str(require_ma)
        + """

    [pppoe]
    interface="""
        + veth_pair_netns["veth_a"]
    )


# ---------------------------------------------------------------------------
# Fixtures (overridable via indirect parametrization)
# ---------------------------------------------------------------------------


# {"include": 0|1, "require": 0|1}
@pytest.fixture()
def ma_config(request):
    return getattr(request, "param", {"include": 1, "require": 1})


# kwargs for RadiusServer (reply_code, ma_mode, bad_response_auth)
@pytest.fixture()
def radius_behavior(request):
    return getattr(request, "param", {})


@pytest.fixture()
def radius_topology(request, ma_config, radius_behavior):
    if getattr(request, "param", None) == "failover":
        primary = RadiusServer(secret=RADIUS_SECRET, reply_code=None)
        server = RadiusServer(secret=RADIUS_BACKUP_SECRET)
        servers = [primary, server]
    else:
        primary = None
        server = RadiusServer(
            expect_request_ma=bool(ma_config["include"]), **radius_behavior
        )
        servers = [server]

    yield {"primary": primary, "server": server}

    for radius_server in servers:
        radius_server.stop()


@pytest.fixture()
def radius_server(radius_topology):
    return radius_topology["server"]


@pytest.fixture()
def accel_pppd_config(veth_pair_netns, radius_topology, ma_config):
    primary = radius_topology["primary"]
    server = radius_topology["server"]
    server_lines = []
    if primary:
        server_lines.append(radius_server_line(primary))
    server_lines.append(radius_server_line(server, backup=bool(primary)))

    return make_accel_pppd_config(
        veth_pair_netns,
        server_lines,
        ma_config["include"],
        ma_config["require"],
    )


@pytest.fixture()
def pppd_config(veth_pair_netns):
    return (
        """
    nodetach
    noipdefault
    defaultroute
    connect /bin/true
    noauth
    persist
    mtu 1492
    noaccomp
    default-asyncmap
    user """
        + USERNAME
        + """
    password pass123
    nic-"""
        + veth_pair_netns["veth_b"]
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def wait_for(predicate, max_wait_time=MAX_WAIT_TIME, step=0.1):
    waited = 0.0
    while waited < max_wait_time:
        if predicate():
            return True
        time.sleep(step)
        waited += step
    return predicate()


def is_session_active(accel_cmd):
    exit_code, out, _err = process.run(
        [accel_cmd, "show sessions match username log.nMA username,ip,state"]
    )
    assert exit_code == 0
    return USERNAME in out and ASSIGNED_IP in out and "active" in out


def radius_auth_lost(accel_cmd):
    """Return list of 'auth lost (total)' counters, one per radius server."""
    exit_code, out, _err = process.run([accel_cmd, "show stat"])
    assert exit_code == 0
    return [int(n) for n in re.findall(r"auth lost\(total/5m/1m\): (\d+)/", out)]


def access_responses_sent(server):
    with server.lock:
        return server.access_responses_sent


def assert_response_dropped(accel_cmd, radius_server):
    # The server must actually have answered, otherwise "no session" proves nothing.
    assert wait_for(lambda: access_responses_sent(radius_server) >= 1)
    # A response rejected by accel-pppd is silently discarded, so the request
    # ends up timing out and is accounted as "auth lost".
    assert wait_for(lambda: sum(radius_auth_lost(accel_cmd)) >= 1)
    assert not is_session_active(accel_cmd)
    assert radius_server.error is None


# ---------------------------------------------------------------------------
# Positive cases: Access-Accept is accepted and the session comes up
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "ma_config, radius_behavior",
    [
        pytest.param(
            {"include": 1, "require": 1},
            {"ma_mode": MA_VALID},
            id="include-require-valid-ma",
        ),
        pytest.param(
            {"include": 1, "require": 0},
            {"ma_mode": MA_NONE},
            id="not-required-missing-ma",
        ),
        pytest.param(
            {"include": 1, "require": 0},
            {"ma_mode": MA_VALID},
            id="not-required-valid-ma",
        ),
        pytest.param(
            {"include": 0, "require": 1},
            {"ma_mode": MA_VALID},
            id="request-ma-disabled",
        ),
    ],
    indirect=True,
)
def test_pppoe_radius_message_authenticator(pppd_instance, accel_cmd, radius_server):
    assert pppd_instance["is_started"]

    assert wait_for(lambda: is_session_active(accel_cmd))
    assert radius_server.error is None
    assert len(radius_server.access_requests) >= 1
    assert sum(radius_auth_lost(accel_cmd)) == 0


# ---------------------------------------------------------------------------
# Negative cases: Access-* response must be discarded
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "radius_behavior",
    [
        pytest.param({"ma_mode": MA_NONE}, id="accept-missing-ma"),
        pytest.param({"ma_mode": MA_BAD}, id="accept-wrong-ma"),
        pytest.param({"ma_mode": MA_DUP}, id="accept-duplicate-ma"),
        pytest.param({"ma_mode": MA_SHORT}, id="accept-short-ma"),
        pytest.param(
            {"ma_mode": MA_VALID, "bad_response_auth": True},
            id="accept-valid-ma-bad-response-auth",
        ),
        pytest.param(
            {"reply_code": RADIUS_ACCESS_REJECT, "ma_mode": MA_NONE},
            id="reject-missing-ma",
        ),
        pytest.param(
            {"reply_code": RADIUS_ACCESS_REJECT, "ma_mode": MA_BAD},
            id="reject-wrong-ma",
        ),
    ],
    indirect=True,
)
def test_pppoe_radius_message_authenticator_response_dropped(
    pppd_instance, accel_cmd, radius_server
):
    assert pppd_instance["is_started"]

    assert_response_dropped(accel_cmd, radius_server)


@pytest.mark.parametrize(
    "ma_config, radius_behavior",
    [
        pytest.param(
            {"include": 1, "require": 0},
            {"ma_mode": MA_BAD},
            id="not-required-wrong-ma",
        )
    ],
    indirect=True,
)
def test_pppoe_radius_message_authenticator_optional_response_dropped(
    pppd_instance, accel_cmd, radius_server
):
    assert pppd_instance["is_started"]

    assert_response_dropped(accel_cmd, radius_server)


@pytest.mark.parametrize(
    "radius_behavior",
    [pytest.param({"reply_code": RADIUS_ACCESS_REJECT, "ma_mode": MA_VALID})],
    ids=["reject-valid-ma"],
    indirect=True,
)
def test_pppoe_radius_message_authenticator_reject_honored(
    pppd_instance, accel_cmd, radius_server
):
    assert pppd_instance["is_started"]

    assert wait_for(lambda: access_responses_sent(radius_server) >= 1)
    # Give accel-pppd longer than the radius timeout. A dropped reply would
    # show up as "auth lost" by then.
    time.sleep(RADIUS_TIMEOUT + 1)

    assert radius_server.error is None
    assert sum(radius_auth_lost(accel_cmd)) == 0
    assert not is_session_active(accel_cmd)


# ---------------------------------------------------------------------------
# Failover: Access-Request MA must be re-signed with the backup server secret
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("radius_topology", ["failover"], indirect=True)
def test_pppoe_radius_message_authenticator_failover(
    pppd_instance, accel_cmd, radius_topology
):
    assert pppd_instance["is_started"]

    assert wait_for(lambda: is_session_active(accel_cmd))

    primary_radius_server = radius_topology["primary"]
    radius_server = radius_topology["server"]

    # Each server checks the request MA against its own secret.
    assert primary_radius_server.error is None
    assert radius_server.error is None
    assert len(primary_radius_server.access_requests) >= 1
    assert len(radius_server.access_requests) >= 1
