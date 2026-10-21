import asyncio
import base64
import socket

import pytest

from cynux_endpoint import proxy


@pytest.mark.parametrize(
    "policy",
    [{"allow": "example.com"}, {"allow": ["*"]}, {"allow": [123]}, {"unknown": []}],
)
def test_malformed_policy_rejected(policy):
    with pytest.raises(ValueError):
        proxy.Policy(policy)


@pytest.mark.parametrize("token", ["", "short", "x" * 31 + "\n"])
def test_weak_or_malformed_token_rejected(token):
    with pytest.raises(ValueError):
        proxy.Gateway(proxy.Policy({}), token)


def test_public_dns_address_is_pinned():
    assert proxy.public_address(
        [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]
    ) == (socket.AF_INET, "8.8.8.8")


def test_policy_deny_precedes_allow_and_wildcard_has_label_boundary():
    policy = proxy.Policy(
        {"allow": ["*.example.com", "example.com"], "deny": ["bad.example.com"]}
    )
    assert policy.allows("api.example.com")
    assert policy.allows("example.com")
    assert not policy.allows("bad.example.com")
    assert not policy.allows("example.com.attacker.test")
    assert not policy.allows("notexample.com")
    assert not proxy.Policy({"allow": [], "deny": []}).allows("example.com")


@pytest.mark.parametrize(
    "target",
    [
        "127.0.0.1:443",
        "[::1]:443",
        "example.com:22",
        "a@b:443",
        "example.com:443/path",
        "example.com",
        "x..com:443",
    ],
)
def test_invalid_authorities_rejected(target):
    with pytest.raises(ValueError):
        proxy.authority(target)


def test_valid_authority_normalized():
    assert proxy.authority("API.Example.com:443") == "api.example.com"


@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "fc00::1", "224.0.0.1"],
)
def test_unsafe_dns_destination_denied(address):
    records = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443))]
    with pytest.raises(ValueError):
        proxy.public_address(records)


def test_mixed_public_private_dns_is_denied():
    records = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443))
        for ip in ["8.8.8.8", "10.0.0.1"]
    ]
    with pytest.raises(ValueError):
        proxy.public_address(records)


def test_real_proxy_auth_policy_and_bidirectional_tunnel():
    async def scenario():
        async def echo(reader, writer):
            try:
                writer.write(await reader.read(100))
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        upstream = await asyncio.start_server(echo, "127.0.0.1", 0)
        upstream_port = upstream.sockets[0].getsockname()[1]
        connections = []

        async def connector(host):
            connections.append(host)
            return await asyncio.open_connection("127.0.0.1", upstream_port)

        logs = []
        gateway = proxy.Gateway(
            proxy.Policy({"allow": ["example.com"]}),
            "t" * 32,
            connector=connector,
            emit=logs.append,
        )
        server = await asyncio.start_server(gateway.handle, "127.0.0.1", 0, limit=8192)
        port = server.sockets[0].getsockname()[1]
        auth = base64.b64encode(b"cynux:" + b"t" * 32).decode()
        try:
            for host, authorization, expected in [
                ("example.com", "", 407),
                ("denied.test", auth, 403),
                ("example.com", auth, 200),
            ]:
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.write(
                    f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\nProxy-Authorization: Basic {authorization}\r\n\r\n".encode()
                )
                await writer.drain()
                response = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 3)
                assert str(expected).encode() in response.split(b"\r\n")[0]
                if expected == 200:
                    writer.write(b"hello tunnel")
                    await writer.drain()
                    assert (
                        await asyncio.wait_for(reader.readexactly(12), 3)
                        == b"hello tunnel"
                    )
                writer.close()
                await writer.wait_closed()
            assert connections == ["example.com"]
            assert all("t" * 32 not in str(item) for item in logs)
        finally:
            server.close()
            upstream.close()
            await server.wait_closed()
            await upstream.wait_closed()

    asyncio.run(scenario())
