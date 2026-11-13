# oc-relay-agent

One Click's relay agent: WireGuard for the Raspberry Pis at One Click's client sites whose
system is too old to run WireGuard itself (Raspbian 9 and 10). It's
[wireguard-go](https://git.zx2c4.com/wireguard-go) (WireGuard's own implementation in Go,
MIT licence) plus the few lines that set up one connection out to One Click's relay, carrying
only the relay's address (10.213.0.1). Nothing else on the Pi goes through it.

It isn't meant to be run by hand: One Click's Raspberry Pi program gives each Pi a one-line
installer, which downloads the build for the Pi's processor from this repository's release,
checks its SHA-256 against the one the installer carries, and runs it as the
`oc-relay-agent` service.

```
oc-relay-agent genkey          a new private key (base64)
oc-relay-agent pubkey < KEY    its public key
oc-relay-agent run CONFIG      the connection, until stopped
oc-relay-agent bridge LISTEN URL [ADDRESS]
                               the web backup, until stopped (v1.1.0 and later)
oc-relay-agent version
```

`CONFIG` has `key_file=`, `address=` (10.213.x.y), `relay_key=` and `endpoint=` lines.

## The web backup (v1.1.0)

Some client sites' firewalls block WireGuard, or recognise it and cut it off. There the Pi's
WireGuard (its own, or this agent's) sends to `LISTEN` on the Pi itself (`127.0.0.1:51821`),
and `bridge` carries each packet as one WebSocket message inside an ordinary HTTPS connection
to the relay (`wss://NAME/PATH`, on port 443), which hands it to the relay's WireGuard. To the
firewall it looks like a browser on a website. `ADDRESS` (`IP:443`) is used when the site can't
look the name up. It only carries WireGuard's packets: WireGuard still encrypts and checks every
one end to end, so the relay's HTTPS certificate isn't checked, on purpose (it gets through
firewalls that re-sign HTTPS, and works on Pis with an out-of-date list of certificate
authorities). The Raspberry Pi program's Pi scripts download this build and switch to it by
themselves when the relay can't be reached the usual way.

## Builds

Each release has `oc-relay-agent-linux-arm` (32-bit ARM, ARMv6 and up: every Raspberry Pi),
`oc-relay-agent-linux-arm64` and `SHA256SUMS`. They're reproducible: with the Go version the
release names,

```
CGO_ENABLED=0 GOFLAGS=-trimpath GOOS=linux GOARCH=arm GOARM=6 \
  go build -ldflags "-s -w -buildid= -X main.version=<tag>" -o oc-relay-agent-linux-arm .
```

(and `GOARCH=arm64` for the other) gives the same bytes.

## Licence

MIT (LICENSE). wireguard-go is MIT too; WireGuard is a registered trademark of Jason A.
Donenfeld.
