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
oc-relay-agent version
```

`CONFIG` has `key_file=`, `address=` (10.213.x.y), `relay_key=` and `endpoint=` lines.

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
