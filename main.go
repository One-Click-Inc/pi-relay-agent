// oc-relay-agent: One Click's relay agent, for the Raspberry Pis at client sites whose system
// can't run WireGuard itself (Raspbian 9 and 10). It is WireGuard (wireguard-go, WireGuard's
// own implementation in Go) plus the few lines that set up one connection out to One Click's
// relay. The Raspberry Pi program's installer downloads it, checks its SHA-256, and runs it as
// the oc-relay-agent service.
//
//	oc-relay-agent genkey          a new private key (base64), for /etc/oc-relay/key
//	oc-relay-agent pubkey < KEY    its public key
//	oc-relay-agent run CONFIG      the connection, until stopped
//	oc-relay-agent version
//
// CONFIG has key=value lines: key_file (the private key's file), address (this Pi's address
// on the relay's network, 10.213.x.y), relay_key (the relay's public key) and endpoint (the
// relay's public IP:port). The connection carries only 10.213.0.1, the relay: nothing else on
// the Pi is routed through it.
package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
)

const (
	iface     = "ocrelay"
	relayIP   = "10.213.0.1/32"
	keepalive = 25
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "genkey":
		err = genkey(os.Stdout)
	case "pubkey":
		err = pubkey(os.Stdin, os.Stdout)
	case "run":
		if len(os.Args) != 3 {
			usage()
		}
		err = run(os.Args[2])
	case "version":
		fmt.Println(version)
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "oc-relay-agent:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: oc-relay-agent genkey | pubkey < KEY | run CONFIG | version")
	os.Exit(2)
}

func genkey(out io.Writer) error {
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		return err
	}
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
	_, err := fmt.Fprintln(out, base64.StdEncoding.EncodeToString(k[:]))
	return err
}

func decodeKey(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != 32 {
		return nil, errors.New("that isn't a WireGuard key")
	}
	return b, nil
}

func publicKey(private []byte) ([]byte, error) {
	return curve25519.X25519(private, curve25519.Basepoint)
}

func pubkey(in io.Reader, out io.Writer) error {
	text, err := io.ReadAll(io.LimitReader(in, 1024))
	if err != nil {
		return err
	}
	private, err := decodeKey(string(text))
	if err != nil {
		return err
	}
	public, err := publicKey(private)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, base64.StdEncoding.EncodeToString(public))
	return err
}

type config struct {
	keyFile, address, relayKey, endpoint string
}

func readConfig(path string) (config, error) {
	var c config
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		if !ok {
			return c, fmt.Errorf("%s: a line isn't name=value", path)
		}
		value = strings.TrimSpace(value)
		switch strings.TrimSpace(name) {
		case "key_file":
			c.keyFile = value
		case "address":
			c.address = value
		case "relay_key":
			c.relayKey = value
		case "endpoint":
			c.endpoint = value
		default:
			return c, fmt.Errorf("%s: unknown setting %q", path, name)
		}
	}
	if err := s.Err(); err != nil {
		return c, err
	}
	if c.keyFile == "" || c.address == "" || c.relayKey == "" || c.endpoint == "" {
		return c, fmt.Errorf("%s needs key_file, address, relay_key and endpoint", path)
	}
	return c, nil
}

// uapiConfig is WireGuard's own configuration text for the one peer, the relay.
func uapiConfig(private, relay []byte, endpoint string) string {
	return fmt.Sprintf(
		"private_key=%s\nreplace_peers=true\npublic_key=%s\nendpoint=%s\n"+
			"persistent_keepalive_interval=%d\nreplace_allowed_ips=true\nallowed_ip=%s\n",
		hex.EncodeToString(private), hex.EncodeToString(relay), endpoint, keepalive, relayIP)
}

func ip(args ...string) error {
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func run(path string) error {
	c, err := readConfig(path)
	if err != nil {
		return err
	}
	keyText, err := os.ReadFile(c.keyFile)
	if err != nil {
		return err
	}
	private, err := decodeKey(string(keyText))
	if err != nil {
		return fmt.Errorf("%s: %w", c.keyFile, err)
	}
	relay, err := decodeKey(c.relayKey)
	if err != nil {
		return fmt.Errorf("relay_key: %w", err)
	}
	addr := net.ParseIP(c.address).To4()
	_, pis, _ := net.ParseCIDR("10.213.0.0/16")
	if addr == nil || !pis.Contains(addr) {
		return errors.New("address must be this Pi's 10.213.x.y")
	}
	endpoint, err := net.ResolveUDPAddr("udp4", c.endpoint)
	if err != nil {
		return fmt.Errorf("endpoint: %w", err)
	}

	tdev, err := tun.CreateTUN(iface, device.DefaultMTU)
	if err != nil {
		return fmt.Errorf("couldn't make the %s interface: %w", iface, err)
	}
	name, err := tdev.Name()
	if err != nil {
		return err
	}
	logger := device.NewLogger(device.LogLevelError, "oc-relay-agent: ")
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), logger)
	defer dev.Close()
	if err := dev.IpcSet(uapiConfig(private, relay, endpoint.String())); err != nil {
		return err
	}
	if err := dev.Up(); err != nil {
		return err
	}
	for _, args := range [][]string{
		{"address", "replace", addr.String() + "/32", "dev", name},
		{"link", "set", name, "up"},
		{"route", "replace", relayIP, "dev", name},
	} {
		if err := ip(args...); err != nil {
			return err
		}
	}

	// WireGuard's control socket, so `wg show ocrelay` works wherever wg is installed.
	if file, err := ipc.UAPIOpen(name); err == nil {
		if listener, err := ipc.UAPIListen(name, file); err == nil {
			defer listener.Close()
			go func() {
				for {
					c, err := listener.Accept()
					if err != nil {
						return
					}
					go dev.IpcHandle(c)
				}
			}()
		}
	}
	fmt.Fprintf(os.Stderr, "oc-relay-agent %s: %s is %s, connecting to the relay at %s\n",
		version, name, addr, endpoint)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, os.Interrupt)
	select {
	case <-stop:
	case <-dev.Wait():
	}
	return nil
}
