// The web backup (Chad and Rob, Nov 13, 2026). Some client sites' firewalls block WireGuard, or
// recognise it and cut it off after its first packet. There, the Pi's WireGuard sends to a port
// on the Pi itself instead, and this bridge carries each of its packets as one message of a
// WebSocket inside an ordinary HTTPS connection to the relay's name on port 443, where the
// relay's oc-relay-web hands it to the relay's WireGuard. To the site's firewall it looks like a
// browser on a website, like RemoteIoT's own connection.
//
//	oc-relay-agent bridge LISTEN URL [ADDRESS]
//
// LISTEN is the local UDP address WireGuard sends to (127.0.0.1 only, e.g. 127.0.0.1:51821);
// URL the relay's (wss://NAME/PATH); ADDRESS (IP:443) is used when the site can't look the name
// up. It keeps one connection open and makes a new one whenever it drops.
//
// The relay's HTTPS certificate isn't checked, on purpose: WireGuard inside is the real lock
// (the relay proves itself with its WireGuard key, and every packet is encrypted end to end),
// so a server pretending to be the relay could only drop packets, as anyone on the path already
// can. Not checking lets it through firewalls that open and re-sign HTTPS, and works on old Pis
// whose list of certificate authorities is out of date.
package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"sync/atomic"
	"time"

	"golang.org/x/net/websocket"
)

const (
	bridgeMaxPacket = 4096
	// The Pi pings the relay every minute, so this long with nothing back means the connection
	// is dead even if TCP hasn't noticed.
	bridgeIdle    = 5 * time.Minute
	bridgeDial    = 15 * time.Second
	bridgeMaxWait = time.Minute
)

type webBridge struct {
	pc    *net.UDPConn
	local atomic.Pointer[net.UDPAddr] // where WireGuard sends from
	out   chan []byte
}

func bridge(listen, rawURL, fallback string) error {
	u, err := relayURL(rawURL)
	if err != nil {
		return err
	}
	if fallback != "" {
		if _, _, err := net.SplitHostPort(fallback); err != nil {
			return fmt.Errorf("ADDRESS must be IP:PORT: %w", err)
		}
	}
	laddr, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		return fmt.Errorf("LISTEN: %w", err)
	}
	if laddr.IP == nil || !laddr.IP.IsLoopback() {
		return errors.New("LISTEN must be on this Pi only (127.0.0.1:PORT)")
	}
	b, err := newWebBridge(laddr)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "oc-relay-agent %s: web backup from %s to %s\n", version, laddr, u)
	b.run(u, fallback)
	return nil
}

func relayURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "wss" || u.Hostname() == "" || u.User != nil {
		return nil, errors.New("URL must be wss://NAME/PATH")
	}
	return u, nil
}

func newWebBridge(laddr *net.UDPAddr) (*webBridge, error) {
	pc, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return nil, err
	}
	b := &webBridge{pc: pc, out: make(chan []byte, 64)}
	go b.readLocal()
	return b, nil
}

// readLocal takes WireGuard's packets and queues them for the relay. A full queue drops the
// packet: WireGuard sends again, as it would over a busy network.
func (b *webBridge) readLocal() {
	buf := make([]byte, bridgeMaxPacket)
	for {
		n, from, err := b.pc.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		if !from.IP.IsLoopback() {
			continue
		}
		b.local.Store(from)
		p := make([]byte, n)
		copy(p, buf[:n])
		select {
		case b.out <- p:
		default:
		}
	}
}

// run keeps a connection to the relay, waiting longer after each failure (up to a minute).
func (b *webBridge) run(u *url.URL, fallback string) {
	wait := time.Second
	for {
		start := time.Now()
		err := b.session(u, fallback)
		if time.Since(start) > time.Minute {
			wait = time.Second
		}
		fmt.Fprintf(os.Stderr, "oc-relay-agent: web backup: %v (again in %s)\n", err, wait)
		time.Sleep(wait)
		wait = min(wait*2, bridgeMaxWait)
	}
}

// session carries packets both ways over one connection until it fails.
func (b *webBridge) session(u *url.URL, fallback string) error {
	ws, err := dialRelay(u, fallback)
	if err != nil {
		return err
	}
	defer ws.Close()
	failed := make(chan error, 1)
	go func() {
		for {
			var msg []byte
			_ = ws.SetReadDeadline(time.Now().Add(bridgeIdle))
			if err := websocket.Message.Receive(ws, &msg); err != nil {
				failed <- err
				return
			}
			if to := b.local.Load(); to != nil && len(msg) > 0 {
				_, _ = b.pc.WriteToUDP(msg, to)
			}
		}
	}()
	for {
		select {
		case p := <-b.out:
			_ = ws.SetWriteDeadline(time.Now().Add(30 * time.Second))
			if err := websocket.Message.Send(ws, p); err != nil {
				return err
			}
		case err := <-failed:
			return err
		}
	}
}

// dialRelay opens HTTPS to the relay's name (or ADDRESS, when the name can't be looked up) and
// upgrades it to a WebSocket that carries binary messages.
func dialRelay(u *url.URL, fallback string) (*websocket.Conn, error) {
	host, port := u.Hostname(), u.Port()
	if port == "" {
		port = "443"
	}
	conf, err := websocket.NewConfig(u.String(), "https://"+host)
	if err != nil {
		return nil, err
	}
	conf.Header.Set("User-Agent", "oc-relay-agent/"+version)
	tlsConf := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // on purpose: see the top of this file
		MinVersion:         tls.VersionTLS12,
		NextProtos:         []string{"http/1.1"},
	}
	d := &net.Dialer{Timeout: bridgeDial, KeepAlive: 30 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", net.JoinHostPort(host, port), tlsConf)
	var dnsErr *net.DNSError
	if err != nil && fallback != "" && errors.As(err, &dnsErr) {
		conn, err = tls.DialWithDialer(d, "tcp", fallback, tlsConf)
	}
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(bridgeDial))
	ws, err := websocket.NewClient(conf, conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	ws.PayloadType = websocket.BinaryFrame
	ws.MaxPayloadBytes = bridgeMaxPacket
	return ws, nil
}
