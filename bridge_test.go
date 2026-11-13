package main

import (
	"net"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"golang.org/x/net/websocket"
)

// relayEcho stands in for the relay's oc-relay-web: it sends every message straight back.
func relayEcho(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(websocket.Server{Handler: func(ws *websocket.Conn) {
		for {
			var msg []byte
			if err := websocket.Message.Receive(ws, &msg); err != nil {
				return
			}
			if err := websocket.Message.Send(ws, msg); err != nil {
				return
			}
		}
	}})
	t.Cleanup(srv.Close)
	return srv
}

// throughBridge sends one packet the way WireGuard would and returns what came back.
func throughBridge(t *testing.T, rawURL, fallback string) string {
	t.Helper()
	u, err := relayURL(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	b, err := newWebBridge(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.pc.Close() })
	go b.run(u, fallback)
	wg, err := net.DialUDP("udp", nil, b.pc.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer wg.Close()
	buf := make([]byte, 2048)
	for try := 0; try < 20; try++ { // the first may go before the connection is up
		if _, err := wg.Write([]byte("a WireGuard packet")); err != nil {
			t.Fatal(err)
		}
		_ = wg.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		if n, err := wg.Read(buf); err == nil {
			return string(buf[:n])
		}
	}
	t.Fatal("nothing came back through the bridge")
	return ""
}

func TestTheBridgeCarriesPacketsToTheRelayAndBack(t *testing.T) {
	srv := relayEcho(t)
	addr := srv.Listener.Addr().String()
	if got := throughBridge(t, "wss://"+addr+"/oc-relay", ""); got != "a WireGuard packet" {
		t.Fatalf("got %q", got)
	}
}

func TestTheBridgeUsesTheAddressWhenTheNameCantBeLookedUp(t *testing.T) {
	srv := relayEcho(t)
	addr := srv.Listener.Addr().String()
	_, port, _ := net.SplitHostPort(addr)
	name := (&url.URL{Scheme: "wss", Host: "oc-relay-test.invalid:" + port, Path: "/oc-relay"}).String()
	if got := throughBridge(t, name, addr); got != "a WireGuard packet" {
		t.Fatalf("got %q", got)
	}
}
