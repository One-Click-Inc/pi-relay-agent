package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The public key of a known private key: RFC 7748's test vector (Alice's).
func TestPubkeyMatchesRFC7748(t *testing.T) {
	private := []byte{
		0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
		0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
	}
	want := []byte{
		0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
		0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a,
	}
	var out bytes.Buffer
	if err := pubkey(strings.NewReader(base64.StdEncoding.EncodeToString(private)+"\n"), &out); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out.String()) != base64.StdEncoding.EncodeToString(want) {
		t.Fatalf("got %s", out.String())
	}
}

func TestGenkeyIsAClampedKey(t *testing.T) {
	var out bytes.Buffer
	if err := genkey(&out); err != nil {
		t.Fatal(err)
	}
	k, err := decodeKey(out.String())
	if err != nil || k[0]&7 != 0 || k[31]&128 != 0 || k[31]&64 == 0 {
		t.Fatalf("not a clamped key: %v %v", k, err)
	}
}

func TestConfigNeedsEverything(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.conf")
	os.WriteFile(path, []byte("# made up\nkey_file=/k\naddress=10.213.1.4\n"), 0o600)
	if _, err := readConfig(path); err == nil {
		t.Fatal("a config without relay_key and endpoint was taken")
	}
	os.WriteFile(path, []byte("key_file=/k\naddress=10.213.1.4\nrelay_key=x\nendpoint=192.0.2.1:51820\n"), 0o600)
	if c, err := readConfig(path); err != nil || c.endpoint != "192.0.2.1:51820" {
		t.Fatalf("%v %v", c, err)
	}
}

func TestOnlyTheRelayGoesThroughTheConnection(t *testing.T) {
	text := uapiConfig(make([]byte, 32), make([]byte, 32), "192.0.2.1:51820")
	if strings.Count(text, "allowed_ip=") != 1 || !strings.Contains(text, "allowed_ip=10.213.0.1/32\n") {
		t.Fatal(text)
	}
}
