package systemproxy

import "testing"

func TestParseNetworkServices(t *testing.T) {
	out := `An asterisk (*) denotes that a network service is disabled.
Wi-Fi
* Thunderbolt Bridge
Ethernet
`
	services := parseNetworkServices(out)
	if len(services) != 2 {
		t.Fatalf("expected 2 services, got %d", len(services))
	}
	if services[0] != "Wi-Fi" || services[1] != "Ethernet" {
		t.Fatalf("unexpected services: %#v", services)
	}
}

func TestChoosePreferredService(t *testing.T) {
	if got := choosePreferredService([]string{"USB 10/100/1000 LAN", "Ethernet"}); got != "Ethernet" {
		t.Fatalf("expected Ethernet, got %q", got)
	}
	if got := choosePreferredService([]string{"VPN", "Cellular"}); got != "VPN" {
		t.Fatalf("expected fallback to first service, got %q", got)
	}
}

func TestParseProxyConfig(t *testing.T) {
	out := `Enabled: Yes
Server: localhost
Port: 8080
Authenticated Proxy Enabled: 0`
	cfg, err := parseProxyConfig(out)
	if err != nil {
		t.Fatalf("parseProxyConfig returned error: %v", err)
	}
	if !cfg.Enabled || cfg.Host != "localhost" || cfg.Port != 8080 {
		t.Fatalf("unexpected cfg: %#v", cfg)
	}
}
