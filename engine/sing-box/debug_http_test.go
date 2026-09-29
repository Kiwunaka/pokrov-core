package box

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	boxCertificate "github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	boxService "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/option"
)

func TestBoxCloseReleasesDebugListener(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	dnsRegistry := dns.NewTransportRegistry()
	local.RegisterTransport(dnsRegistry)
	ctx := Context(context.Background(), inbound.NewRegistry(), outbound.NewRegistry(), endpoint.NewRegistry(), dnsRegistry, boxService.NewRegistry(), boxCertificate.NewRegistry())
	instance, err := New(Options{
		Context: ctx,
		Options: option.Options{
			Log:          &option.LogOptions{Disabled: true},
			Experimental: &option.ExperimentalOptions{Debug: &option.DebugOptions{Listen: address}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	if err = instance.Start(); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: time.Second}
	response, err := client.Get("http://" + address + "/debug/memory")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	client.CloseIdleConnections()
	if err = instance.Close(); err != nil {
		t.Fatal(err)
	}
	listener, err = net.Listen("tcp", address)
	if err != nil {
		t.Fatalf("Box.Close retained its debug listener: %v", err)
	}
	listener.Close()
}
