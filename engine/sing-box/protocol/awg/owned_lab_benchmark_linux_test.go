package awg

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	awgtransport "github.com/sagernet/sing-box/transport/awg"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Operator-only synthetic workload against an existing owned AWG3.1 lab.
// It uses userspace networking, without changing host routes or DNS.
func TestOwnedAWGPresetBenchmark(t *testing.T) {
	encoded := os.Getenv("POKROV_OWNED_AWG_BENCHMARK_B64")
	if encoded == "" {
		t.Skip("owned AWG benchmark fixture is not available")
	}
	_ = os.Unsetenv("POKROV_OWNED_AWG_BENCHMARK_B64")
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal("benchmark input encoding rejected")
	}
	defer clear(raw)
	var input struct {
		Endpoint option.AwgEndpointOptions `json:"endpoint"`
		Preset   string                    `json:"preset"`
		Port     uint16                    `json:"port"`
	}
	if json.Unmarshal(raw, &input) != nil || input.Port < 1024 {
		t.Fatal("benchmark input rejected")
	}
	jc, ok := map[string]int{"control": 6, "low-junk": 1, "high-junk": 12}[input.Preset]
	if !ok || input.Endpoint.Jc != jc || input.Endpoint.ContractID != awg31ContractID || input.Endpoint.MTU != 1280 {
		t.Fatal("benchmark preset outside declared comparison")
	}
	if validateEndpointOptions(input.Endpoint) != nil || len(input.Endpoint.Peers) != 1 {
		t.Fatal("benchmark endpoint contract rejected")
	}
	ipc, err := genIpcConfig(input.Endpoint)
	if err != nil {
		t.Fatal("benchmark IPC preparation failed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Second)
	defer cancel()
	probeIP, err := resolveOwnedProbeIPv4(ctx)
	if err != nil {
		t.Fatal("owned egress probe resolution failed")
	}
	direct, err := dialer.NewDefault(ctx, option.DialerOptions{})
	if err != nil {
		t.Fatal("benchmark dialer unavailable")
	}
	meter := &ownedLabObservedDialer{Dialer: direct}
	started := time.Now()
	device, err := awgtransport.NewDevice(ctx, log.NewNOPFactory().Logger(), meter, ipc,
		awgtransport.DeviceOpts{Address: input.Endpoint.Address, AllowedIps: input.Endpoint.Peers[0].AllowedIPs, MTU: input.Endpoint.MTU})
	if err != nil {
		t.Fatal("benchmark device preparation failed")
	}
	defer device.Close()
	if device.Start(adapter.StartStateStart) != nil {
		t.Fatal("benchmark device start failed")
	}
	connection, err := device.DialContext(ctx, N.NetworkTCP, M.Socksaddr{Addr: probeIP, Port: 443})
	if err != nil {
		t.Fatal("benchmark initial TCP egress failed")
	}
	tcpReady := time.Since(started)
	deadline, _ := ctx.Deadline()
	_ = connection.SetDeadline(deadline)
	secure := tls.Client(connection, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "api.pokrov.space"})
	defer secure.Close()
	if secure.HandshakeContext(ctx) != nil {
		t.Fatal("benchmark authenticated TLS egress failed")
	}
	_, err = io.WriteString(secure, "GET /api/public/authenticated-egress-probe HTTP/1.1\r\nHost: api.pokrov.space\r\nConnection: close\r\n\r\n")
	if err != nil {
		t.Fatal("benchmark egress request failed")
	}
	response, err := http.ReadResponse(bufio.NewReader(secure), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal("benchmark egress response failed")
	}
	valid := response.StatusCode == http.StatusNoContent && response.Header.Get("X-Pokrov-Egress-Probe") == "pokrov-authenticated-egress-v1"
	response.Body.Close()
	secure.Close()
	if !valid {
		t.Fatal("benchmark egress marker rejected")
	}
	egressReady := time.Since(started)
	startup := awgBenchmarkCounters(meter)
	fixture := M.Socksaddr{Addr: netip.MustParseAddr("10.203.31.1"), Port: input.Port}
	dataConnection, err := device.DialContext(ctx, N.NetworkTCP, fixture)
	if err != nil {
		t.Fatal("private benchmark stream unavailable")
	}
	defer dataConnection.Close()
	_ = dataConnection.SetDeadline(deadline)
	before := awgBenchmarkCounters(meter)
	cpuBefore := awgBenchmarkCPU(t)
	dataStarted := time.Now()
	if _, err := io.WriteString(dataConnection, "GET /r12-a06-stream HTTP/1.1\r\nHost: owned-awg-lab\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal("private benchmark request failed")
	}
	stream, err := http.ReadResponse(bufio.NewReader(dataConnection), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal("private benchmark response failed")
	}
	defer stream.Body.Close()
	if stream.StatusCode != 200 || stream.Header.Get("X-Pokrov-Benchmark") != "r12-a06-fixture-v1" {
		t.Fatal("private benchmark marker rejected")
	}
	digest := sha256.New()
	count, err := io.Copy(digest, io.LimitReader(stream.Body, 5*1024*1024+1))
	stream.Body.Close()
	dataElapsed := time.Since(dataStarted)
	cpu := awgBenchmarkCPU(t) - cpuBefore
	after := awgBenchmarkCounters(meter)
	if err != nil || count != 5*1024*1024 {
		t.Fatal("bounded benchmark stream incomplete")
	}
	want := sha256.Sum256(bytes.Repeat([]byte{'a'}, 5*1024*1024))
	if !bytes.Equal(digest.Sum(nil), want[:]) {
		t.Fatal("synthetic benchmark data integrity mismatch")
	}
	retransmissions, err := strconv.ParseUint(stream.Trailer.Get("X-Pokrov-TCP-Retrans"), 10, 32)
	if err != nil {
		t.Fatal("server TCP retransmission counter unavailable")
	}
	dataConnection.Close()
	udp, err := device.DialContext(ctx, N.NetworkUDP, fixture)
	if err != nil {
		t.Fatal("private benchmark datagram path unavailable")
	}
	defer udp.Close()
	_ = udp.SetDeadline(time.Now().Add(5 * time.Second))
	type received struct{ unique, duplicate, invalid int }
	done := make(chan received, 1)
	go func() {
		seen := make(map[uint32]bool)
		result := received{}
		buffer := make([]byte, 512)
		for {
			n, readErr := udp.Read(buffer)
			if readErr != nil {
				break
			}
			if n != 256 || string(buffer[:4]) != "A06!" {
				result.invalid++
				continue
			}
			sequence := binary.BigEndian.Uint32(buffer[4:8])
			if sequence >= 100 || !bytes.Equal(buffer[8:n], bytes.Repeat([]byte{'a'}, 248)) {
				result.invalid++
			} else if seen[sequence] {
				result.duplicate++
			} else {
				seen[sequence] = true
				result.unique++
			}
		}
		done <- result
	}()
	packet := bytes.Repeat([]byte{'a'}, 256)
	copy(packet, "A06!")
	for i := uint32(0); i < 100; i++ {
		binary.BigEndian.PutUint32(packet[4:8], i)
		if _, err := udp.Write(packet); err != nil {
			t.Fatal("private benchmark datagram send failed")
		}
		time.Sleep(20 * time.Millisecond)
	}
	datagrams := <-done
	result := map[string]any{
		"preset": input.Preset, "jc": jc, "mtu": input.Endpoint.MTU,
		"tcp_ready_ms": tcpReady.Milliseconds(), "verified_egress_ms": egressReady.Milliseconds(),
		"startup_outer": startup, "data_bytes": count, "data_elapsed_ms": dataElapsed.Milliseconds(),
		"data_cpu_microseconds": cpu.Microseconds(), "data_average_core_percent": cpu.Seconds() / dataElapsed.Seconds() * 100,
		"data_outer":                       map[string]int64{"tx_packets": after["tx_packets"] - before["tx_packets"], "rx_packets": after["rx_packets"] - before["rx_packets"], "tx_udp_payload_bytes": after["tx_udp_payload_bytes"] - before["tx_udp_payload_bytes"], "rx_udp_payload_bytes": after["rx_udp_payload_bytes"] - before["rx_udp_payload_bytes"]},
		"server_tcp_total_retransmissions": retransmissions, "udp_sent": 100, "udp_received_unique": datagrams.unique,
		"udp_lost": 100 - datagrams.unique, "udp_duplicate": datagrams.duplicate, "udp_invalid": datagrams.invalid,
		"load":    "5MiB synthetic download paced at 2Mibit/s; not maximum-throughput measurement",
		"battery": "NOT_MEASURED_NO_BATTERY_DEVICE", "outer_byte_scope": "UDP payload only; excludes outer IP and UDP headers",
	}
	encodedResult, err := json.Marshal(result)
	if err != nil {
		t.Fatal("benchmark result encoding failed")
	}
	t.Log("POKROV_AWG_PRESET_RESULT " + string(encodedResult))
}

func awgBenchmarkCPU(t *testing.T) time.Duration {
	t.Helper()
	var usage syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &usage) != nil {
		t.Fatal("process CPU accounting unavailable")
	}
	return time.Duration(usage.Utime.Sec+usage.Stime.Sec)*time.Second + time.Duration(usage.Utime.Usec+usage.Stime.Usec)*time.Microsecond
}

func awgBenchmarkCounters(meter *ownedLabObservedDialer) map[string]int64 {
	return map[string]int64{"tx_packets": meter.writeCount.Load(), "rx_packets": meter.readCount.Load(), "tx_udp_payload_bytes": meter.writeBytes.Load(), "rx_udp_payload_bytes": meter.readBytes.Load()}
}
