package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mahsanet/dnstt/noise"
	mts "github.com/sagernet/sing-box/protocol/pokrov/mtscarrier"
	kcp "github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
)

func main() {
	board := flag.String("board", "", "MTS board URL")
	keyPath := flag.String("key", "", "private key file")
	apiUpstream := flag.String("api-upstream", "", "fixed API host and port")
	public := flag.Bool("public-key", false, "print public key and exit")
	flag.Parse()
	if *keyPath == "" {
		log.Fatal("key file is required")
	}
	key, err := loadKey(*keyPath)
	if err != nil {
		log.Fatal(err)
	}
	if *public {
		fmt.Println(noise.EncodeKey(noise.PubkeyFromPrivkey(key)))
		return
	}
	if *board == "" || *apiUpstream == "" {
		log.Fatal("board URL and API upstream are required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	d := net.Dialer{}
	carrier := mts.NewUncompressedTransport(*board, mts.DefaultConfig(), d.DialContext)
	packet, err := mts.NewPacketConn(carrier, true)
	if err != nil {
		log.Fatal(err)
	}
	if err = carrier.Start(); err != nil {
		log.Fatal(err)
	}
	defer packet.Close()
	listener, err := kcp.ServeConn(nil, 0, 0, packet)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	go func() { <-ctx.Done(); listener.Close() }()
	slots := make(chan struct{}, 128)
	for {
		conn, err := listener.AcceptKCP()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Fatal(err)
		}
		select {
		case slots <- struct{}{}:
			go func() { defer func() { <-slots }(); serve(conn, key, *apiUpstream) }()
		default:
			conn.Close()
		}
	}
}
func loadKey(path string) ([]byte, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		key, e := noise.GeneratePrivkey()
		if e != nil {
			return nil, e
		}
		f, e = os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return nil, e
		}
		e = noise.WriteKey(f, key)
		if closeErr := f.Close(); e == nil {
			e = closeErr
		}
		return key, e
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return noise.ReadKey(f)
}
func serve(conn *kcp.UDPSession, key []byte, apiUpstream string) {
	defer conn.Close()
	conn.SetStreamMode(true)
	conn.SetNoDelay(0, 0, 0, 1)
	conn.SetWindowSize(128, 128)
	conn.SetMtu(1200)
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	secure, err := noise.NewServer(conn, key)
	if err != nil {
		return
	}
	defer secure.Close()
	conn.SetDeadline(time.Time{})
	cfg := smux.DefaultConfig()
	cfg.Version = 2
	cfg.KeepAliveTimeout = 2 * time.Minute
	cfg.MaxStreamBuffer = 1 << 20
	mux, err := smux.Server(secure, cfg)
	if err != nil {
		return
	}
	defer mux.Close()
	for {
		stream, err := mux.AcceptStream()
		if err != nil {
			return
		}
		go func() {
			defer stream.Close()
			stream.SetReadDeadline(time.Now().Add(10 * time.Second))
			var service [1]byte
			if _, err := io.ReadFull(stream, service[:]); err != nil {
				return
			}
			stream.SetReadDeadline(time.Time{})
			target := "127.0.0.1:12543"
			if service[0] == 1 {
				target = apiUpstream
			} else if service[0] != 0 {
				return
			}
			dst, err := net.DialTimeout("tcp", target, 10*time.Second)
			if err != nil {
				return
			}
			defer dst.Close()
			go io.Copy(dst, stream)
			io.Copy(stream, dst)
		}()
	}
}
