package tf_test

import (
	"context"
	"crypto/tls"
	"net"
	"testing"

	tf "github.com/sagernet/sing-box/common/tlsfragment"

	"github.com/stretchr/testify/require"
)

type emptyWriteConn struct{ net.Conn }

func (emptyWriteConn) Write([]byte) (int, error) { return 0, nil }

func TestEmptyWriteKeepsFragmentation(t *testing.T) {
	conn := tf.NewConn(emptyWriteConn{}, context.Background(), true, false, 0)
	n, err := conn.Write(nil)
	require.NoError(t, err)
	require.Zero(t, n)
	require.False(t, conn.WriterReplaceable(), "empty writes must not allow bypassing ClientHello fragmentation")
}

func TestTLSFragment(t *testing.T) {
	t.Parallel()
	tcpConn, err := net.Dial("tcp", "1.1.1.1:443")
	require.NoError(t, err)
	tlsConn := tls.Client(tf.NewConn(tcpConn, context.Background(), true, false, 0), &tls.Config{
		ServerName: "www.cloudflare.com",
	})
	require.NoError(t, tlsConn.Handshake())
}

func TestTLSRecordFragment(t *testing.T) {
	t.Parallel()
	tcpConn, err := net.Dial("tcp", "1.1.1.1:443")
	require.NoError(t, err)
	tlsConn := tls.Client(tf.NewConn(tcpConn, context.Background(), false, true, 0), &tls.Config{
		ServerName: "www.cloudflare.com",
	})
	require.NoError(t, tlsConn.Handshake())
}

func TestTLS2Fragment(t *testing.T) {
	t.Parallel()
	tcpConn, err := net.Dial("tcp", "1.1.1.1:443")
	require.NoError(t, err)
	tlsConn := tls.Client(tf.NewConn(tcpConn, context.Background(), true, true, 0), &tls.Config{
		ServerName: "www.cloudflare.com",
	})
	require.NoError(t, tlsConn.Handshake())
}
