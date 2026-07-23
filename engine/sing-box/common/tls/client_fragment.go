package tls

import (
	"context"
	"net"
	"time"

	tf "github.com/sagernet/sing-box/common/tlsfragment"
)

func wrapClientHelloFragment(
	ctx context.Context,
	conn net.Conn,
	fragment bool,
	recordFragment bool,
	fallbackDelay time.Duration,
) net.Conn {
	if !fragment && !recordFragment {
		return conn
	}
	return tf.NewConn(conn, ctx, fragment, recordFragment, fallbackDelay)
}
