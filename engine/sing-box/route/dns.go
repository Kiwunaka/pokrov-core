package route

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	dnsOutbound "github.com/sagernet/sing-box/protocol/dns"
	R "github.com/sagernet/sing-box/route/rule"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
)

func (r *Router) hijackDNSStream(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	r.searchProcessInfo(ctx, &metadata)
	metadata.Destination = M.Socksaddr{}
	err := N.ReportConnHandshakeSuccess(conn, conn)
	if err != nil {
		return E.Cause(err, "report handshake success")
	}
	for {
		conn.SetReadDeadline(time.Now().Add(C.DNSTimeout))
		err = dnsOutbound.HandleStreamDNSRequest(ctx, r.dns, conn, metadata)
		if err != nil {
			if !E.IsClosedOrCanceled(err) {
				return err
			} else {
				return nil
			}
		}
	}
}

func (r *Router) hijackDNSPacket(ctx context.Context, conn N.PacketConn, packetBuffers []*N.PacketBuffer, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) error {
	r.searchProcessInfo(ctx, &metadata)
	err := N.ReportPacketConnHandshakeSuccess(conn, nil)
	if err != nil {
		N.ReleaseMultiPacketBuffer(packetBuffers)
		err = E.Cause(err, "report handshake success")
	} else {
		err = dnsOutbound.NewDNSPacketConnection(ctx, r.dns, conn, packetBuffers, metadata)
	}
	N.CloseOnHandshakeFailure(conn, onClose, err)
	if err != nil && !E.IsClosedOrCanceled(err) {
		return E.Cause(err, "process DNS packet")
	}
	return nil
}

func (r *Router) HijackDNSPacket(ctx context.Context, payload []byte, writer N.PacketWriter, metadata adapter.InboundContext) {
	var message mDNS.Msg
	err := message.Unpack(payload)
	if err != nil {
		r.logger.ErrorContext(ctx, E.Cause(err, "process DNS packet: unpack request"))
		return
	}
	var trace adapter.OwnedDNSProbeTrace
	if isOwnedDNSProbeQuestion(&message) {
		trace = service.FromContext[adapter.OwnedDNSProbeTrace](ctx)
		if trace != nil && !trace(ctx, adapter.OwnedDNSProbeReceive, nil) {
			trace = nil
		}
	}
	r.searchProcessInfo(ctx, &metadata)
	destination := metadata.Destination
	metadata.Destination = M.Socksaddr{}
	r.dns.ExchangeAsync(adapter.WithContext(ctx, &metadata), &message, adapter.DNSQueryOptions{}, func(response *mDNS.Msg, exchangeErr error) {
		if trace != nil {
			trace(ctx, adapter.OwnedDNSProbeExchange, exchangeErr)
		}
		if exchangeErr == nil {
			exchangeErr = r.writeDNSPacketResponse(&message, response, writer, destination)
			if trace != nil {
				trace(ctx, adapter.OwnedDNSProbeReply, exchangeErr)
			}
		}
		if exchangeErr != nil && !R.IsRejected(exchangeErr) && !E.IsClosedOrCanceled(exchangeErr) {
			r.logger.ErrorContext(ctx, E.Cause(exchangeErr, "process DNS packet"))
		}
	})
}

func isOwnedDNSProbeQuestion(message *mDNS.Msg) bool {
	if message.Response || message.Opcode != mDNS.OpcodeQuery || len(message.Question) != 1 {
		return false
	}
	question := message.Question[0]
	return question.Qclass == mDNS.ClassINET && question.Qtype == mDNS.TypeA &&
		(strings.EqualFold(question.Name, "api.pokrov.space.") || strings.EqualFold(question.Name, "pokrov.space."))
}

func (r *Router) writeDNSPacketResponse(message *mDNS.Msg, response *mDNS.Msg, writer N.PacketWriter, destination M.Socksaddr) error {
	responseBuffer, err := dns.TruncateDNSMessage(message, response, N.CalculateFrontHeadroom(writer), N.CalculateRearHeadroom(writer))
	if err != nil {
		return err
	}
	return writer.WritePacket(responseBuffer, destination)
}
