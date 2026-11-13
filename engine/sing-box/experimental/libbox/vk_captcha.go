package libbox

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sagernet/sing-box/protocol/pokrov/vk"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

// VkCaptchaHandler must post UI work and return immediately. Secrets are
// exchanged only through this instance's callback, never through logs or files.
type VkCaptchaHandler interface {
	ShowVkCaptcha(requestID, challengeURL string)
	CancelVkCaptcha(requestID string)
}

// PrepareVkBridge obtains the relay while the owner Activity is still visible.
// Internet readiness is checked separately through the inner VLESS outbound.
func (s *CommandServer) PrepareVkBridge() error {
	instance := s.StartedService.Instance()
	if instance == nil || instance.Box() == nil {
		return errors.New("VK bridge unavailable")
	}
	out, ok := instance.Box().Outbound().Outbound("vk-tunnel")
	if !ok || out.Type() != "vk" {
		return errors.New("VK bridge unavailable")
	}
	ctx, cancel := context.WithTimeout(instance.Context(), 90*time.Second)
	defer cancel()
	stream, err := out.DialContext(ctx, "tcp", M.Socksaddr{})
	if err != nil {
		return err
	}
	return stream.Close()
}

type vkCaptchaBroker struct {
	sync.Mutex
	handler VkCaptchaHandler
	id      string
	answer  chan string
}

// VkCaptchaSession belongs to one isolated candidate probe.
type VkCaptchaSession struct{ broker *vkCaptchaBroker }

func NewVkCaptchaSession(handler VkCaptchaHandler) *VkCaptchaSession {
	return &VkCaptchaSession{broker: &vkCaptchaBroker{handler: handler}}
}

func (s *VkCaptchaSession) SubmitResult(requestID, token string) bool {
	return s.broker.submit(requestID, token)
}
func (s *VkCaptchaSession) Close() {
	s.broker.Lock()
	s.broker.handler = nil
	if s.broker.answer != nil {
		select {
		case s.broker.answer <- "":
		default:
		}
	}
	s.broker.Unlock()
}

func WithVkCaptcha(ctx context.Context, session *VkCaptchaSession) context.Context {
	if session == nil {
		return ctx
	}
	return service.ContextWith[vk.CaptchaSolver](ctx, session.broker)
}

func (s *CommandServer) SetVkCaptchaHandler(handler VkCaptchaHandler) {
	s.vkCaptcha.Lock()
	s.vkCaptcha.handler = handler
	s.vkCaptcha.Unlock()
}

func (s *CommandServer) SubmitVkCaptchaResult(requestID, token string) bool {
	return s.vkCaptcha.submit(requestID, token)
}

func (b *vkCaptchaBroker) submit(requestID, token string) bool {
	b.Lock()
	defer b.Unlock()
	if b.id != requestID || b.answer == nil {
		return false
	}
	select {
	case b.answer <- token:
		b.id = ""
		return true
	default:
		return false
	}
}

func (b *vkCaptchaBroker) SolveVkCaptcha(ctx context.Context, challengeURL string) (string, error) {
	b.Lock()
	if b.handler == nil || b.answer != nil {
		b.Unlock()
		return "", errors.New("VK verification unavailable")
	}
	id, answer, handler := uuid.NewString(), make(chan string, 1), b.handler
	b.id, b.answer = id, answer
	b.Unlock()
	defer func() {
		b.Lock()
		b.id, b.answer = "", nil
		b.Unlock()
		handler.CancelVkCaptcha(id)
	}()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	handler.ShowVkCaptcha(id, challengeURL)
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case token := <-answer:
		if token == "" {
			return "", errors.New("VK verification cancelled")
		}
		return token, nil
	}
}
