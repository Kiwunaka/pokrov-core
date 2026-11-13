package libbox

import (
	"context"
	"testing"
	"time"
)

type vkTestHandler struct {
	shown     chan string
	cancelled chan string
}

func (h vkTestHandler) ShowVkCaptcha(id, _ string) { h.shown <- id }
func (h vkTestHandler) CancelVkCaptcha(id string)  { h.cancelled <- id }

func TestVkCaptchaCancellationRejectsLateAnswer(t *testing.T) {
	handler := vkTestHandler{make(chan string, 2), make(chan string, 2)}
	s := &CommandServer{vkCaptcha: &vkCaptchaBroker{handler: handler}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := s.vkCaptcha.SolveVkCaptcha(ctx, "https://vk.com/not_robot_captcha"); done <- err }()
	id := <-handler.shown
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled challenge succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("challenge did not stop")
	}
	if got := <-handler.cancelled; got != id {
		t.Fatal("different challenge cancelled")
	}
	if s.SubmitVkCaptchaResult(id, "late") {
		t.Fatal("late answer accepted")
	}
	go func() {
		_, err := s.vkCaptcha.SolveVkCaptcha(context.Background(), "https://vk.com/not_robot_captcha")
		done <- err
	}()
	newID := <-handler.shown
	if s.SubmitVkCaptchaResult(id, "old") || !s.SubmitVkCaptchaResult(newID, "current") || s.SubmitVkCaptchaResult(newID, "duplicate") {
		t.Fatal("answer ownership failed")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestVkCaptchaAnswerIsInstanceBound(t *testing.T) {
	handler := vkTestHandler{make(chan string, 1), make(chan string, 1)}
	a := &CommandServer{vkCaptcha: &vkCaptchaBroker{handler: handler}}
	b := &CommandServer{vkCaptcha: &vkCaptchaBroker{}}
	done := make(chan string, 1)
	go func() {
		token, _ := a.vkCaptcha.SolveVkCaptcha(context.Background(), "https://vk.com/not_robot_captcha")
		done <- token
	}()
	id := <-handler.shown
	if b.SubmitVkCaptchaResult(id, "wrong owner") {
		t.Fatal("different runtime accepted answer")
	}
	if !a.SubmitVkCaptchaResult(id, "answer") || <-done != "answer" {
		t.Fatal("answer lost")
	}
}

func TestVkCaptchaProbeCloseStopsPendingCheck(t *testing.T) {
	handler := vkTestHandler{make(chan string, 1), make(chan string, 1)}
	session := NewVkCaptchaSession(handler)
	done := make(chan error, 1)
	go func() {
		_, err := session.broker.SolveVkCaptcha(context.Background(), "https://vk.com/not_robot_captcha")
		done <- err
	}()
	id := <-handler.shown
	session.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("closed probe returned a verification answer")
		}
	case <-time.After(time.Second):
		t.Fatal("closed probe kept waiting")
	}
	if session.SubmitResult(id, "late") {
		t.Fatal("closed probe accepted a late answer")
	}
}
