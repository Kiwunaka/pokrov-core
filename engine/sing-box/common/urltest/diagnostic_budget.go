package urltest

import (
	"context"
	"errors"
	"sync"
)

var ErrDiagnosticByteBudget = errors.New("diagnostic byte budget exhausted")

// DiagnosticByteBudget is one operation's reservation ledger, shared by its
// children. It does not infer byte counts from attempts, elapsed time or results.
// An IO producer must reserve a bound before work and account for all network
// bytes of each probe, including DNS, handshakes, headers and retransmissions.
// This ledger alone cannot measure or enforce that host wire boundary.
type DiagnosticByteBudget struct {
	access sync.Mutex
	ctx context.Context
	cancel context.CancelCauseFunc
	limit int64
	reserved int64
	exhausted bool
}

// The ceiling matches max_diagnostic_bytes in the signed transport budget.
// It is a schema limit, not a default allowance for any probe or operation.
func NewDiagnosticByteBudget(parent context.Context, limit int64) (*DiagnosticByteBudget, error) {
	if limit < 0 || limit > 67108864 {
		return nil, errors.New("invalid diagnostic byte budget")
	}
	ctx, cancel := context.WithCancelCause(parent)
	return &DiagnosticByteBudget{ctx: ctx, cancel: cancel, limit: limit}, nil
}

// Context is cancelled on parent cancellation, explicit close or over-budget
// reservation. Children must use it for their dial/read/write lifetimes.
func (b *DiagnosticByteBudget) Context() context.Context { return b.ctx }

// Reserve consumes allowance before IO. It is never refunded: a failed or
// cancelled diagnostic cannot reset the operation's accounting for a retry.
// Exceeding the allowance cancels all children, without admitting the request.
func (b *DiagnosticByteBudget) Reserve(count int64) error {
	b.access.Lock()
	defer b.access.Unlock()
	if err := context.Cause(b.ctx); err != nil {
		return err
	}
	if count <= 0 {
		return errors.New("invalid diagnostic byte reservation")
	}
	if count > b.limit-b.reserved {
		b.exhausted = true
		b.cancel(ErrDiagnosticByteBudget)
		return ErrDiagnosticByteBudget
	}
	b.reserved += count
	return nil
}

// Snapshot reports reserved allowances, never observed traffic or wire bytes.
// Only callers that retain this same object can account for sibling work.
func (b *DiagnosticByteBudget) Snapshot() (limit, reserved int64, closed, exhausted bool) {
	b.access.Lock()
	defer b.access.Unlock()
	return b.limit, b.reserved, b.ctx.Err() != nil, b.exhausted
}

// Close cancels children but does not erase reservations or grant a fresh budget.
// Cancellation alone does not acknowledge that every child has stopped.
func (b *DiagnosticByteBudget) Close() {
	b.access.Lock()
	defer b.access.Unlock()
	b.cancel(context.Canceled)
}
