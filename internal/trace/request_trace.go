package trace

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	mathrand "math/rand"
	"sync"
	"time"
)

type requestTraceContextKey string

const traceContextKey requestTraceContextKey = "trace"

type RequestTrace struct {
	ID string

	Start time.Time

	SanitizeStart time.Time
	SanitizeEnd   time.Time

	UpstreamStart time.Time
	FirstByte     time.Time
	UpstreamEnd   time.Time

	ResponseStart time.Time
	ResponseEnd   time.Time

	IsStreaming bool
	Sampled     bool

	logOnce sync.Once
}

func NewRequestTrace() *RequestTrace {
	return &RequestTrace{
		ID:      newTraceID(),
		Start:   time.Now(),
		Sampled: mathrand.Float64() <= 0.1,
	}
}

func newTraceID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("trace-%d", time.Now().UnixNano())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4],
		b[4:6],
		b[6:8],
		b[8:10],
		b[10:16],
	)
}

func WithContext(ctx context.Context, tr *RequestTrace) context.Context {
	if tr == nil {
		return ctx
	}
	return context.WithValue(ctx, traceContextKey, tr)
}

func FromContext(ctx context.Context) (*RequestTrace, bool) {
	if ctx == nil {
		return nil, false
	}
	tr, ok := ctx.Value(traceContextKey).(*RequestTrace)
	return tr, ok
}

func (t *RequestTrace) TrackingReadCloser(rc io.ReadCloser, onClose func()) io.ReadCloser {
	return &trackingReadCloser{rc: rc, onClose: onClose}
}

func (t *RequestTrace) LogAt(end time.Time) {
	if t == nil || !t.Sampled {
		return
	}
	t.logOnce.Do(func() {
		total := durationBetween(t.Start, end)
		sanitize := durationBetween(t.SanitizeStart, t.SanitizeEnd)
		ttfb := durationBetween(t.UpstreamStart, t.FirstByte)
		upstream := durationBetween(t.UpstreamStart, t.UpstreamEnd)
		response := durationBetween(t.ResponseStart, t.ResponseEnd)
		firstByteLatency := durationBetween(t.Start, t.FirstByte)

		log.Printf(
			"trace=%s total=%v sanitize=%v ttfb=%v upstream=%v response=%v first_byte_latency=%v streaming=%v",
			t.ID,
			total,
			sanitize,
			ttfb,
			upstream,
			response,
			firstByteLatency,
			t.IsStreaming,
		)
	})
}

func durationBetween(start, end time.Time) time.Duration {
	if start.IsZero() || end.IsZero() || end.Before(start) {
		return 0
	}
	return end.Sub(start)
}

type trackingReadCloser struct {
	rc      io.ReadCloser
	onClose func()
	once    sync.Once
}

func (t *trackingReadCloser) Read(p []byte) (int, error) {
	return t.rc.Read(p)
}

func (t *trackingReadCloser) Close() error {
	err := t.rc.Close()
	t.once.Do(func() {
		if t.onClose != nil {
			t.onClose()
		}
	})
	return err
}
