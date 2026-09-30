package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/prometheus/client_golang/prometheus"
)

// Hub fans out live events (decisions, approvals, tool changes) to dashboards.
type Hub struct {
	mu      sync.Mutex
	clients map[chan []byte]struct{}
}

func NewHub() *Hub { return &Hub{clients: map[chan []byte]struct{}{}} }

func (h *Hub) Broadcast(kind string, data any) {
	msg, err := json.Marshal(map[string]any{"type": kind, "data": data})
	if err != nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for c := range h.clients {
		select {
		case c <- msg:
		default: // slow client: drop rather than block the gateway
		}
	}
}

func (h *Hub) serve(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer conn.CloseNow()
	ch := make(chan []byte, 128)
	h.mu.Lock()
	h.clients[ch] = struct{}{}
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.clients, ch)
		h.mu.Unlock()
	}()
	ctx := conn.CloseRead(r.Context())
	ping := time.NewTicker(25 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-ch:
			wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			err := conn.Write(wctx, websocket.MessageText, msg)
			cancel()
			if err != nil {
				return
			}
		case <-ping.C:
			if err := conn.Ping(ctx); err != nil {
				return
			}
		}
	}
}

type Metrics struct {
	Registry  *prometheus.Registry
	decisions *prometheus.CounterVec
	overhead  prometheus.Histogram
	stages    *prometheus.HistogramVec
}

func NewMetrics() *Metrics {
	m := &Metrics{
		Registry: prometheus.NewRegistry(),
		decisions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "gateway_decisions_total", Help: "Tool-call decisions by verdict.",
		}, []string{"verdict"}),
		overhead: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "gateway_overhead_seconds", Help: "Time the gateway adds per tool call (excludes tool and human time).",
			Buckets: []float64{.0001, .00025, .0005, .001, .0025, .005, .01, .025, .05, .1},
		}),
		stages: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "gateway_stage_seconds", Help: "Time per pipeline stage.",
			Buckets: []float64{.00001, .00005, .0001, .0005, .001, .005, .01, .05},
		}, []string{"stage"}),
	}
	m.Registry.MustRegister(m.decisions, m.overhead, m.stages)
	return m
}

func (m *Metrics) Observe(verdict string, overhead time.Duration, stages map[string]int64) {
	m.decisions.WithLabelValues(verdict).Inc()
	m.overhead.Observe(overhead.Seconds())
	for s, us := range stages {
		if s == "upstream" || s == "approval_wait" {
			continue
		}
		m.stages.WithLabelValues(s).Observe(float64(us) / 1e6)
	}
}
