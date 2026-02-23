package proxy

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"promptshield/internal/classifier"
	"promptshield/internal/config"
	"promptshield/internal/policy"
)

func BenchmarkProxy(b *testing.B) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	pr := &Proxy{transport: transport, policy: policy.NewRuleEngine(nil), classifier: classifier.HostClassifier{}, audit: &memoryAudit{}, mitmCfg: config.MITM{}}
	proxySrv := httptest.NewServer(http.HandlerFunc(pr.handle))
	defer proxySrv.Close()

	client := proxyClient(proxySrv.URL, nil)

	b.Run("serial", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			start := time.Now()
			resp, err := client.Get(upstream.URL + "/bench")
			if err != nil {
				b.Fatalf("request failed: %v", err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			b.ReportMetric(float64(time.Since(start).Microseconds()), "us/op_latency")
		}
	})

	for _, concurrency := range []int{10, 100} {
		concurrency := concurrency
		b.Run("concurrency_"+strconv.Itoa(concurrency), func(b *testing.B) {
			samples := runLoad(client, upstream.URL+"/bench", b.N, concurrency, b)
			reportLatencyStats(b, samples)
		})
	}
}

func runLoad(client *http.Client, url string, n, concurrency int, b *testing.B) []time.Duration {
	if n <= 0 {
		return nil
	}
	samples := make([]time.Duration, n)
	jobs := make(chan int)
	errs := make(chan error, concurrency)
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for idx := range jobs {
			start := time.Now()
			resp, err := client.Get(url)
			if err != nil {
				errs <- err
				continue
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			samples[idx] = time.Since(start)
		}
	}

	if concurrency > n {
		concurrency = n
	}
	wg.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		go worker()
	}
	for i := 0; i < n; i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			b.Fatalf("request failed: %v", err)
		}
	}
	return samples
}

func reportLatencyStats(b *testing.B, samples []time.Duration) {
	if len(samples) == 0 {
		return
	}
	vals := append([]time.Duration(nil), samples...)
	sort.Slice(vals, func(i, j int) bool { return vals[i] < vals[j] })

	var total time.Duration
	for _, d := range vals {
		total += d
	}
	avg := total / time.Duration(len(vals))
	p50 := percentile(vals, 0.50)
	p95 := percentile(vals, 0.95)
	p99 := percentile(vals, 0.99)

	b.ReportMetric(float64(avg.Microseconds()), "us/avg")
	b.ReportMetric(float64(p50.Microseconds()), "us/p50")
	b.ReportMetric(float64(p95.Microseconds()), "us/p95")
	b.ReportMetric(float64(p99.Microseconds()), "us/p99")
	b.Logf("latency report: avg=%v p50=%v p95=%v p99=%v", avg, p50, p95, p99)
}

func percentile(vals []time.Duration, p float64) time.Duration {
	if len(vals) == 0 {
		return 0
	}
	idx := int(float64(len(vals)-1) * p)
	if idx < 0 {
		idx = 0
	}
	if idx >= len(vals) {
		idx = len(vals) - 1
	}
	return vals[idx]
}
