package transport

import (
	"context"
	"time"

	"github.com/tailscale/tailcat"
)

// Maintain refreshes the authenticated lease without closing application flows.
// Failed attempts leave traffic state intact and retry while the caller lives.
func Maintain(ctx context.Context, c *tailcat.Client, report func(error)) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	watch(ctx, c.Renew, c.Probe, c.RefreshNetwork, RenewInterval, 5*time.Second, ticker.C, time.Now, report)
}

func maintain(ctx context.Context, renew func(context.Context) error, interval, retry time.Duration, report func(error)) {
	step := min(interval, retry, 5*time.Second)
	ticker := time.NewTicker(step)
	defer ticker.Stop()
	watch(ctx, renew, nil, nil, interval, retry, ticker.C, time.Now, report)
}

// Use wall time: macOS's monotonic clock can stop during sleep. Read the clock
// after receiving a tick rather than trusting a stale buffered ticker value.
func watch(ctx context.Context, renew, probe func(context.Context) error, refresh func() error,
	interval, retry time.Duration, ticks <-chan time.Time, now func() time.Time, report func(error)) {
	last := now().Round(0)
	nextRenew, nextProbe := last.Add(interval), last.Add(30*time.Second)
	recovering := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticks:
		}
		current := now().Round(0)
		gap := current.Sub(last)
		last = current
		if gap > 15*time.Second || gap < 0 {
			recovering = true
			nextRenew = current
		}
		if !recovering && probe != nil && !current.Before(nextProbe) {
			probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := probe(probeCtx)
			cancel()
			if err != nil {
				recovering = true
				nextRenew = current
			}
			nextProbe = now().Round(0).Add(30 * time.Second)
		}
		if ctx.Err() != nil {
			return
		}
		if current.Before(nextRenew) {
			last = now().Round(0)
			continue
		}
		var err error
		if recovering && refresh != nil {
			err = refresh()
		}
		if err == nil {
			err = renew(ctx)
		}
		if err == nil && recovering && probe != nil {
			probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err = probe(probeCtx)
			cancel()
		}
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			if report != nil {
				report(err)
			}
			recovering = true
			nextRenew = now().Round(0).Add(retry)
		} else {
			recovering = false
			nextRenew = now().Round(0).Add(interval)
			nextProbe = now().Round(0).Add(30 * time.Second)
		}
		last = now().Round(0)
	}
}
