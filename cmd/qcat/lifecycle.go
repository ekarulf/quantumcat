package main

import (
	"context"
)

func clientContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithCancel(parent)
}
