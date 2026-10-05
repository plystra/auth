package requestinfo

import (
	"context"
	"net"
)

type Info struct {
	ID    string
	Plane string
	IP    net.IP
}
type key struct{}

func With(ctx context.Context, value Info) context.Context {
	return context.WithValue(ctx, key{}, value)
}
func Get(ctx context.Context) Info { value, _ := ctx.Value(key{}).(Info); return value }
