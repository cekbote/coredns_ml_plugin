package mlplugin

import (
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/caddyserver/caddy"
)

func init() {
	caddy.RegisterPlugin("mlplugin", caddy.Plugin{
		ServerType: "dns",
		Action:     setup,
	})
}

func setup(c *caddy.Controller) error {
	c.Next() // 'mlplugin'
	if c.NextArg() {
		return plugin.Error("mlplugin", c.ArgErr())
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return Mlplugin{}
	})

	return nil
}