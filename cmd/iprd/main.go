package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"iprd/internal/auth"
	"iprd/internal/control"
	"iprd/internal/diagnostic"
	"iprd/internal/proxy"
	"iprd/internal/relay"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "iprd:", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 {
		usage()
		return nil
	}
	switch os.Args[1] {
	case "auth":
		flags := flag.NewFlagSet("auth", flag.ContinueOnError)
		var options auth.Options
		flags.StringVar(&options.StateDir, "anisette-state", "runtime/anisette", "Anisette v3 identity and provisioning directory")
		flags.StringVar(&options.ServerURL, "anisette-server", "https://new.ani.sidestore.io", "Anisette v3 provider")
		flags.StringVar(&options.Output, "output", "runtime/account.json", "MobileMe credential output")
		flags.StringVar(&options.AccountRequest, "account-request", "", "Read account name from a saved init request plist")
		flags.StringVar(&options.DebugDir, "debug-dir", "", "Save raw authentication protocol diagnostics in this directory")
		flags.BoolVar(&options.InitOnly, "init-only", false, "Only request the SRP challenge, without a password")
		if err := flags.Parse(os.Args[2:]); err != nil {
			return err
		}
		return auth.Run(context.Background(), options)
	case "csf":
		flags := flag.NewFlagSet("csf", flag.ContinueOnError)
		account := flags.String("account", "runtime/account.json", "MobileMe credential file")
		output := flags.String("output", "runtime/csf.json", "CSF subscriber response output")
		if err := flags.Parse(os.Args[2:]); err != nil {
			return err
		}
		return auth.ExchangeCSF(context.Background(), *account, *output)
	case "serve":
		flags := flag.NewFlagSet("serve", flag.ContinueOnError)
		var options control.Options
		controlFlags(flags, &options)
		listen := flags.String("listen", "0.0.0.0:1080", "SOCKS5 and HTTP proxy listen address")
		if err := flags.Parse(os.Args[2:]); err != nil {
			return err
		}
		if _, err := relay.ParseTransport(options.Transport); err != nil {
			return err
		}
		if _, err := relay.ParseGeohash(options.Geohash); err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		manager, err := control.NewManager(ctx, options, stderrf)
		if err != nil {
			return err
		}
		defer manager.Close()
		dialer, err := relay.NewManaged(ctx, manager, stderrf)
		if err != nil {
			return err
		}
		defer dialer.Close()
		if err := dialer.SetTransport(relay.Transport(options.Transport)); err != nil {
			return err
		}
		if err := dialer.SetGeohash(options.Geohash); err != nil {
			return err
		}
		return proxy.Serve(ctx, *listen, dialer.DialContext, stderrf)
	case "debug":
		flags := flag.NewFlagSet("debug", flag.ContinueOnError)
		var options diagnostic.Options
		controlFlags(flags, &options.Control)
		flags.StringVar(&options.URL, "url", "https://api.ipify.org/", "Target URL for the full relay diagnostic")
		flags.StringVar(&options.UDP, "udp", "", "Run a UDP DNS diagnostic against HOST:PORT instead of the HTTP target")
		flags.DurationVar(&options.Timeout, "timeout", 45*time.Second, "Overall diagnostic timeout; 0 disables it")
		flags.BoolVar(&options.ListOnly, "list", false, "List signed configuration endpoints and paths without account authentication")
		flags.BoolVar(&options.JSON, "json", false, "Write the diagnostic report as JSON")
		if err := flags.Parse(os.Args[2:]); err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return diagnostic.Run(ctx, options, os.Stdout, os.Stderr)
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		return fmt.Errorf("unknown command %q", os.Args[1])
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "iprd — iCloud Private Relay Daemon")
	fmt.Fprintln(os.Stderr, "  iprd auth  [--anisette-state DIR] [--output FILE] [--init-only]")
	fmt.Fprintln(os.Stderr, "  iprd csf   [--account FILE] [--output FILE]")
	fmt.Fprintln(os.Stderr, "  iprd serve [--account FILE] [--listen 0.0.0.0:1080] [--transport auto|h3|h2] [--config-proxy URL] [--geohash auto|GEOHASH] [--ingress VENDOR|HOST] [--egress VENDOR|HOST]")
	fmt.Fprintln(os.Stderr, "  iprd debug [--list] [--json] [--url URL | --udp HOST:PORT] [--transport auto|h3|h2] [--config-proxy URL] [--geohash auto|GEOHASH] [--ingress VENDOR|HOST] [--egress VENDOR|HOST]")
}

func controlFlags(flags *flag.FlagSet, options *control.Options) {
	flags.StringVar(&options.Account, "account", "runtime/account.json", "MobileMe credential file")
	flags.StringVar(&options.Subscription, "subscription", "", "Use a supplied CSF response file")
	flags.StringVar(&options.StateDir, "anisette-state", "runtime/anisette", "Anisette v3 identity and provisioning directory")
	flags.StringVar(&options.ServerURL, "anisette-server", "https://new.ani.sidestore.io", "Anisette v3 provider")
	flags.IntVar(&options.TokenTarget, "token-pool-size", 60, "In-memory token pool target per hop; refill at half this count")
	flags.StringVar(&options.Transport, "transport", "auto", "Relay transport mode: auto, h3, or h2")
	flags.StringVar(&options.ConfigProxy, "config-proxy", "", "Upstream proxy URL (http, https, socks5, socks5h) for fetching the relay configuration")
	flags.StringVar(&options.Geohash, "geohash", "", "Egress Sec-CH-Geohash: omit (default, do not send), auto (forward ingress Client-Geohash), or a 4-character geohash")
	flags.StringVar(&options.ClientInfo, "client-info", control.DefaultClientInfo, "X-Mask-Client-Info for configuration and token issuance")
	preferenceFlag(flags, &options.Preferences.Ingress, "ingress")
	preferenceFlag(flags, &options.Preferences.Egress, "egress")
}

func preferenceFlag(flags *flag.FlagSet, destination *[]string, name string) {
	flags.Func(name, "Preferred "+name+" vendor or hostname, in order; repeat or separate with commas", func(value string) error {
		for _, item := range strings.Split(value, ",") {
			if item = strings.TrimSpace(item); item != "" {
				*destination = append(*destination, item)
			}
		}
		return nil
	})
}

func stderrf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}
