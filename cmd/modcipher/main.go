package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"modcipher"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func main() {
	preferences := preferences{}
	flag.Var(&preferences, "prefer", "")
	flag.Parse()

	for cs, p := range preferences {
		slog.Info("preference", "cipher_suite", cs, "value", p)
	}

	http.DefaultTransport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}
			conn, err := dialer.DialContext(ctx, network, addr)
			return &modcipher.Conn{Conn: conn, Preferences: preferences}, err
		},
		//ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	for _, arg := range flag.Args() {
		resp, err := http.Get(arg)
		if err != nil {
			slog.Error("GET failed", "err", err)
			continue
		}

		b, err := io.ReadAll(resp.Body)
		if err != nil {
			slog.Error("read error", "err", err)
			continue
		}

		var m map[string]interface{}
		if err := json.Unmarshal(b, &m); err == nil {
			s, err := json.MarshalIndent(m, "", "  ")
			if err != nil {
				slog.Error("json marshal failed", "err", err)
			}
			fmt.Println(string(s))
		} else {
			fmt.Println(string(b))
		}

		if err := resp.Body.Close(); err != nil {
			slog.Error("body close failed", "err", err)
		}
	}
}

type preferences map[modcipher.CipherSuite]int

var _ flag.Value = (preferences)(nil)

func (p preferences) String() string {
	return fmt.Sprintf("%#v", p)
}

func (p preferences) Set(s string) error {
	kv := strings.SplitN(s, "=", 2)
	k, err := strconv.ParseInt(kv[0], 16, 32)
	if err != nil {
		return err
	}
	v := 1
	if len(kv) == 2 {
		v, err = strconv.Atoi(kv[1])
		if err != nil {
			return err
		}
	}
	p[modcipher.CipherSuite(k)] = v
	return nil
}
