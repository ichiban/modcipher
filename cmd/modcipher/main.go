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
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	for _, arg := range flag.Args() {
		req, err := http.NewRequest(http.MethodGet, arg, nil)
		if err != nil {
			slog.Error("NewRequest failed", "err", err)
			continue
		}

		req.Header.Set("Accept", "application/json")
		req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9,ja;q=0.8")
		req.Header.Set("Host", "httpbin.org")
		req.Header.Set("Priority", "u=1, i")
		req.Header.Set("Referer", "https,//httpbin.org/")
		req.Header.Set("Sec-Ch-Ua", "\"Not)A;Brand\";v=\"99\", \"Google Chrome\";v=\"127\", \"Chromium\";v=\"127\"")
		req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
		req.Header.Set("Sec-Ch-Ua-Platform", "\"macOS\"")
		req.Header.Set("Sec-Fetch-Dest", "empty")
		req.Header.Set("Sec-Fetch-Mode", "cors")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36")
		req.Header.Set("X-Amzn-Trace-Id", "Root=1-66d2fdf0-41deabbe241611ad5e8c4f6a")

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
	i, err := strconv.ParseInt(s, 16, 32)
	if err != nil {
		return err
	}
	p[modcipher.CipherSuite(i)] = 1
	return nil
}
