package infra

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// BGPClient abstracts BGP upstream lookups for testing.
type BGPClient interface {
	LookupUpstreams(ctx context.Context, asn int) ([]int, error)
}

// bgpToolsClient queries bgp.tools via TCP whois.
type bgpToolsClient struct {
	addr string
}

// NewBGPClient returns a BGPClient that queries bgp.tools on port 43.
func NewBGPClient() BGPClient {
	return &bgpToolsClient{addr: "bgp.tools:43"}
}

func (c *bgpToolsClient) LookupUpstreams(ctx context.Context, asn int) ([]int, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", c.addr)
	if err != nil {
		return nil, fmt.Errorf("bgp.tools dial: %w", err)
	}
	defer conn.Close()

	query := fmt.Sprintf("AS%d\n", asn)
	if _, err := conn.Write([]byte(query)); err != nil {
		return nil, fmt.Errorf("bgp.tools write: %w", err)
	}

	return ParseBGPUpstreams(bufio.NewScanner(conn))
}

// ParseBGPUpstreams parses the whois-style response from bgp.tools,
// looking for upstream ASN numbers. The response format includes lines like:
//
//	Upstreams:    AS174, AS3356
func ParseBGPUpstreams(scanner *bufio.Scanner) ([]int, error) {
	var upstreams []int
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "Upstreams:") {
			continue
		}
		// Extract the value part after "Upstreams:"
		parts := strings.SplitN(line, ":", 2)
		if len(parts) < 2 {
			continue
		}
		value := strings.TrimSpace(parts[1])
		if value == "" || value == "None" {
			return nil, nil
		}
		for _, tok := range strings.Split(value, ",") {
			tok = strings.TrimSpace(tok)
			tok = strings.TrimPrefix(tok, "AS")
			tok = strings.TrimPrefix(tok, "as")
			if tok == "" {
				continue
			}
			n, err := strconv.Atoi(tok)
			if err != nil {
				continue
			}
			upstreams = append(upstreams, n)
		}
		break
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("bgp.tools read: %w", err)
	}
	return upstreams, nil
}
