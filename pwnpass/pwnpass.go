// Package pwnpass implements a client for the Pwned Passwords API.
package pwnpass

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/clfs/m/ntlm"
)

const defaultBaseURL = "https://api.pwnedpasswords.com"

// ErrInvalidPrefix is returned when an invalid hash prefix is provided.
var ErrInvalidPrefix = errors.New("invalid prefix")

var isValidPrefix = regexp.MustCompile(`^[0-9A-Fa-f]{5}$`)

func newBag(r io.Reader) (map[string]int, error) {
	m := make(map[string]int)
	s := bufio.NewScanner(r)
	for s.Scan() {
		line := s.Text()

		suffix, freq, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("malformed response: %q", line)
		}

		n, err := strconv.Atoi(freq)
		if err != nil {
			return nil, fmt.Errorf("malformed response: %q", line)
		}

		switch {
		case n < 0:
			return nil, fmt.Errorf("malformed response: %q", line)
		case n == 0:
			continue // skip padding lines
		default:
			m[suffix] = n
		}
	}
	return m, s.Err()
}

// Client is a client for the Pwned Passwords API.
//
// [Privacy-enhancing padding] is enabled by default.
//
// [Privacy-enhancing padding]: https://haveibeenpwned.com/API/v3#PwnedPasswordsPadding
type Client struct {
	h       *http.Client
	baseURL string
}

// NewClient returns a new Client.
func NewClient() *Client {
	return &Client{
		h:       http.DefaultClient,
		baseURL: defaultBaseURL,
	}
}

// SetHTTPClient sets a custom HTTP client.
func (c *Client) SetHTTPClient(h *http.Client) {
	c.h = h
}

func (c *Client) search(ctx context.Context, prefix string, ntlm bool) (map[string]int, error) {
	if !isValidPrefix.MatchString(prefix) {
		return nil, ErrInvalidPrefix
	}

	rawURL := c.baseURL + "/range/" + prefix
	if ntlm {
		rawURL += "?mode=ntlm"
	}

	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Add-Padding", "true")

	resp, err := c.h.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return newBag(resp.Body)
}

// SearchSHA1 searches for password hash suffixes by SHA-1 prefix.
func (c *Client) SearchSHA1(ctx context.Context, prefix string) (map[string]int, error) {
	return c.search(ctx, prefix, false)
}

// SearchNTLM searches for password hash suffixes by NTLM prefix.
func (c *Client) SearchNTLM(ctx context.Context, prefix string) (map[string]int, error) {
	return c.search(ctx, prefix, true)
}

// IsPwnedPassword returns true if the password has been pwned.
func (c *Client) IsPwnedPassword(ctx context.Context, s string) (bool, error) {
	sha1Hash := sha1.Sum([]byte(s))
	sha1Hex := strings.ToUpper(hex.EncodeToString(sha1Hash[:]))
	sha1Prefix, sha1Suffix := sha1Hex[:5], sha1Hex[5:]

	bag, err := c.SearchSHA1(ctx, sha1Prefix)
	if err != nil {
		return false, err
	}
	if _, ok := bag[sha1Suffix]; ok {
		return true, nil
	}

	ntlmHash := ntlm.Sum([]byte(s))
	ntlmHex := strings.ToUpper(hex.EncodeToString(ntlmHash[:]))
	ntlmPrefix, ntlmSuffix := ntlmHex[:5], ntlmHex[5:]

	bag, err = c.SearchNTLM(ctx, ntlmPrefix)
	if err != nil {
		return false, err
	}
	if _, ok := bag[ntlmSuffix]; ok {
		return true, nil
	}

	return false, nil
}
