package pwnpass

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"golang.org/x/exp/maps"
)

func readFile(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestNewBag(t *testing.T) {
	in := `003CD215739D7C1B2218670D26F81408237:1
003D68EB55068C33ACE09247EE4C639306B:4
012C192B2F16F82EA0EB9EF18D9D539B0DD:3
01330C689E5D64F660D6947A93AD634EF8F:1
0161D96B45F0098840A638034BF2A2986F7:1
74CA8A034D814B96B14A9745027D372A6E7:0
1FD7611F2610A21E64785D9AE5CAA0FC4A2:0
211CD29F14EED9C1521ABED8C83288B8E48:0
F77F0562B5968517CCE156A9F9493AA9376:0
94CBDFCC58B8794761602BC0423AAD2CF03:0`
	want := map[string]int{
		"003CD215739D7C1B2218670D26F81408237": 1,
		"003D68EB55068C33ACE09247EE4C639306B": 4,
		"012C192B2F16F82EA0EB9EF18D9D539B0DD": 3,
		"01330C689E5D64F660D6947A93AD634EF8F": 1,
		"0161D96B45F0098840A638034BF2A2986F7": 1,
	}

	got, err := newBag(strings.NewReader(in))
	if err != nil {
		t.Fatalf("newBag(): error: %v", err)
	}

	if !maps.Equal(want, got) {
		t.Errorf("newBag(): want %v, got %v", want, got)
	}
}

func TestClient_IsPwnedPassword(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(readFile(t, "testdata/8846f_ntlm.txt"))
	}))
	defer testServer.Close()

	c := NewClient()
	c.baseURL = testServer.URL

	pwned, err := c.IsPwnedPassword(context.Background(), "password")
	if err != nil {
		t.Fatalf("IsPwnedPassword(): error: %v", err)
	}

	if !pwned {
		t.Errorf("IsPwnedPassword(): want true, got false")
	}
}
