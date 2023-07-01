package ntlm_test

import (
	"fmt"
	"io"

	"github.com/clfs/m/ntlm"
)

func ExampleNew() {
	h := ntlm.New()
	io.WriteString(h, "His money is twice tainted:")
	io.WriteString(h, " 'taint yours and 'taint mine.")
	fmt.Printf("% x", h.Sum(nil))
	// Output: 65 97 cd c7 76 28 73 77 fe 8d 20 6e da 13 54 38
}

func ExampleSum() {
	data := []byte("This page intentionally left blank.")
	fmt.Printf("% x", ntlm.Sum(data))
	// Output: bb bb f9 2b 7f cc 91 6f 37 7b 63 aa 50 13 2e 43
}
