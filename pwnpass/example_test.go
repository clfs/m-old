package pwnpass_test

import (
	"context"
	"fmt"
	"log"

	"github.com/clfs/m/pwnpass"
)

func ExampleClient_IsPwnedPassword() {
	c := pwnpass.NewClient()

	// Use whatever context is appropriate for your application.
	pwned, err := c.IsPwnedPassword(context.TODO(), "hunter2")
	if err != nil {
		log.Fatal(err)
	}

	if pwned {
		fmt.Println("oh no - pwned!")
	} else {
		fmt.Println("good news - safe!")
	}
}
