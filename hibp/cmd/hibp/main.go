package main

import (
	"context"
	"log"

	"github.com/clfs/m/hibp"
)

func main() {
	log.SetFlags(log.Lshortfile | log.LstdFlags)

	client := hibp.NewClient("", "github.com/clfs/m/hibp/cmd/hibp")
	bag, err := client.HashSuffixes(context.Background(), hibp.HashSuffixesRequest{Prefix: "abcde"})
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("%+v", bag)
}
