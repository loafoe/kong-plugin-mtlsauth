package main

import (
	"fmt"
	"net/http"
	"sync"

	"github.com/Kong/go-pdk"
	"github.com/Kong/go-pdk/server"
	signer "github.com/philips-software/go-hsdp-signer"
)

// Config
type Config struct {
	SharedKey string `json:"shared_key"`
	SecretKey string `json:"secret_key"`
	verifier  *signer.Signer
	err       error
}

//nolint
func New() interface{} {
	return &Config{}
}

var doOnce sync.Once

// Access implements the Access step
func (conf *Config) Access(kong *pdk.PDK) {
	doOnce.Do(func() {
		conf.verifier, conf.err = signer.New(conf.SharedKey, conf.SecretKey)
	})

	if conf.err != nil {
		kong.Response.Exit(http.StatusUnauthorized, fmt.Sprintf("verifier failed: %v\n", conf.err), nil)
		return
	}
	headers, err := kong.Request.GetHeaders(-1)
	if err != nil {
		kong.Response.Exit(http.StatusUnauthorized, fmt.Sprintf("getHeaders failed: %v\n", err), nil)
		return
	}
	method, _ := kong.Request.GetMethod()

	valid, err := conf.verifier.ValidateRequest(&http.Request{
		Header: headers,
		Method: method,
	})
	if err != nil {
		kong.Response.Exit(http.StatusUnauthorized, fmt.Sprintf("validation failed: %v\n", err), nil)
		return
	}
	if !valid {
		kong.Response.Exit(http.StatusUnauthorized, "invalid signature. blocked\n", headers)
		return
	}
}

func main() {
	_ = server.StartServer(New, "0.1", 1000)
}
