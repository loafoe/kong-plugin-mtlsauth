package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Kong/go-pdk"
	"github.com/Kong/go-pdk/server"
	"github.com/patrickmn/go-cache"
	signer "github.com/philips-software/go-hsdp-signer"
)

// Config
type Config struct {
	SharedKey    string `json:"shared_key"`
	SecretKey    string `json:"secret_key"`
	MTLSHeader   string `json:"mtls_header"`
	SerialHeader string `json:"serial_header"`
	DPSEndpoint  string `json:"dps_endpoint"`
	verifier     *signer.Signer
	err          error
	cache        *cache.Cache
	doOnce       sync.Once
}

//nolint
func New() interface{} {
	return &Config{}
}

// Access implements the Access step
func (conf *Config) Access(kong *pdk.PDK) {
	conf.doOnce.Do(func() {
		conf.verifier, conf.err = signer.New(conf.SharedKey, conf.SecretKey)
		conf.cache = cache.New(30*time.Minute, 60*time.Minute)
	})

	if conf.err != nil {
		kong.Response.Exit(http.StatusUnauthorized, fmt.Sprintf("verifier failed: %v\n", conf.err), nil)
		return
	}

	// Signature validation
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

	// Authorization
	mtlData, ok := headers[conf.MTLSHeader]
	if !ok || len(mtlData) == 0 {
		kong.Response.Exit(http.StatusUnauthorized, "missing mTLS data\n", headers)
		return
	}
	serialData, ok := headers[conf.SerialHeader]
	if !ok || len(serialData) == 0 {
		kong.Response.Exit(http.StatusUnauthorized, "missing SerialNumber data\n", headers)
		return
	}
	mtlsFields := strings.Split(serialData[0], ",")
	var cn string
	if found, _ := fmt.Sscanf(mtlsFields[0], "CN=%s", &cn); found != 1 {
		kong.Response.Exit(http.StatusUnauthorized, "missing CN field\n", headers)
	}
	serialNumber := serialData[0]
	key := cn + "|" + serialNumber
	cachedToken, found := conf.cache.Get(key)
	if !found { // Authorize
		var mr = mapperRequest{
			TPMHash:      cn,
			DeviceSerial: serialNumber,
		}
		body, err := json.Marshal(&mr)
		if err != nil {
			kong.Response.Exit(http.StatusInternalServerError, "error marshalling token request", headers)
			return
		}
		resp, err := http.Post(conf.DPSEndpoint+"/Mapper", "application/json", bytes.NewBuffer(body))
		if err != nil {
			kong.Response.Exit(http.StatusInternalServerError, "error requesting token\n", headers)
			return
		}
		var tokenResponse mapperResponse
		err = json.NewDecoder(resp.Body).Decode(&tokenResponse)
		if err != nil {
			kong.Response.Exit(http.StatusInternalServerError, "error decoding token response\n", headers)
			return
		}
		defer resp.Body.Close()

		cachedToken = tokenResponse.AccessToken
		conf.cache.Set(key, cachedToken, time.Duration(tokenResponse.ExpiresIn)*time.Minute)
		_ = kong.ServiceRequest.SetHeader("X-Mapped-Hash", key)
	} else {
		_ = kong.ServiceRequest.SetHeader("X-Cached-Hash", key)
	}

	_ = kong.ServiceRequest.SetHeader("Authorization", "Bearer "+cachedToken.(string))
}

func main() {
	_ = server.StartServer(New, "0.1", 1000)
}
