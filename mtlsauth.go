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
		_ = kong.ServiceRequest.SetHeader("X-Plugin-Error", fmt.Sprintf("verifier failed: %v", conf.err))
		return
	}

	// Signature validation
	headers, err := kong.Request.GetHeaders(-1)
	if err != nil {
		_ = kong.ServiceRequest.SetHeader("X-Plugin-Error", fmt.Sprintf("getHeaders failed: %v", err))
		return
	}
	method, _ := kong.Request.GetMethod()
	req, _ := http.NewRequest(method, "https://foo", nil)
	req.Header.Set(signer.HeaderAuthorization, headers[signer.HeaderAuthorization][0])
	req.Header.Set(signer.HeaderSignedDate, headers[signer.HeaderSignedDate][0])
	valid, err := conf.verifier.ValidateRequest(req)
	if err != nil {
		_ = kong.ServiceRequest.SetHeader("X-Plugin-Error", fmt.Sprintf("validation failed: %v", err))
		return
	}
	if !valid {
		_ = kong.ServiceRequest.SetHeader("X-Plugin-Error", "invalid signature")
		return
	}

	// Authorization
	mtlsData, ok := headers[conf.MTLSHeader]
	if !ok || len(mtlsData) == 0 {
		_ = kong.ServiceRequest.SetHeader("X-Plugin-Error", "missing mtls data")
		return
	}
	serialData, ok := headers[conf.SerialHeader]
	if !ok || len(serialData) == 0 {
		_ = kong.ServiceRequest.SetHeader("X-Plugin-Error", "missing serial data")
		return
	}
	mtlsFields := strings.Split(serialData[0], ",")
	var cn string
	if found, _ := fmt.Sscanf(mtlsFields[0], "CN=%s", &cn); found != 1 {
		_ = kong.ServiceRequest.SetHeader("X-Plugin-Error", "missing CN")
		return
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
			_ = kong.ServiceRequest.SetHeader("X-Plugin-Error", "error marshalling token request")
			return
		}
		resp, err := http.Post(conf.DPSEndpoint+"/Mapper", "application/json", bytes.NewBuffer(body))
		if err != nil {
			_ = kong.ServiceRequest.SetHeader("X-Plugin-Error", fmt.Sprintf("error requesting token: %v", err))
			return
		}
		var tokenResponse mapperResponse
		err = json.NewDecoder(resp.Body).Decode(&tokenResponse)
		if err != nil {
			_ = kong.ServiceRequest.SetHeader("X-Plugin-Error", fmt.Sprintf("error decoding token response: %v", err))
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
