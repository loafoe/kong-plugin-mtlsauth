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
	headers, err := kong.Request.GetHeaders(50)

	var keys []string
	for k := range headers {
		keys = append(keys, k)
	}

	if err != nil {
		_ = kong.ServiceRequest.SetHeader("X-Plugin-Headers", "failed")
		return
	}
	req, _ := http.NewRequest(http.MethodGet, "https://foo", nil)

	dateH := ""
	if v, ok := headers["signeddate"]; ok && len(v) > 0 {
		dateH = v[0]
	} else {
		_ = kong.ServiceRequest.SetHeader("X-Plugin-Error", "missing signeddate header")
		return
	}
	req.Header.Set(signer.HeaderSignedDate, dateH)

	authH := ""
	if v, ok := headers["hsdp-api-signature"]; ok && len(v) > 0 {
		authH = v[0]
	} else {
		_ = kong.ServiceRequest.SetHeader("X-Plugin-Error", fmt.Sprintf("missing auth header: %s", strings.Join(keys, ",")))
		return
	}
	req.Header.Set(signer.HeaderAuthorization, authH)

	valid, err := conf.verifier.ValidateRequest(req)
	if err != nil {
		_ = kong.ServiceRequest.SetHeader("X-Plugin-Error", "validation failed")
		return
	}
	_ = kong.ServiceRequest.SetHeader("X-Plugin-Validated", "almost")
	if !valid {
		_ = kong.ServiceRequest.SetHeader("X-Plugin-Error", "invalid signature")
		return
	}
	_ = kong.ServiceRequest.SetHeader("X-Plugin-Status", "verified")
	_ = kong.Log.Info("Signature verified")

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
	mtlsFields := strings.Split(mtlsData[0], ",")
	var cn string
	if found, _ := fmt.Sscanf(mtlsFields[0], "CN=%s", &cn); found != 1 {
		_ = kong.ServiceRequest.SetHeader("X-Plugin-Error", "missing CN")
		return
	}
	serialNumber := serialData[0]
	key := cn + "|" + serialNumber
	_ = kong.ServiceRequest.SetHeader("X-Plugin-Key", key)

	cachedToken, found := conf.cache.Get(key)
	if !found || cachedToken.(string) == "" { // Authorize
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
			_ = kong.ServiceRequest.SetHeader("X-Plugin-Error", "error requesting token")
			return
		}
		var tokenResponse mapperResponse
		err = json.NewDecoder(resp.Body).Decode(&tokenResponse)
		if err != nil {
			_ = kong.ServiceRequest.SetHeader("X-Plugin-Error", "error decoding token response")
			return
		}
		defer resp.Body.Close()
		_ = kong.ServiceRequest.SetHeader("X-Plugin-Response", fmt.Sprintf("%d", resp.StatusCode))

		cachedToken = tokenResponse.AccessToken
		conf.cache.Set(key, cachedToken, time.Duration(tokenResponse.ExpiresIn)*time.Minute)
		_ = kong.ServiceRequest.SetHeader("X-Mapped-Hash", key+"|"+tokenResponse.AccessToken)
	} else {
		_ = kong.ServiceRequest.SetHeader("X-Cached-Hash", key)
	}

	_ = kong.ServiceRequest.SetHeader("Authorization", "Bearer "+cachedToken.(string))
}

func main() {
	_ = server.StartServer(New, "0.1", 1000)
}
