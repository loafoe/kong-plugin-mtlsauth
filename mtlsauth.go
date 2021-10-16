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
	"github.com/Kong/go-pdk/request"
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
	if err := conf.validateSignature(kong.Request); err != nil {
		_ = kong.ServiceRequest.SetHeader("X-Plugin-Error", "validation failed")
		return
	}
	// Authorization
	headers, err := kong.Request.GetHeaders(-1)
	if err != nil {
		_ = kong.ServiceRequest.SetHeader("X-Plugin-Error", fmt.Sprintf("get headers failed: %v", err))
		return
	}
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
		tokenResponse, err := conf.mapMTLS(cn, serialNumber)
		if err != nil {
			_ = kong.ServiceRequest.SetHeader("X-Mapped-Error", err.Error())
			return
		}
		conf.cache.Set(key, cachedToken, time.Duration(tokenResponse.ExpiresIn)*time.Minute)
	}
	_ = kong.ServiceRequest.SetHeader("Authorization", "Bearer "+cachedToken.(string))
}

func (conf *Config) mapMTLS(cn string, serial string) (*mapperResponse, error) {
	var mr = mapperRequest{
		TPMHash:      cn,
		DeviceSerial: serial,
	}
	body, err := json.Marshal(&mr)
	if err != nil {
		return nil, err
	}
	endpoint := conf.DPSEndpoint + "/Mapper"
	resp, err := http.Post(endpoint, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("mapper returned statusCode %d", resp.StatusCode)
	}
	var tokenResponse mapperResponse
	err = json.NewDecoder(resp.Body).Decode(&tokenResponse)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return &tokenResponse, nil
}

func (conf *Config) validateSignature(req request.Request) error {
	headers, err := req.GetHeaders(-1)
	if err != nil {
		return err
	}
	testReq, _ := http.NewRequest(http.MethodGet, "https://foo", nil)

	dateH := ""
	if v, ok := headers["signeddate"]; ok && len(v) > 0 {
		dateH = v[0]
	} else {
		return fmt.Errorf("missing signeddate header")
	}
	testReq.Header.Set(signer.HeaderSignedDate, dateH)

	authH := ""
	if v, ok := headers["hsdp-api-signature"]; ok && len(v) > 0 {
		authH = v[0]
	} else {
		return fmt.Errorf("missing hsdp-api-signature header")
	}
	testReq.Header.Set(signer.HeaderAuthorization, authH)

	valid, err := conf.verifier.ValidateRequest(testReq)
	if err != nil {
		return err
	}
	if !valid {
		return fmt.Errorf("invalid signature")
	}
	return nil
}

func main() {
	_ = server.StartServer(New, "0.1", 1000)
}
