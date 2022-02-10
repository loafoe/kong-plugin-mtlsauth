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
	"github.com/go-resty/resty/v2"
	"github.com/patrickmn/go-cache"
	"github.com/philips-software/go-hsdp-api/iam"
	signer "github.com/philips-software/go-hsdp-signer"
)

// Config
type Config struct {
	SharedKey          string `json:"shared_key"`
	SecretKey          string `json:"secret_key"`
	Region             string `json:"region"`
	Environment        string `json:"environment"`
	ServicePrivateKey  string `json:"service_private_key"`
	ServiceIdentity    string `json:"service_identity"`
	MTLSHeader         string `json:"mtls_header"`
	SerialHeader       string `json:"serial_header"`
	GetDeviceEndpoint  string `json:"get_device_endpoint"`
	OAuth2ClientID     string `json:"oauth2_client_id"`
	OAuth2ClientSecret string `json:"oauth2_client_secret"`
	DebugLog           string `json:"debug_log"`
	verifier           *signer.Signer
	serviceClient      *iam.Client
	err                error
	cache              *cache.Cache
	doOnce             sync.Once
}

type GetResponse struct {
	Entry       []Device `json:"entry"`
	TotalResult int      `json:"totalResult"`
}

type Device struct {
	ID           string        `json:"id"`
	Name         string        `json:"name"`
	PracticeID   string        `json:"practiceId"`
	LoginID      string        `json:"loginId"`
	Password     string        `json:"password"`
	ClientID     string        `json:"clientId"`
	ClientSecret string        `json:"clientSecret"`
	CN           string        `json:"cn"`
	Associations []Association `json:"associations"`
}

type Association struct {
	Name         string `json:"name"`
	SerialNumber string `json:"serialNumber"`
	ModelNumber  string `json:"modelNumber"`
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
		if conf.err == nil {
			conf.serviceClient, conf.err = iam.NewClient(nil, &iam.Config{
				Region:      conf.Region,
				Environment: conf.Environment,
				DebugLog:    conf.DebugLog,
			})
			if conf.err == nil {
				err := conf.serviceClient.ServiceLogin(iam.Service{
					PrivateKey: conf.ServicePrivateKey,
					ServiceID:  conf.ServiceIdentity,
				})
				if err != nil {
					conf.err = err
				}
			}
		}
	})
	_ = kong.ServiceRequest.SetHeader("X-Service-ID", conf.ServiceIdentity)

	if conf.err != nil {
		_ = kong.ServiceRequest.SetHeader("X-Plugin-Error", fmt.Sprintf("init failed: %v", conf.err))
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
		_ = kong.ServiceRequest.SetHeader("X-Plugin-Error", "missing mTLS data")
		return
	}

	// Extract CN
	mtlsFields := strings.Split(mtlsData[0], ",")
	var cn string
	for _, field := range mtlsFields {
		if found, _ := fmt.Sscanf(field, "CN=%s", &cn); found == 1 {
			break
		}
	}
	if cn == "" {
		_ = kong.ServiceRequest.SetHeader("X-Plugin-Error", "missing CN")
		return
	}

	// Cache key
	key := cn + "|v1"
	_ = kong.ServiceRequest.SetHeader("X-Cache-Key", key)

	tr, found := conf.cache.Get(key)
	if !found { // Authorize
		newTokenResponse, err := conf.mapMTLS(cn)
		if err != nil {
			conf.cache.Delete(key)
			_ = kong.ServiceRequest.SetHeader("X-Mapped-Error", err.Error())
			return
		}
		if newTokenResponse.AccessToken == "" || newTokenResponse.ExpiresIn <= 0 {
			conf.cache.Delete(key)
			_ = kong.ServiceRequest.SetHeader("X-Token-Error", "empty token or invalid expiry")
			return
		}
		tr = *newTokenResponse
		conf.cache.Set(key, tr, time.Duration(newTokenResponse.ExpiresIn-60)*time.Second)
	}
	tokenResponse := tr.(mapperResponse)
	expiresIn := time.Until(tokenResponse.ExpiresAt) / time.Second
	if expiresIn <= 0 {
		conf.cache.Delete(key)
		_ = kong.ServiceRequest.SetHeader("X-Token-Error", "negative expiry")
		return
	}
	_ = kong.ServiceRequest.SetHeader("Authorization", "Bearer "+tokenResponse.AccessToken)
	_ = kong.ServiceRequest.SetHeader("X-Token-Expires", fmt.Sprintf("%d", expiresIn))
}

func (conf *Config) mapMTLS(cn string) (*mapperResponse, error) {
	// Fetch device info
	endpoint := conf.GetDeviceEndpoint + "?cn=" + cn
	client := resty.New()
	r := client.R()
	r = r.SetHeader("Authorization", "Bearer "+conf.serviceClient.Token())
	r = r.SetHeader("Content-Type", "application/json")
	r = r.SetHeader("Accept", "application/json")
	r = r.SetHeader("Api-Version", "1")
	resp, _ := r.Execute(http.MethodGet, endpoint)
	if resp.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("getDevice returned statusCode %d", resp.StatusCode())
	}
	var getResponse GetResponse
	err := json.NewDecoder(bytes.NewReader(resp.Body())).Decode(&getResponse)
	if err != nil {
		return nil, err
	}
	if len(getResponse.Entry) < 1 {
		return nil, fmt.Errorf("no results found for CN: %s", cn)
	}
	device := getResponse.Entry[0]

	deviceClient, err := iam.NewClient(nil, &iam.Config{
		OAuth2ClientID: device.ClientID,
		OAuth2Secret:   device.ClientSecret,
		Region:         conf.Region,
		Environment:    conf.Environment,
		DebugLog:       conf.DebugLog,
	})
	if err != nil {
		return nil, fmt.Errorf("error creating IAM client: %w", err)
	}

	// Fetch accessToken
	if err := deviceClient.Login(device.LoginID, device.Password); err != nil {
		return nil, fmt.Errorf("error logging in using device credentials: %w", err)
	}
	return &mapperResponse{
		AccessToken:  deviceClient.Token(),
		RefreshToken: deviceClient.RefreshToken(),
		ExpiresAt:    time.Unix(deviceClient.Expires(), 0),
	}, nil
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
