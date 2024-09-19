package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
	"net/http"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/Kong/go-pdk"
	"github.com/Kong/go-pdk/request"
	"github.com/patrickmn/go-cache"
	"github.com/philips-software/go-hsdp-api/iam"
	signer "github.com/philips-software/go-hsdp-signer"
	"gopkg.in/resty.v1"
)

// Config holds the configuration of the plugin
type Config struct {
	Region            string `json:"region"`
	Environment       string `json:"environment"`
	MTLSHeader        string `json:"mtls_header"`
	SerialHeader      string `json:"serial_header"`
	GetDeviceEndpoint string `json:"get_device_endpoint"`
	DeviceTokenURL    string `json:"device_token_url"`
	verifier          *signer.Signer
	serviceClient     *iam.Client
	err               error
	initialized       bool
	cache             *cache.Cache
	mu                sync.Mutex
	doOnce            sync.Once
	revision          string
	settings          []debug.BuildSetting
	serviceId         string
	sharedKey         string
	secretKey         string
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

type tokenRequest struct {
	Username  string `json:"username"`
	Password  string `json:"password"`
	GrantType string `json:"grant_type"`
}

type tokenResponse struct {
	Scope        string `json:"scope"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

const (
	preSeconds = 60
)

// New returns a new plugin instance
// nolint
func New() interface{} {
	return &Config{}
}

type Data struct {
	ServerCert               string            `json:"server_cert"`
	ServerKey                string            `json:"server_key"`
	ServiceSSHPrivateKey     string            `json:"server_ssh_private_key"`
	TrustedCACert            string            `json:"trusted_ca_cert"`
	EnableGlobalRateLimiting bool              `json:"enable_global_rate_limiting"`
	HSPLogdrainURL           string            `json:"hsp_logdrain_url"`
	CaddyServerUsername      string            `json:"caddy_server_username"`
	CaddyServiceBastionHost  string            `json:"caddy_server_bastion_host"`
	CaddyServerPrivateHosts  []string          `json:"caddy_server_private_hosts"`
	EndpointMappings         map[string]string `json:"endpoint_mappings"`
	MTLSAuthSharedKey        string            `json:"mtlsauth_shared_key"`
	MTLSAuthSecretKey        string            `json:"mtlsauth_secret_key"`
}

// Access implements the Access step
func (conf *Config) Access(kong *pdk.PDK) {
	if !conf.initialized {
		conf.mu.Lock()
		initFunc := func() error {
			ctx := context.Background()
			vaultAddr := os.Getenv("MTLSAUTH_VAULT_ADDR")
			roleId := os.Getenv("MTLSAUTH_VAULT_ROLE_ID")
			secretId := os.Getenv("MTLSAUTH_VAULT_SECRET_ID")
			vaultPath := os.Getenv("MTLSAUTH_VAULT_PATH")

			// prepare a client with the given base address
			client, err := vault.New(
				vault.WithAddress(vaultAddr),
				vault.WithRequestTimeout(30*time.Second),
			)
			if err != nil {
				return fmt.Errorf("error creating vault client: %w", err)
			}
			resp, err := client.Auth.AppRoleLogin(
				ctx,
				schema.AppRoleLoginRequest{
					RoleId:   roleId,
					SecretId: secretId,
				},
			)
			if err != nil {
				return fmt.Errorf("error logging into vault: %w", err)
			}

			if err := client.SetToken(resp.Auth.ClientToken); err != nil {
				return fmt.Errorf("error setting vault token: %w", err)
			}

			data, err := client.Read(ctx, vaultPath)
			if err != nil {
				return fmt.Errorf("error reading vault key %s data: %w", vaultPath, err)
			}

			conf.sharedKey = data.Data["mtlsauth_shared_key"].(string)
			conf.secretKey = data.Data["mtlsauth_secret_key"].(string)

			verifier, err := signer.New(conf.sharedKey, conf.secretKey)
			if err != nil {
				return err
			}
			conf.verifier = verifier
			conf.cache = cache.New(30*time.Minute, 30*time.Minute)

			info, ok := debug.ReadBuildInfo()
			if ok {
				conf.settings = info.Settings
				for _, kv := range info.Settings {
					if kv.Key == "vcs.revision" {
						conf.revision = kv.Value
					}
				}
			}
			cfg := &iam.Config{
				Region:      conf.Region,
				Environment: conf.Environment,
			}
			if debugLog := os.Getenv("MTLSAUTH_DEBUG_LOG"); debugLog != "" {
				cfg.DebugLog = os.Stderr
			}
			conf.serviceId = os.Getenv("MTLSAUTH_SERVICE_ID")
			serviceClient, err := iam.NewClient(nil, cfg)
			if err != nil {
				return fmt.Errorf("error creating serviceClient: %w", err)
			}
			conf.serviceClient = serviceClient
			// TODO: add a redo here to handle transient errors
			err = conf.serviceClient.ServiceLogin(iam.Service{
				PrivateKey: os.Getenv("MTLSAUTH_SERVICE_PRIVATE_KEY"),
				ServiceID:  conf.serviceId,
			})
			if err != nil {
				return fmt.Errorf("error logging in: service_id=%s error=%w", conf.serviceId, err)
			}
			return nil
		}
		conf.doOnce.Do(func() {
			conf.err = initFunc()
		})
		conf.initialized = true
		conf.mu.Unlock()
	}
	_ = kong.ServiceRequest.SetHeader("X-Service-ID", conf.serviceId)
	_ = kong.ServiceRequest.SetHeader("X-Plugin-Revision", conf.revision)

	if conf.err != nil {
		_ = kong.ServiceRequest.SetHeader("X-Plugin-Error", fmt.Sprintf("init failed: %v", conf.err))
		return
	}
	// Signature validation
	if err := conf.validateSignature(kong.Request); err != nil {
		_ = kong.ServiceRequest.SetHeader("X-Plugin-Error", "signature validation failed")
		return
	}
	// Authorization
	headers, err := kong.Request.GetHeaders(-1)
	if err != nil {
		_ = kong.ServiceRequest.SetHeader("X-Plugin-Error", fmt.Sprintf("get headers failed: %v", err))
		return
	}

	// Pre-existing Authorization header have priority
	upstreamAuth, ok := headers["Authorization"]
	if ok && len(upstreamAuth) > 0 {
		_ = kong.ServiceRequest.SetHeader("X-Plugin-Info", "existing auth header found")
		return
	}

	// mTLS based authorization starts here
	mtlsData, ok := headers[conf.MTLSHeader]
	if !ok || len(mtlsData) == 0 {
		_ = kong.ServiceRequest.SetHeader("X-Plugin-Error", "missing mTLS data")
		return
	}

	// Extract CN
	var cn string
	cn = mtlsData[0] // Format: 624e1a69-c12e-43d8-b53f-be21b8a50408_DevOps_1
	mtlsFields := strings.Split(mtlsData[0], ",")
	for _, field := range mtlsFields {
		// Format: CN=624e1a69-c12e-43d8-b53f-be21b8a50408_DevOps_1,OU=Scientia+OU=15000001,O=Alcon Research LLC,C=US
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

	var tokenResponse mapperResponse
	var expiresIn time.Duration
	tr, found := conf.cache.Get(key)
	if found {
		tokenResponse = tr.(mapperResponse)
		expiresIn = time.Until(tokenResponse.ExpiresAt) / time.Second
		if expiresIn <= preSeconds {
			conf.cache.Delete(key)
			conf.cache.DeleteExpired()
			found = false
		}
	}
	if !found { // Authorize
		newTokenResponse, err := conf.mapMTLS(cn)
		if err != nil {
			conf.cache.Delete(key)
			conf.cache.DeleteExpired()
			_ = kong.ServiceRequest.SetHeader("X-Mapped-Error", err.Error())
			return
		}
		if newTokenResponse.AccessToken == "" || newTokenResponse.ExpiresIn <= 0 {
			conf.cache.Delete(key)
			conf.cache.DeleteExpired()
			_ = kong.ServiceRequest.SetHeader("X-Token-Error", fmt.Sprintf("empty token or invalid expiry (%d)", newTokenResponse.ExpiresIn))
			return
		}
		tr = *newTokenResponse
		conf.cache.Set(key, tr, time.Duration(newTokenResponse.ExpiresIn-preSeconds)*time.Second)
		tokenResponse = tr.(mapperResponse)
		expiresIn = time.Until(tokenResponse.ExpiresAt) / time.Second
	}

	_ = kong.ServiceRequest.SetHeader("Authorization", "Bearer "+tokenResponse.AccessToken)
	_ = kong.ServiceRequest.SetHeader("X-Token-Expires", fmt.Sprintf("%d", expiresIn))
}

func (conf *Config) mapMTLS(cn string) (*mapperResponse, error) {
	// Fetch device info
	endpoint := conf.GetDeviceEndpoint + "?cn=" + cn
	client := resty.New()
	token, err := conf.serviceClient.Token()
	if err != nil {
		return nil, fmt.Errorf("serviceClient token error: %w", err)
	}
	r := client.R()
	r = r.SetHeader("Authorization", "Bearer "+token)
	r = r.SetHeader("Content-Type", "application/json")
	r = r.SetHeader("Accept", "application/json")
	r = r.SetHeader("Api-Version", "1")
	// Call to device registration service
	resp, _ := r.Execute(http.MethodGet, endpoint)
	if resp.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("getDevice returned statusCode %d", resp.StatusCode())
	}
	var getResponse GetResponse
	err = json.NewDecoder(bytes.NewReader(resp.Body())).Decode(&getResponse)
	if err != nil {
		return nil, fmt.Errorf("error decoding getDevice response: %w", err)
	}
	if len(getResponse.Entry) < 1 {
		return nil, fmt.Errorf("no results found for CN: %s", cn)
	}
	device := getResponse.Entry[0]

	tokenClient := resty.New()
	rt := tokenClient.R()
	rt = rt.SetBasicAuth(device.ClientID, device.ClientSecret)
	rt = rt.SetHeader("API-Version", "1")
	rt = rt.SetHeader("Accept", "application/json")
	rt = rt.SetHeader("Accept-Language", "en-US")
	rt = rt.SetHeader("Content-Type", "application/json")
	rt = rt.SetBody(tokenRequest{
		Username:  device.LoginID,
		Password:  device.Password,
		GrantType: "password",
	})
	resp, err = rt.Execute(http.MethodPost, conf.DeviceTokenURL)
	if err != nil {
		return nil, fmt.Errorf("error performing device token call: %w", err)
	}

	var tr tokenResponse
	err = json.NewDecoder(bytes.NewReader(resp.Body())).Decode(&tr)
	if err != nil {
		return nil, fmt.Errorf("error decoding token response: %w", err)
	}
	expiresAt := time.Unix(time.Now().Unix()+tr.ExpiresIn, 0).UTC()
	return &mapperResponse{
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		ExpiresAt:    expiresAt,
		ExpiresIn:    tr.ExpiresIn,
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

	// TODO: check if we should validate testReq or just req
	valid, err := conf.verifier.ValidateRequest(testReq)
	if err != nil {
		return err
	}
	if !valid {
		return fmt.Errorf("invalid signature")
	}
	return nil
}
