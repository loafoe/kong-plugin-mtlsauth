package auth_test

import (
	"testing"

	"github.com/Kong/go-pdk/test"
	"github.com/loafoe/kong-plugin-mtlsauth/auth"
	"github.com/stretchr/testify/assert"
)

func TestPlugin(t *testing.T) {
	env, err := test.New(t, test.Request{
		Method:  "GET",
		Url:     "https://example.com?q=search&x=9",
		Headers: map[string][]string{"X-Hi": {"hello"}},
	})
	assert.NoError(t, err)
	cfg := auth.New()

	config, ok := cfg.(*auth.Config)
	if !assert.Equal(t, true, ok) {
		return
	}
	env.DoHttps(config)
	assert.Equal(t, 200, env.ClientRes.Status)
	assert.Equal(t, "init failed: missing shared key", env.ClientRes.Headers.Get("X-Plugin-Error"))
}
