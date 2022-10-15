# kong-plugin-mtlauth

Authorization using mTLS certs from Caddy

## configuration

```yaml
plugins:
  - name: mtlsauth
    config:
       shared_key: XXX
       secret_key: YYY
       mtls_header: X-Client-Common-Name
       get_device_url: http://dps.apps.internal:8080
       device_token_url: https://dev-auth-services.smartsuite-cataract.com//authorize/oauth2/token
       service_identity: aaa@bbb.com
       service_private_key: .....
       region: us-east
       environment: client-test
       
```
## credentials

The plugin reads credentials from the environment

| Field                          | Description                      |
|--------------------------------|----------------------------------|
| `MTLSAUTH_SERVICE_ID`          | The service identity             |
| `MTLSAUTH_SERVICE_PRIVATE_KEY` | The service identity private key |


## fields

* `config.shared_key` - (Required) The shared key to use for signature validation
* `config.secret_key` - (Required) The secret key used for signature validation
* `config.mtls_header` - (Required) The HTTP header containing the mTLS certificate info
* `config.get_device_url` - (Required) The GET device registration (DRS) URL API endpoint
* `config.device_token_url` - (Required) The POST endpoint for token auth
* `config.region` - (Required) The IAM region we are in (`us-east`, `eu-west`, etc..)
* `config.environment` - (Required) The IAM environment to use (`client-test` or `prod`)
## license

License is proprietary
