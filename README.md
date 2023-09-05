# kong-plugin-mtlauth

Authorization using mTLS certs from Caddy

## configuration

```yaml
plugins:
  - name: mtlsauth
    config:
       mtls_header: X-Client-Common-Name
       get_device_url: http://dps.apps.internal:8080
       device_token_url: https://dev-auth-services.smartsuite-cataract.com//authorize/oauth2/token
       region: us-east
       environment: client-test
       
```
## credentials

The plugin reads credentials from the environment and from a Vault instance

| Field                          | Description                                 |
|--------------------------------|---------------------------------------------|
| `MTLSAUTH_SERVICE_ID`          | The service identity                        |
| `MTLSAUTH_SERVICE_PRIVATE_KEY` | The service identity private key            |
| `MTLSAUTH_VAULT_ADDR`          | The Vault address                           |
| `MTLSAUTH_VAULT_ROLE_ID`       | The vault role id                           |
| `MTLSAUTH_VAULT_SECRET_ID`     | The vault secret id                         |
| `MTLSAUTH_VAULT_PATH`          | The vault path to read the config data from |

The following attributes are expected in the Vault data object

| Attribute             | Description                                           |
|-----------------------|-------------------------------------------------------|
| `mtlsauth_shared_key` | The shared key to use for signing/validating requests |
| `mtlsauth_secret_key` | The secret key to use for signing/validating requests |


## fields

* `config.mtls_header` - (Required) The HTTP header containing the mTLS certificate info
* `config.get_device_url` - (Required) The GET device registration (DRS) URL API endpoint
* `config.device_token_url` - (Required) The POST endpoint for token auth
* `config.region` - (Required) The IAM region we are in (`us-east`, `eu-west`, etc..)
* `config.environment` - (Required) The IAM environment to use (`client-test` or `prod`)
## license

License is MIT
