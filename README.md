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
       oauth2_client_id: connectClient
       oauth2_client_secret: s3cretpW
       region: us-east
       environment: client-test
       
```

## fields

* `config.shared_key` - (Required) The shared key to look for
* `config.secret_key` - (Required) The secret key used for signature generation
* `config.mtls_header` - (Required) The HTTP header containing the mTLS certificate info
* `config.serial_header` - (Required) The HTTP header containing the device serial

## license

License is proprietary
