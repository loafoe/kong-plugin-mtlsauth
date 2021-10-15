# kong-plugin-mtlauth

Authoriation using mTLS certs from Caddy

## configuration

```yaml
plugins:
  - name: mtlsauth
    config:
       shared_key: XXX
       secret_key: YYY
       mtls_header: X-Client-Common-Name
       serial_header: X-Client-Device-Serial
       dps_url: http://dps.apps.internal:8080
```

## fields

* `config.shared_key` - (Required) The shared key to look for
* `config.secret_key` - (Required) The secret key used for signature generation
* `config.mtls_header` - (Required) The HTTP header containing the mTLS certificate info
* `config.serial_header` - (Required) The HTTP header containing the device serial

## license

License is propriatary
