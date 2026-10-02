# Jupyter SMART on FHIR

Prototype extensions for loading credentials in Jupyter contexts via [SMART on FHIR](https://docs.smarthealthit.org).

This package contains two implementations:

- `server_extension`: a Jupyter server extension that acts as public client for a SMART server.
- `hub_service`: a JupyterHub service that acts as confidential client for a SMART server and performs asymmetric authentication.

Check the READMEs in the example folders for more information.

This package is very much a work in progress.

## Server Extension

The Server extension is enabled by default on install.
It registers the following handlers:

- `{base_url}/smart-on-fhir/launch` - the launch URL to provide
- `{base_url}/smart-on-fhir/login` (an intermediate implementation-detail handler that may go away)
- `{base_url}/smart-on-fhir/callback` - the OAuth callback you'll want to register

When deployed in JupyterHub, register the URLs `https://jupyterhub.example.org/hub/user-redirect/smart-on-fhir/launch` as the launch URL and `https://jupyterhub.example.org/hub/user-redirect/smart-on-fhir/callback` as the oauth callback URL.

After SMART launch, the token info will be stored in `jupyter_runtime_dir() / "smart_token.json"` (also available to notebooks as `$SMART_TOKEN_FILE`), and in `$SMART_TOKEN`.
`$SMART_TOKEN` will only be available to notebooks started after

Currently, only one token is stored at a time, so if there are multiple smart launches to a single notebook server, only the latest will be persisted.

Configure `SMARTExtensionApp` in `jupyter_server_config.py`:

```
c.SMARTExtensionApp.scopes = ["openid", "fhirUser", "launch", "patient/*.*"]
c.SMARTExtensionApp.client_id = "your-client-id"
```

see sourcecode in `server_extension.py` for now for more options.

### Server Extension Authentication

By setting:

```python
c.ServerApp.identity_provider_class = "jupyter_smart_on_fhir.server_extension.SMARTIdentityProvider"
```

the SMART launch process will be used to authenticate access to all of Jupyter Server.
Only browsers that have completed the SMART launch process will be able to make any requests to the server,
and the latest SMART launch token may be used as a Bearer token to communicate with the Jupyter Server.

## JupyterHub Service

The JupyterHub service is a bare proof of concept which completes the SMART flow and fetches some sample data, it is not useful yet.
