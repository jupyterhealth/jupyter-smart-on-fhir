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

### Sessions (0.3+)

Each EHR launch mints a **per-browser session**: a signed, `HttpOnly` cookie
(`smart-session`) carrying a session id; OAuth `state`, the PKCE verifier and the token
are stored server-side against that id. On https the cookie is
`Secure; SameSite=None; Partitioned` so it works inside an EHR iframe (Epic Hyperspace).
One session per browser cookie jar: a new launch replaces the previous session, and a
render URL names its session (`?smart_session=…`) so a stale frame fails closed.

Tokens are written one file per session to `$SMART_TOKEN_DIR/<session-id>.json`
(mode 0600). A **Voilà** kernel reads _its own_ session's token with:

```python
from jupyter_smart_on_fhir.session import load_token
token = load_token()
```

This needs `c.VoilaConfiguration.http_header_envs = ["Cookie"]`; `load_token()` is not
available to JupyterLab/notebook kernels (they have no request cookie).

**Standalone servers** (no JupyterHub) must configure all of:

```python
c.ServerApp.identity_provider_class = "jupyter_smart_on_fhir.server_extension.SMARTIdentityProvider"
c.ServerApp.authorizer_class = "jupyter_smart_on_fhir.server_extension.SMARTAuthorizer"
c.ServerApp.allow_unauthenticated_access = False
c.ServerApp.reraise_server_extension_failures = True   # a bad allowlist must stop the server
c.ServerApp.terminals_enabled = False
c.SMARTExtensionApp.allowed_issuers = ["https://fhir.example.org/r4"]   # the EHR's FHIR base (`iss`)
# A session may exchange widget comm messages with its kernel but never run code:
c.MappingKernelManager.allowed_message_types = [
    "comm_open", "comm_close", "comm_msg", "comm_info_request", "kernel_info_request", "shutdown_request",
]
```

`allowed_issuers` is required in this mode: a launch from any other issuer is refused
before any outbound request. With this, any browser without an authenticated session gets
**403** on every page and API route, `/login` is a "must be opened from your EHR" page,
an authenticated session may only reach the kernel Voilà started for it (no terminals,
contents, sessions, kernel listing), and it cannot execute code in that kernel. Sessions
expire with the token's `expires_in` (capped by `SMARTExtensionApp.session_lifetime`).
Trust boundary: all kernels still run as one OS user and Voilà's own shutdown route is not
ownership-checked, so one standalone server is one trust domain; run multi-organization
deployments under JupyterHub.

Under **JupyterHub** keep Hub's identity provider. The launch handlers still require a
logged-in Jupyter user there. `allowed_issuers` is optional under Hub (a startup warning
when empty; enforced when set). Set `c.SMARTExtensionApp.persist_global_token = True` to
keep writing `smart_token.json` + `$SMART_TOKEN` for notebook kernels (one server per user
makes that per-user); it is ignored in standalone mode. Upgrading from 0.1.x:
`smart_token.json` and `$SMART_TOKEN` are no longer written unless
`persist_global_token=True`.

Configure `SMARTExtensionApp` in `jupyter_server_config.py`:

```
c.SMARTExtensionApp.scopes = ["openid", "fhirUser", "launch", "patient/*.*"]
c.SMARTExtensionApp.client_id = "your-client-id"
```

see sourcecode in `server_extension.py` for now for more options.

## JupyterHub Service

The JupyterHub service is a bare proof of concept which completes the SMART flow and fetches some sample data, it is not useful yet.
