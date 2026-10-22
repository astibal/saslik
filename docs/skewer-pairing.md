# Skewer TLS-PSK pairing

Requires Python 3.13+ and an OpenSSL-enabled Python build with PSK callbacks.
The appliance already targets Ubuntu `resolute`; its default Python packages
are used. No lab CA, server certificate, or client certificate participates.

Saslik starts a separate TLS 1.3 control listener on the UI port plus one
(normally 8766), bound to the same address as the UI. It currently grants only
authenticated discovery/status, not arbitrary lab administration. An occupied
control port is an error, not a reason to downgrade to plaintext.

From the local GUI, use **Kopírovat párovací adresu** in the Skewer card.
Paste into Skewer's **Pair with Saslik…** dialog, or its Saslik URL field.
The fragment is removed before saving the URL. The bootstrap key travels to
the child process on stdin, never on its command line.

For the terminal:

```sh
skewer pair -
# Paste the pairing address on stdin, then Enter.
skewer remote-status skewer://HOST:8766/pair
```

The endpoint address must be reachable from the client. A loopback address
refers to the client machine; for a remote server use an appropriate hostname
or an SSH tunnel. Exposing the existing HTTP GUI does not make it secure:
pairing-secret management is restricted to loopback peers and a loopback Host
header, with the existing CSRF check. There is no remote HTTP enrollment-secret
endpoint. The GUI must be viewed locally or through a trusted SSH forward.
When forwarding, also forward the separate PSK port or adjust the address.

Invitation lifecycle:

* A random 256-bit invitation exists only in memory, without a timer.
* Refresh/copy does not rotate it. Restart invalidates it.
* Enrollment atomically reserves the invitation for one instance and request ID.
* The client stores its unique key before committing over a new authenticated
  connection. Pending credentials survive restarts and can finish commit.
* Commit activates the client and rotates the invitation. Retry is idempotent.
* Manual regeneration cancels pending enrollments, but preserves active clients.

Server keys live in `skewer-clients.json` under the Saslik data root (0600).
Client keys live in `$XDG_DATA_HOME/skewer/pairings` (directory 0700, files 0600).
These are secret files; do not publish them or include them in support bundles.
Copying a client profile copies its identity and credentials.

The local POST `/api/skewer/pairing` supports `link`, `rotate`, `list`, and
`revoke` (with the client's `identity`). It requires `X-Saslik-CSRF`.
The old HTTP discovery/report routes remain for unpaired legacy use; they are
not a fallback for an established PSK connection. Authenticated status includes
the current workspace's public CA as `ca_pem` (or `ca_error` when unavailable).
Skewer validates it and updates CA Trust and Runtime Trust without installing
trust. Private keys are never included. Authenticated inventory reports update
the client's online state and CA inventory, keyed by pairing identity. Status
also includes lab health and web endpoints. Lab-control operations are not
implemented yet. A client is considered connected for 30 seconds after its
last successful request; inventory reports have the same freshness window.

Run tests including the native client with:

```sh
PYTHONPATH=src SKEWER_TEST_BINARY=/path/to/skewer python3 -m unittest discover -s tests
```
