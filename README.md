# cert-manager webhook for Namecheap

Forked from [kelvie/cert-manager-webhook-namecheap](https://github.com/kelvie/cert-manager-webhook-namecheap), with the following fixes for the long-standing "TXT records never appear in Namecheap" problem:

- **Check `IsSuccess` on `SetHosts` responses.** The upstream SDK only inspects `<Errors>`; Namecheap can return HTTP 200 with `IsSuccess="false"` and an empty error list, which the previous code reported to cert-manager as success.
- **Stop caching the Namecheap client across challenges.** A cached client kept stale credentials when multiple Issuers used different secrets.
- **Serialize `GetHosts` + `SetHosts`.** `SetHosts` is a full record-set replacement, so concurrent SAN challenges raced and clobbered each other.
- **Make `Present` idempotent.** cert-manager calls `Present` repeatedly during self-checks; the previous version appended a duplicate TXT record every time.
- **Apex (`@`) handling, whitespace-trimmed secrets, drop unsupported `EmailType` values** that fail SDK validation when round-tripped.
- **Verbose `klog` logging** for `Present` / `CleanUp` so the failure mode is visible in webhook logs.
- Bumped `github.com/namecheap/go-namecheap-sdk/v2` to `v2.4.1`.

# Instructions for use with Let's Encrypt

Thanks to [Addison van den Hoeven](https://github.com/Addyvan), from https://github.com/jetstack/cert-manager/issues/646

Use helm to deploy this into your `cert-manager` namespace:

``` sh
# Make sure you're in the right context:
# kubectl config use-context mycontext

# cert-manager is by default in the cert-manager context
helm install -n cert-manager namecheap-webhook deploy/cert-manager-webhook-namecheap/
```

Create the cluster issuers:

``` sh
helm install --set email=yourname@example.com -n cert-manager letsencrypt-namecheap-issuer deploy/letsencrypt-namecheap-issuer/
```

Go to namecheap and set up your API key (note that you'll need to whitelist the
public IP of the k8s cluster to use the webhook), and set the secret:

``` yaml
apiVersion: v1
kind: Secret
metadata:
  name: namecheap-credentials
  namespace: cert-manager
type: Opaque
stringData:
  apiKey: my_api_key_from_namecheap
  apiUser: my_username_from_namecheap
```

Now you can create a certificate in staging for testing:

``` yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: wildcard-cert-stage
  namespace: default
spec:
  secretName: wildcard-cert-stage
  commonName: "*.<domain>"
  issuerRef:
    kind: ClusterIssuer
    name: letsencrypt-stage
  dnsNames:
  - "*.<domain>"
```

And now validate that it worked:

``` sh
kubectl get certificates -n default
kubectl describe certificate wildcard-cert-stage
```

And finally, create your production cert, and it'll be ready to use in the
`wildcard-cert-prod` secret.

``` yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: wildcard-cert-prod
  namespace: default
spec:
  secretName: wildcard-cert-prod
  commonName: "*.<domain>"
  issuerRef:
    kind: ClusterIssuer
    name: letsencrypt-prod
  dnsNames:
  - "*.<domain>"
```

TODO: add simple nginx example to test that it works

### Running the test suite

All DNS providers **must** run the DNS01 provider conformance testing suite,
else they will have undetermined behaviour when used with cert-manager.

**It is essential that you configure and run the test suite when creating a
DNS01 webhook.**

An example Go test file has been provided in [main_test.go](https://github.com/jetstack/cert-manager-webhook-example/blob/master/main_test.go).

You can run the test suite with:

```bash
$ TEST_ZONE_NAME=example.com. make test
```

The example file has a number of areas you must fill in and replace with your
own options in order for tests to pass.
