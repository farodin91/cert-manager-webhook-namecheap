package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"sync"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"

	namecheap "github.com/namecheap/go-namecheap-sdk/v2/namecheap"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const DEFAULT_TTL = 60

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	cmd.RunWebhookServer(GroupName,
		&namecheapDNSProviderSolver{},
	)
}

type (
	Record struct {
		Name    *string
		Type    *string
		Address *string
		MXPref  *int
		TTL     *int
	}

	Domain struct {
		Name      *string
		EmailType *string
		Records   *[]Record
	}

	NamecheapClient interface {
		GetDomain(string) (*Domain, error)
		SetDomain(Domain) error
	}

	namecheapClientImpl struct {
		client *namecheap.Client
	}

	// namecheapDNSProviderSolver implements the provider-specific logic needed to
	// 'present' an ACME challenge TXT record for Namecheap.
	namecheapDNSProviderSolver struct {
		ctx       context.Context
		k8sClient *kubernetes.Clientset
		// mu serializes Get/Set against Namecheap. SetHosts replaces the entire
		// record set, so concurrent presents from multiple SAN challenges would
		// otherwise race and clobber each other's TXT records.
		mu sync.Mutex
	}

	namecheapDNSProviderConfig struct {
		APIKeySecretRef   *cmmeta.SecretKeySelector `json:"apiKeySecretRef"`
		APIUserSecretRef  *cmmeta.SecretKeySelector `json:"apiUserSecretRef"`
		ClientIP          *string                   `json:"clientIP"`
		UseSandbox        bool                      `json:"useSandbox"`
		UsernameSecretRef *cmmeta.SecretKeySelector `json:"usernameSecretRef"`
	}
)

func (c *namecheapDNSProviderSolver) Name() string {
	return "namecheap"
}

func (c *namecheapDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	zone, host, err := c.parseChallenge(ch)
	if err != nil {
		return err
	}

	klog.Infof("Present: zone=%q host=%q fqdn=%q key=%q sandbox=%t",
		zone, host, ch.ResolvedFQDN, ch.Key, cfg.UseSandbox)

	nc, err := c.newNamecheapClient(ch, cfg)
	if err != nil {
		return err
	}

	d, err := nc.GetDomain(zone)
	if err != nil {
		return fmt.Errorf("namecheap GetHosts(%s) failed: %w", zone, err)
	}

	if d.addChallengeRecord(host, ch.Key) {
		klog.Infof("Present: TXT record for %s already exists, skipping update", host)
		return nil
	}

	if err := nc.SetDomain(*d); err != nil {
		return fmt.Errorf("namecheap SetHosts(%s) failed: %w", zone, err)
	}

	klog.Infof("Present: successfully wrote TXT record for %s.%s", host, zone)
	return nil
}

func (c *namecheapDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	zone, host, err := c.parseChallenge(ch)
	if err != nil {
		return err
	}

	klog.Infof("CleanUp: zone=%q host=%q fqdn=%q", zone, host, ch.ResolvedFQDN)

	nc, err := c.newNamecheapClient(ch, cfg)
	if err != nil {
		return err
	}

	d, err := nc.GetDomain(zone)
	if err != nil {
		return fmt.Errorf("namecheap GetHosts(%s) failed: %w", zone, err)
	}

	if !d.removeChallengeRecord(host, ch.Key) {
		klog.Infof("CleanUp: TXT record for %s already absent, nothing to do", host)
		return nil
	}

	if err := nc.SetDomain(*d); err != nil {
		return fmt.Errorf("namecheap SetHosts(%s) failed: %w", zone, err)
	}

	klog.Infof("CleanUp: removed TXT record for %s.%s", host, zone)
	return nil
}

func (c *namecheapDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	c.k8sClient = cl
	c.ctx = context.Background()

	return nil
}

func (c *namecheapDNSProviderSolver) getSecret(ref *cmmeta.SecretKeySelector, namespace string) (*string, error) {
	if ref.Name == "" {
		return nil, fmt.Errorf(
			"secret not found in '%s'",
			namespace,
		)
	}
	if ref.Key == "" {
		return nil, fmt.Errorf(
			"no 'key' set in secret '%s/%s'",
			namespace,
			ref.Name,
		)
	}

	secret, err := c.k8sClient.CoreV1().Secrets(namespace).Get(
		c.ctx, ref.Name, metav1.GetOptions{},
	)
	if err != nil {
		return nil, err
	}
	keyBytes, ok := secret.Data[ref.Key]
	if !ok {
		return nil, fmt.Errorf(
			"no key '%s' in secret '%s/%s'",
			ref.Key,
			namespace,
			ref.Name,
		)
	}
	// Trim whitespace/newlines that commonly creep in from `kubectl create
	// secret --from-literal` or YAML stringData blocks. Namecheap rejects keys
	// with stray whitespace — silently in some failure modes.
	s := strings.TrimSpace(string(keyBytes))
	return &s, nil
}

// newNamecheapClient builds a fresh client per challenge. The previous version
// cached the client on the solver, which silently used stale credentials when
// multiple Issuers with different secrets were configured against the same
// webhook deployment.
func (c *namecheapDNSProviderSolver) newNamecheapClient(
	ch *v1alpha1.ChallengeRequest,
	cfg namecheapDNSProviderConfig,
) (NamecheapClient, error) {
	apiKey, err := c.getSecret(cfg.APIKeySecretRef, ch.ResourceNamespace)
	if err != nil {
		return nil, err
	}

	apiUser, err := c.getSecret(cfg.APIUserSecretRef, ch.ResourceNamespace)
	if err != nil {
		return nil, err
	}

	opts := &namecheap.ClientOptions{
		ApiKey:     *apiKey,
		ApiUser:    *apiUser,
		UseSandbox: cfg.UseSandbox,
	}

	if cfg.ClientIP == nil {
		ip, err := getOutboundIP()
		if err != nil {
			return nil, err
		}
		opts.ClientIp = ip.String()
	} else {
		opts.ClientIp = *cfg.ClientIP
	}

	if cfg.UsernameSecretRef == nil {
		opts.UserName = *apiUser
	} else {
		username, err := c.getSecret(cfg.UsernameSecretRef, ch.ResourceNamespace)
		if err != nil {
			return nil, err
		}
		opts.UserName = *username
	}

	return &namecheapClientImpl{
		client: namecheap.NewClient(opts),
	}, nil
}

func (c *namecheapDNSProviderSolver) parseChallenge(ch *v1alpha1.ChallengeRequest) (
	zone string, host string, err error,
) {
	ctx := context.Background()

	if zone, err = util.FindZoneByFqdn(ctx,
		ch.ResolvedFQDN, util.RecursiveNameservers,
	); err != nil {
		return "", "", err
	}
	zone = util.UnFqdn(zone)

	// Strip the registered zone from the FQDN to get the host portion that
	// Namecheap expects (e.g. "_acme-challenge" or "_acme-challenge.sub").
	fqdn := util.UnFqdn(ch.ResolvedFQDN)
	switch {
	case fqdn == zone:
		host = "@"
	case strings.HasSuffix(fqdn, "."+zone):
		host = strings.TrimSuffix(fqdn, "."+zone)
	default:
		return "", "", fmt.Errorf("resolved FQDN %q is not within zone %q", fqdn, zone)
	}

	return zone, host, nil
}

// addChallengeRecord appends a TXT record. Returns true if an identical record
// already exists (caller should skip the SetHosts round-trip).
func (d *Domain) addChallengeRecord(host, key string) bool {
	if d.Records != nil {
		for _, r := range *d.Records {
			if r.Name != nil && r.Type != nil && r.Address != nil &&
				*r.Name == host &&
				*r.Type == namecheap.RecordTypeTXT &&
				*r.Address == key {
				return true
			}
		}
	}
	if d.Records == nil {
		empty := []Record{}
		d.Records = &empty
	}
	*d.Records = append(
		*d.Records,
		Record{
			Name:    &host,
			Type:    namecheap.String(namecheap.RecordTypeTXT),
			Address: namecheap.String(key),
			TTL:     namecheap.Int(DEFAULT_TTL),
		},
	)
	return false
}

// removeChallengeRecord drops a matching TXT record. Returns true if a record
// was actually removed.
func (d *Domain) removeChallengeRecord(host, key string) bool {
	if d.Records == nil {
		return false
	}
	for i, r := range *d.Records {
		if r.Name != nil && r.Type != nil && r.Address != nil &&
			*r.Name == host &&
			*r.Type == namecheap.RecordTypeTXT &&
			*r.Address == key {
			records := *d.Records
			*d.Records = slices.Concat(records[:i], records[i+1:])
			return true
		}
	}
	return false
}

func (c *namecheapClientImpl) SetDomain(domain Domain) error {
	args := &namecheap.DomainsDNSSetHostsArgs{
		Domain: domain.Name,
	}
	// Namecheap's SDK validates EmailType against a fixed list. Round-tripping
	// values like "FREE" or unknown types from GetHosts blows up validation
	// before the request is even sent. Only forward values the SDK accepts.
	if domain.EmailType != nil {
		if isAllowedEmailType(*domain.EmailType) {
			args.EmailType = domain.EmailType
		}
	}

	records := make([]namecheap.DomainsDNSHostRecord, 0, len(*domain.Records))
	for _, record := range *domain.Records {
		r := namecheap.DomainsDNSHostRecord{
			HostName:   record.Name,
			RecordType: record.Type,
			Address:    record.Address,
			TTL:        record.TTL,
		}

		if record.MXPref != nil {
			r.MXPref = namecheap.UInt8(uint8(*record.MXPref)) //nolint:gosec
		}
		records = append(records, r)
	}
	args.Records = &records

	resp, err := c.client.DomainsDNS.SetHosts(args)
	if err != nil {
		return err
	}

	// CRITICAL: the SDK does not check IsSuccess. Namecheap can return
	// HTTP 200 with Status="OK" and Errors empty while still reporting
	// IsSuccess="false" in the result body — a silent no-op that previously
	// looked like success to cert-manager. Surface it as an error.
	if resp == nil || resp.DomainDNSSetHostsResult == nil {
		return fmt.Errorf("namecheap SetHosts: empty response")
	}
	if resp.DomainDNSSetHostsResult.IsSuccess == nil || !*resp.DomainDNSSetHostsResult.IsSuccess {
		return fmt.Errorf("namecheap SetHosts reported IsSuccess=false for domain %s — "+
			"the API silently rejected the change "+
			"(check API key, ApiUser, whitelisted ClientIp, and that the account actually owns this domain)",
			derefString(domain.Name))
	}
	return nil
}

func (c *namecheapClientImpl) GetDomain(domain string) (*Domain, error) {
	resp, err := c.client.DomainsDNS.GetHosts(domain)
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.DomainDNSGetHostsResult == nil {
		return nil, fmt.Errorf("namecheap GetHosts: empty response for %s", domain)
	}

	d := &Domain{
		Name:      resp.DomainDNSGetHostsResult.Domain,
		EmailType: resp.DomainDNSGetHostsResult.EmailType,
	}
	var records []Record
	if resp.DomainDNSGetHostsResult.Hosts != nil {
		records = make([]Record, 0, len(*resp.DomainDNSGetHostsResult.Hosts))
		for _, r := range *resp.DomainDNSGetHostsResult.Hosts {
			records = append(records, Record{
				Name:    r.Name,
				Type:    r.Type,
				Address: r.Address,
				MXPref:  r.MXPref,
				TTL:     r.TTL,
			})
		}
	}
	d.Records = &records

	return d, nil
}

func isAllowedEmailType(v string) bool {
	for _, a := range namecheap.AllowedEmailTypeValues {
		if v == a {
			return true
		}
	}
	return false
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// Get preferred outbound ip of this machine
func getOutboundIP() (*net.IP, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	localAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if ok {
		return nil, errors.New("expect UDPAddr")
	}

	return &localAddr.IP, nil
}

func loadConfig(cfgJSON *extapi.JSON) (namecheapDNSProviderConfig, error) {
	cfg := namecheapDNSProviderConfig{}
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}
