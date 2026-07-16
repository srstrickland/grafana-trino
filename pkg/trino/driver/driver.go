package driver

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/grafana/grafana-plugin-sdk-go/backend/httpclient"
	"github.com/grafana/grafana-plugin-sdk-go/backend/proxy"
	trinoClient "github.com/trinodb/grafana-trino/pkg/trino/client"

	"github.com/trinodb/grafana-trino/pkg/trino/models"
	"github.com/trinodb/trino-go-client/trino"
	_ "github.com/trinodb/trino-go-client/trino"
)

const DriverName string = "trino"

// just compile time assertion
var _ http.RoundTripper = &customTransport{}

type customTransport struct {
	client *trinoClient.Client
}

func (t *customTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.client.Do(req)
}

// Open registers a new driver with a unique name
func Open(settings models.TrinoDatasourceSettings) (*sql.DB, error) {
	tlsConfig, err := buildTLSConfig(settings.Opts.TLS)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	// Wires the transport to dial through Grafana's secure SOCKS proxy (used by
	// Grafana Cloud's Private Data Source Connect) when the datasource has it
	// enabled. A true no-op otherwise. Must happen before any wrapping below, so
	// it applies regardless of which auth method is configured.
	if err := configureSecureSocksProxy(transport, settings.Opts.ProxyOptions); err != nil {
		return nil, fmt.Errorf("failed to configure secure SOCKS proxy: %w", err)
	}
	client := &http.Client{Transport: transport}
	if settings.TokenUrl != "" || settings.ClientId != "" || settings.ClientSecret != "" {
		if settings.AccessToken != "" {
			return nil, errors.New("access token must not be set within 'OAuth Trino Authentication' settings")
		}
		var missingParams []string
		if settings.TokenUrl == "" {
			missingParams = append(missingParams, "Token URL")
		}
		if settings.ClientId == "" {
			missingParams = append(missingParams, "Client id")
		}
		if settings.ClientSecret == "" {
			missingParams = append(missingParams, "Client secret")
		}
		if len(missingParams) > 0 {
			return nil, fmt.Errorf("missing parameters for 'OAuth Trino Authentication': %v", strings.Join(missingParams, ", "))
		}
		client = &http.Client{
			Transport: &customTransport{
				client: &trinoClient.Client{
					Client:            client,
					ClientId:          settings.ClientId,
					ClientSecret:      settings.ClientSecret,
					Url:               settings.TokenUrl,
					ImpersonationUser: settings.ImpersonationUser,
				},
			},
		}
	}
	err = trino.RegisterCustomClient("grafana", client)
	if err != nil {
		return nil, err
	}

	roles, err := parseRoles(settings.Roles)
	if err != nil {
		return nil, err
	}

	config := trino.Config{
		ServerURI:                  settings.URL.String(),
		Source:                     "grafana",
		CustomClientName:           "grafana",
		ForwardAuthorizationHeader: true,
		AccessToken:                settings.AccessToken,
		Roles:                      roles,
	}

	dsn, err := config.FormatDSN()
	if err != nil {
		return nil, err
	}
	return sql.Open(DriverName, dsn)
}

// buildTLSConfig builds the tls.Config used for connections to Trino from
// the datasource's TLS settings (CA certificate, client certificate/key,
// skip-verify).
func buildTLSConfig(opts *httpclient.TLSOptions) (*tls.Config, error) {
	if opts == nil {
		return &tls.Config{}, nil
	}

	var certPool *x509.CertPool
	if opts.CACertificate != "" {
		certPool = x509.NewCertPool()
		certPool.AppendCertsFromPEM([]byte(opts.CACertificate))
	}

	var clientCert []tls.Certificate
	if opts.ClientCertificate != "" {
		if opts.ClientKey == "" {
			return nil, errors.New("client certificate was configured without a client key")
		}
		cert, err := tls.X509KeyPair([]byte(opts.ClientCertificate), []byte(opts.ClientKey))
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		clientCert = append(clientCert, cert)
	}

	return &tls.Config{
		InsecureSkipVerify: opts.InsecureSkipVerify,
		Certificates:       clientCert,
		RootCAs:            certPool,
	}, nil
}

// configureSecureSocksProxy wires transport to dial through Grafana's secure
// SOCKS proxy when opts.Enabled (set from the datasource's
// jsonData.enableSecureSocksProxy, see SecureSocksProxyEnabledOnDS in the
// SDK). It's a no-op when the proxy isn't enabled.
func configureSecureSocksProxy(transport *http.Transport, opts *proxy.Options) error {
	return proxy.New(opts).ConfigureSecureSocksHTTPProxy(transport)
}

func parseRoles(roleStr string) (map[string]string, error) {
	roles := make(map[string]string)
	if strings.TrimSpace(roleStr) == "" {
		return roles, nil
	}
	pairs := strings.Split(roleStr, ";")
	for _, pair := range pairs {
		parts := strings.SplitN(pair, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("Invalid role format. expected catalog:role, got '%s'", pair)
		}
		catalog := strings.TrimSpace(parts[0])
		role := strings.TrimSpace(parts[1])
		if catalog != "" && role != "" {
			roles[catalog] = role
		}
	}
	return roles, nil
}
