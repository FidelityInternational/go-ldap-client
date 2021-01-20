package ldapClient

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

// LDAPClient - the ldap client interface
type LDAPClient interface {
	Bind() error
	Authenticate(string, string) (bool, map[string]string, error)
	Close()
}

// Client - the ldap client
type Client struct {
	Conn        ldap.Client
	Config      *Config
	disconnects int
}

// Config - ldap client config
type Config struct {
	Attributes         []string
	Base               string
	BindDN             string
	BindPassword       string
	GroupFilter        string // e.g. "(memberUid=%s)"
	Host               string
	UserFilter         string // e.g. "(uid=%s)"
	Port               int
	InsecureSkipVerify bool
	UseSSL             bool
	ClientCertificates []tls.Certificate // Adding client certificates
	CACertificates     []byte
}

// New - Creates a new ldap client
func New(config *Config) (*Client, error) {
	client := &Client{Config: config}
	if err := client.connect(); err != nil {
		return &Client{}, err
	}
	if err := client.Bind(); err != nil {
		return &Client{}, err
	}
	return client, nil
}

func (c *Client) connect() error {
	var (
		ldapConn *ldap.Conn
		err      error
	)
	c.Close()
	address := fmt.Sprintf("%s:%d", c.Config.Host, c.Config.Port)
	if c.Config.UseSSL {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: c.Config.InsecureSkipVerify,
			ServerName:         c.Config.Host,
		}
		if len(c.Config.CACertificates) > 0 {
			tlsConfig.RootCAs = x509.NewCertPool()
			if !tlsConfig.RootCAs.AppendCertsFromPEM(c.Config.CACertificates) {
				return fmt.Errorf("Could not append CA certs from PEM")
			}
		}
		if c.Config.ClientCertificates != nil && len(c.Config.ClientCertificates) > 0 {
			tlsConfig.Certificates = c.Config.ClientCertificates
		}
		ldapConn, err = ldap.DialTLS("tcp", address, tlsConfig)
		if err != nil {
			return err
		}
	} else {
		ldapConn, err = ldap.Dial("tcp", address)
		if err != nil {
			return err
		}
	}
	c.Conn = ldapConn
	return nil
}

// Bind - bind to LDAP as the Config user
func (c *Client) Bind() error {
	if c.Config.BindDN != "" && c.Config.BindPassword != "" {
		if err := c.Conn.Bind(c.Config.BindDN, c.Config.BindPassword); err != nil {
			if err.Error() == `LDAP Result Code 200 "Network Error": ldap: connection closed` {
				c.disconnects++
				if c.disconnects < 2 {
					if err := c.connect(); err != nil {
						return err
					}
					return c.Bind()
				}
			}
			return err
		}
		c.disconnects = 0
		return nil
	}
	return fmt.Errorf("BindDN or BindPassword was not set on Client config")
}

// Close - close the backend ldap connection
func (c *Client) Close() {
	if c.Conn != nil {
		c.Conn.Close()
		c.Conn = nil
	}
}

// Authenticate - authenticates a user against ldap
func (c *Client) Authenticate(username, password string) (bool, map[string]string, error) {
	defer c.Bind()
	if err := c.Bind(); err != nil {
		return false, nil, err
	}
	attributes := append(c.Config.Attributes, "dn")
	// Search for the given username
	searchRequest := ldap.NewSearchRequest(
		c.Config.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(c.Config.UserFilter, username),
		attributes,
		nil,
	)

	sr, err := c.Conn.Search(searchRequest)
	if err != nil {
		return false, nil, err
	}

	if len(sr.Entries) < 1 {
		return false, nil, fmt.Errorf("User does not exist")
	}

	if len(sr.Entries) > 1 {
		return false, nil, fmt.Errorf("Too many entries returned")
	}

	userDN := sr.Entries[0].DN
	user := map[string]string{}
	for _, attr := range c.Config.Attributes {
		user[attr] = sr.Entries[0].GetAttributeValue(attr)
	}

	// Bind as the user to verify their password
	if err := c.Conn.Bind(userDN, password); err != nil {
		return false, user, err
	}
	return true, user, nil
}
