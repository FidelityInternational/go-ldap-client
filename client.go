package ldapClient

import (
	"crypto/tls"
	"fmt"
	"gopkg.in/ldap.v2"
)

// LDAPClient - the ldap client interface
type LDAPClient interface {
	Bind() error
	Authenticate(string, string) (bool, map[string]string, error)
	Close()
}

// Client - the ldap client
type Client struct {
	Conn   *ldap.Conn
	Config *Config
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
}

// New - Creates a new ldap client
func New(config *Config) (*Client, error) {
	var (
		ldapConn *ldap.Conn
		err      error
	)

	address := fmt.Sprintf("%s:%d", config.Host, config.Port)
	if config.UseSSL {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: config.InsecureSkipVerify,
			ServerName:         config.Host,
		}
		if config.ClientCertificates != nil && len(config.ClientCertificates) > 0 {
			tlsConfig.Certificates = config.ClientCertificates
		}
		ldapConn, err = ldap.DialTLS("tcp", address, tlsConfig)
		if err != nil {
			return &Client{}, err
		}
	} else {
		ldapConn, err = ldap.Dial("tcp", address)
		if err != nil {
			return &Client{}, err
		}
	}
	client := &Client{Conn: ldapConn, Config: config}
	if err := client.Bind(); err != nil {
		return &Client{}, err
	}
	return client, nil
}

// Bind - bind to LDAP as the Config user
func (c *Client) Bind() error {
	if c.Config.BindDN != "" && c.Config.BindPassword != "" {
		if err := c.Conn.Bind(c.Config.BindDN, c.Config.BindPassword); err != nil {
			return err
		}
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
