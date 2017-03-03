package ldapClient_test

import (
	"crypto/tls"
	"fmt"
	. "github.com/FidelityInternational/go-ldap-client"
	"gopkg.in/ldap.v2"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type fakeConn struct {
	ldap.Conn
}

func (fc *fakeConn) Close() {}

func (fc *fakeConn) Bind(username, password string) error {
	if password == "valid" {
		return nil
	}
	return fmt.Errorf("ldap bind failed")
}

func (fc *fakeConn) Search(searchReq *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if strings.Contains(searchReq.Filter, "failedSearch") {
		return &ldap.SearchResult{}, fmt.Errorf("failed ldap search")
	}
	if strings.Contains(searchReq.Filter, "notExist") {
		return &ldap.SearchResult{}, nil
	}

	if strings.Contains(searchReq.Filter, "tooMany") {
		return &ldap.SearchResult{
			Entries: []*ldap.Entry{
				{
					DN: "dn1",
				},
				{
					DN: "dn2",
				},
			},
		}, nil
	}
	return &ldap.SearchResult{
		Entries: []*ldap.Entry{
			{
				DN: "userDn",
			},
		},
	}, nil
}

var _ = Describe("GoLdapClient", func() {
	Describe("#New", func() {
		var (
			config *Config
			client *Client
			err    error
		)

		JustBeforeEach(func() {
			client, err = New(config)
		})

		Context("when SSL is set", func() {
			Context("and connecting to the server fails", func() {
				BeforeEach(func() {
					config = &Config{
						UseSSL:             true,
						InsecureSkipVerify: true,
						Host:               "fake.localhost",
						ClientCertificates: []tls.Certificate{
							{
								Certificate: [][]byte{},
							},
						},
						BindDN:       "user",
						BindPassword: "valid",
					}
				})

				It("returns an error", func() {
					Ω(err).Should(MatchError(`LDAP Result Code 200 "": dial tcp: lookup fake.localhost: no such host`))
					Ω(client).Should(Equal(&Client{}))
				})
			})
		})

		Context("when SSL is not set", func() {
			Context("and connecting to the server fails", func() {
				BeforeEach(func() {
					config = &Config{
						UseSSL:       false,
						BindDN:       "user",
						BindPassword: "valid",
					}
				})

				It("returns an error", func() {
					Ω(err).Should(MatchError(`LDAP Result Code 200 "": dial tcp :0: connect: can't assign requested address`))
					Ω(client).Should(Equal(&Client{}))
				})
			})
		})
	})

	Describe("#Close", func() {
		It("closes the backend ldap connection", func() {
			client := Client{
				Conn: &fakeConn{},
			}
			Ω(client.Conn).Should(Equal(&fakeConn{}))
			client.Close()
			Ω(client.Conn).Should(BeNil())
		})
	})

	Describe("#Bind", func() {
		var (
			bindDN       string
			bindPassword string
			err          error
		)

		JustBeforeEach(func() {
			config := &Config{
				BindDN:       bindDN,
				BindPassword: bindPassword,
			}
			client := &Client{
				Conn:   &fakeConn{},
				Config: config,
			}
			err = client.Bind()
		})

		Context("when BindDN and BindPassword are set", func() {
			BeforeEach(func() {
				bindDN = "bindDN"
			})

			Context("and bind fails", func() {
				BeforeEach(func() {
					bindPassword = "invalid"
				})

				It("returns an error", func() {
					Ω(err).Should(MatchError("ldap bind failed"))
				})
			})

			Context("and the bind works", func() {
				BeforeEach(func() {
					bindPassword = "valid"
				})

				It("does not return an error", func() {
					Ω(err).Should(BeNil())
				})
			})
		})

		Context("when the BindDN is not set", func() {
			BeforeEach(func() {
				bindDN = ""
			})

			It("returns an error", func() {
				Ω(err).Should(MatchError("BindDN or BindPassword was not set on Client config"))
			})
		})

		Context("when the BindPassword is not set", func() {
			BeforeEach(func() {
				bindPassword = ""
			})

			It("returns an error", func() {
				Ω(err).Should(MatchError("BindDN or BindPassword was not set on Client config"))
			})
		})

		Context("when the BindDN and BindPassword are not set", func() {
			BeforeEach(func() {
				bindDN = ""
				bindPassword = ""
			})

			It("returns an error", func() {
				Ω(err).Should(MatchError("BindDN or BindPassword was not set on Client config"))
			})
		})
	})

	Describe("#Authenticate", func() {
		var (
			authenticated bool
			user          map[string]string
			err           error
			username      string
			password      string
		)

		JustBeforeEach(func() {
			client := &Client{
				Conn: &fakeConn{},
				Config: &Config{
					BindDN:       "bindDN",
					BindPassword: "valid",
					Attributes:   []string{"attribute1"},
				},
			}
			Ω(client.Bind()).Should(BeNil())
			authenticated, user, err = client.Authenticate(username, password)
		})

		Context("and the ldap search fails", func() {
			BeforeEach(func() {
				username = "failedSearch"
				password = "password"
			})

			It("returns an error", func() {
				Ω(err).Should(MatchError("failed ldap search"))
				Ω(authenticated).Should(BeFalse())
				Ω(user).Should(BeNil())
			})
		})

		Context("and the ldap search is successful", func() {
			Context("and the ldap search returned no results", func() {
				BeforeEach(func() {
					username = "notExist"
					password = "password"
				})

				It("returns an error", func() {
					Ω(err).Should(MatchError("User does not exist"))
					Ω(authenticated).Should(BeFalse())
					Ω(user).Should(BeNil())
				})
			})

			Context("and the ldap search returned more than 1 results", func() {
				BeforeEach(func() {
					username = "tooMany"
					password = "password"
				})

				It("returns an error", func() {
					Ω(err).Should(MatchError("Too many entries returned"))
					Ω(authenticated).Should(BeFalse())
					Ω(user).Should(BeNil())
				})
			})

			Context("and the ldap search returned exactly 1 results", func() {
				BeforeEach(func() {
					username = "user"
				})

				Context("and the password is incorrect", func() {
					BeforeEach(func() {
						password = "invalid"
					})

					It("returns an error and the user that was found", func() {
						Ω(err).Should(MatchError("ldap bind failed"))
						Ω(authenticated).Should(BeFalse())
						Ω(user).Should(Equal(map[string]string{"attribute1": ""}))
					})
				})

				Context("and the password is correct", func() {
					BeforeEach(func() {
						password = "valid"
					})

					It("returns authenticated true and the user properties", func() {
						Ω(err).Should(BeNil())
						Ω(authenticated).Should(BeTrue())
						Ω(user).Should(Equal(map[string]string{"attribute1": ""}))
					})
				})
			})
		})
	})
})
