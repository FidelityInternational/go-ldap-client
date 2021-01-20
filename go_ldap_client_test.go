package ldapClient_test

import (
	"crypto/tls"
	"fmt"

	. "github.com/FidelityInternational/go-ldap-client"
	"github.com/go-ldap/ldap/v3"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

type fakeConn struct {
	ldap.Conn
	mock.Mock
}

func (fc *fakeConn) Close() {}

func (fc *fakeConn) Bind(username, password string) error {
	args := fc.Called(username, password)
	return args.Error(0)
}

func (fc *fakeConn) Search(searchReq *ldap.SearchRequest) (*ldap.SearchResult, error) {
	args := fc.Called(searchReq)
	return args.Get(0).(*ldap.SearchResult), args.Error(1)
}

func setFakeConn(bindErr error) *fakeConn {
	fakeConnection := &fakeConn{}
	fakeConnection.On("Bind", "magicUser", mock.AnythingOfType("string")).Return(nil)
	fakeConnection.On("Bind", mock.AnythingOfType("string"), mock.AnythingOfType("string")).Return(bindErr)
	return fakeConnection
}

func (fc *fakeConn) fakeSearch(searchRes *ldap.SearchResult, err error) {
	fc.On("Search", mock.AnythingOfType("*ldap.SearchRequest")).Return(searchRes, err)
}

var singleUser = &ldap.SearchResult{
	Entries: []*ldap.Entry{
		{
			DN: "dn1",
		},
	},
}

var multiUser = &ldap.SearchResult{
	Entries: []*ldap.Entry{
		{
			DN: "dn1",
		},
		{
			DN: "dn1",
		},
	},
}

var noUser = &ldap.SearchResult{}

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
			Context("and the ca cert is invalid", func() {
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
						CACertificates: []byte("a CA Cert"),
						BindDN:         "username",
						BindPassword:   "password",
					}
				})

				It("returns an error", func() {
					Ω(err).Should(MatchError("Could not append CA certs from PEM"))
					Ω(client).Should(Equal(&Client{}))
				})
			})

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
						BindDN:       "username",
						BindPassword: "password",
					}
				})

				It("returns an error", func() {
					Ω(err).ShouldNot(BeNil())
					Ω(err.Error()).Should(MatchRegexp("LDAP Result Code 200.*"))
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
					Ω(err).ShouldNot(BeNil())
					Ω(err.Error()).Should(MatchRegexp("LDAP Result Code 200.*"))
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
			err            error
			fakeConnection *fakeConn
			bindDN         = "username"
			bindPassword   = "password"
		)

		JustBeforeEach(func() {
			config := &Config{
				BindDN:       bindDN,
				BindPassword: bindPassword,
			}
			client := &Client{
				Conn:   fakeConnection,
				Config: config,
			}
			err = client.Bind()
		})

		AfterEach(func() {
			bindDN = "username"
			bindPassword = "password"
		})

		Context("when BindDN and BindPassword are set", func() {
			Context("and bind fails", func() {
				BeforeEach(func() {
					fakeConnection = setFakeConn(fmt.Errorf("ldap bind failed"))
				})

				It("returns an error", func() {
					Ω(err).Should(MatchError("ldap bind failed"))
				})
			})

			Context("and the bind works", func() {
				BeforeEach(func() {
					fakeConnection = setFakeConn(nil)
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
			authenticated  bool
			user           map[string]string
			err            error
			bindDN         = "magicUser"
			bindPassword   = "password"
			fakeConnection *fakeConn
		)

		JustBeforeEach(func() {
			client := &Client{
				Conn: fakeConnection,
				Config: &Config{
					BindDN:       bindDN,
					BindPassword: bindPassword,
					Attributes:   []string{"attribute1"},
				},
			}
			Ω(client.Bind()).Should(BeNil())
			authenticated, user, err = client.Authenticate("authUsername", "password")
		})

		Context("and the ldap search fails", func() {
			BeforeEach(func() {
				fakeConnection = setFakeConn(nil)
				fakeConnection.fakeSearch(noUser, fmt.Errorf("failed ldap search"))
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
					fakeConnection = setFakeConn(nil)
					fakeConnection.fakeSearch(noUser, nil)
				})

				It("returns an error", func() {
					Ω(err).Should(MatchError("User does not exist"))
					Ω(authenticated).Should(BeFalse())
					Ω(user).Should(BeNil())
				})
			})

			Context("and the ldap search returned more than 1 results", func() {
				BeforeEach(func() {
					fakeConnection = setFakeConn(nil)
					fakeConnection.fakeSearch(multiUser, nil)
				})

				It("returns an error", func() {
					Ω(err).Should(MatchError("Too many entries returned"))
					Ω(authenticated).Should(BeFalse())
					Ω(user).Should(BeNil())
				})
			})

			Context("and the ldap search returned exactly 1 results", func() {
				Context("and the password is incorrect", func() {
					BeforeEach(func() {
						fakeConnection = setFakeConn(fmt.Errorf("ldap bind failed"))
						fakeConnection.fakeSearch(singleUser, nil)
					})

					It("returns an error and the user that was found", func() {
						Ω(err).Should(MatchError("ldap bind failed"))
						Ω(authenticated).Should(BeFalse())
						Ω(user).Should(Equal(map[string]string{"attribute1": ""}))
					})
				})

				Context("and the password is correct", func() {
					BeforeEach(func() {
						fakeConnection = setFakeConn(nil)
						fakeConnection.fakeSearch(singleUser, nil)
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
