package ldapClient_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestGoLdapClient(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "GoLdapClient Suite")
}
