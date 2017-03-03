# go-ldap-client

A simple [GoLang](https://golang.org) LDAP client for authenticating users.

### Usage

[Go Doc](https://godoc.org/github.com/FidelityInternational/go-ldap-client)

### Example

```
package main

import (
  "fmt"
  "os"
  "github.com/FidelityInternational/go-ldap-client"
)

func main() {
  config := &ldapClient.Config{
    Base:         "dc=example,dc=com",
    Host:         "ldap.example.com",
    Port:         389,
    UseSSL:       false,
    BindDN:       "uid=exampleUser,ou=examplePeople,dc=example,dc=com",
    BindPassword: "exampleUserPassword",
    UserFilter:   "(userName=%s)",
    GroupFilter:  "(groupName=%s)",
    Attributes:   []string{"userName", "sn", "mail", "id"},
  }
  client, err := ldapClient.New(config)
  if err != nil {
    fmt.Println(err)
    os.Exit(1)
  }
  authenticated, user, err := client.Authenticate("aUsername", "aPassword")
  if err != nil {
    fmt.Println(err)
    os.Exit(1)
  }
  if !authenticated {
    fmt.Printf("Authentication failed for user: %v\n", "aUsername")
  }
  fmt.Printf("Authentication successful for user: %v\n", "aUsername")
  fmt.Printf("%+v\n", user)
}
```
