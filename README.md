# go-ldap-client

[![codecov.io](https://codecov.io/github/FidelityInternational/go-ldap-client/coverage.svg?branch=master)](https://codecov.io/github/FidelityInternational/go-ldap-client?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/FidelityInternational/go-ldap-client)](https://goreportcard.com/report/github.com/FidelityInternational/go-ldap-client) [![Build Status](https://travis-ci.org/FidelityInternational/go-ldap-client.svg?branch=master)](https://travis-ci.org/FidelityInternational/go-ldap-client)

A simple [GoLang](https://golang.org) LDAP client for authenticating users. It is effectively a wrapper around [gopkg.in/ldap.v2](https://github.com/go-ldap/ldap) and aims at making LDAP easier to use.

At the moment the main aim is for making user authentication as easy as possible by providing an Authenticate function that looks up the user, tests their password and then resets the bind user back to the base config. One bit of useful functionality is that the client exposes `ldap.Client` from `gopkg.in/ldap.v2` via `ldapClient.Conn`, this should allow you to use any functionality of the base package and use this a simpler initilaiser.

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
  defer client.Close()
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
