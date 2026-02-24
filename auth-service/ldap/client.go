package ldap

import (
	"errors"
	"fmt"
	"os"

	"github.com/go-ldap/ldap/v3"
)

type Client struct {
	host    string
	port    string
	adminDN string
	adminPW string
	baseDN  string
}

func NewClient() *Client {
	return &Client{
		host:    os.Getenv("LDAP_HOST"),
		port:    os.Getenv("LDAP_PORT"),
		adminDN: fmt.Sprintf("cn=%s,dc=example,dc=com", os.Getenv("LDAP_ADMIN_USERNAME")),
		adminPW: os.Getenv("LDAP_ADMIN_PASSWORD"),
		baseDN:  os.Getenv("LDAP_ROOT"),
	}
}

func (c *Client) Authenticate(username, password string) (bool, error) {
	conn, err := ldap.Dial("tcp", fmt.Sprintf("%s:%s", c.host, c.port))
	if err != nil {
		return false, fmt.Errorf("failed to connect to LDAP: %w", err)
	}
	defer conn.Close()

	// Bind as admin to search
	err = conn.Bind(c.adminDN, c.adminPW)
	if err != nil {
		return false, fmt.Errorf("admin bind failed: %w", err)
	}

	// Search for user by uid
	searchRequest := ldap.NewSearchRequest(
		c.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		fmt.Sprintf("(uid=%s)", ldap.EscapeFilter(username)),
		[]string{"dn"},
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		return false, fmt.Errorf("search failed: %w", err)
	}

	// User not found in directory — not a system error
	if len(result.Entries) == 0 {
		return false, nil
	}

	// Ambiguous — multiple users with same uid — real problem
	if len(result.Entries) > 1 {
		return false, fmt.Errorf("ambiguous user search: %d results for uid=%s", len(result.Entries), username)
	}

	userDN := result.Entries[0].DN

	// Bind as user to verify password
	err = conn.Bind(userDN, password)
	if err != nil {
		// Check if it's specifically an invalid credentials error
		// LDAP error code 49 = Invalid Credentials (wrong password)
		// This is NOT a system error — return false, nil cleanly
		var ldapErr *ldap.Error
		if errors.As(err, &ldapErr) && ldapErr.ResultCode == ldap.LDAPResultInvalidCredentials {
			return false, nil
		}
		// Any other LDAP error is a real system problem
		return false, fmt.Errorf("user bind failed: %w", err)
	}

	return true, nil
}