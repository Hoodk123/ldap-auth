package ldap
import(
	"fmt"
	"os"

	"github.com/go-ldap/ldap/v3"
)
type Client struct{
	host string
	port string 
	adminDN string 
	adminPW string
	baseDN string
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
		return false, fmt.Errorf("DIAL ERROR: %w", err)
	}
	defer conn.Close()

	err = conn.Bind(c.adminDN, c.adminPW)
	if err != nil {
		return false, fmt.Errorf("ADMIN BIND ERROR — DN used: %s — %w", c.adminDN, err)
	}

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
		return false, fmt.Errorf("SEARCH ERROR: %w", err)
	}

	if len(result.Entries) != 1 {
		return false, fmt.Errorf("USER NOT FOUND — searched for uid=%s in %s, got %d results", username, c.baseDN, len(result.Entries))
	}

	userDN := result.Entries[0].DN
	err = conn.Bind(userDN, password)
	if err != nil {
		return false, fmt.Errorf("USER BIND ERROR — DN: %s — %w", userDN, err)
	}

	return true, nil
}