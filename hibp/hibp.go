// Package hibp implements a Have I Been Pwned (HIBP) client.
package hibp

import (
	"context"
	"net/http"
)

// defaultHIBPBaseURL is the default base URL for the HIBP API.
const defaultHIBPBaseURL = "https://haveibeenpwned.com/api/v3/"

// defaultPPBaseURL is the default base URL for the Pwned Passwords API.
const defaultPPBaseURL = "https://api.pwnedpasswords.com/range/"

// Breach represents a data breach.
type Breach struct {
	// A Pascal-cased name representing the breach which is unique across all
	// other breaches. This value never changes and may be used to name
	// dependent assets (such as images) but should not be shown directly to end
	// users (see the "Title" attribute instead).
	Name string `json:"Name"`
	// A descriptive title for the breach suitable for displaying to end users.
	// It's unique across all breaches but individual values may change in the
	// future (i.e. if another breach occurs against an organisation already in
	// the system). If a stable value is required to reference the breach, refer
	// to the "Name" attribute instead.
	Title string `json:"Title"`
	// The domain of the primary website the breach occurred on. This may be
	// used for identifying other assets external systems may have for the site.
	Domain string `json:"Domain"`
	// The date (with no time) the breach originally occurred on in ISO 8601
	// format. This is not always accurate -- frequently breaches are discovered
	// and reported long after the original incident. Use this attribute as a
	// guide only.
	BreachDate string `json:"BreachDate"`
	// The date and time (precision to the minute) the breach was added to the
	// system in ISO 8601 format.
	AddedDate string `json:"AddedDate"`
	// The date and time (precision to the minute) the breach was modified in
	// ISO 8601 format. This will only differ from the AddedDate attribute if
	// other attributes represented here are changed or data in the breach
	// itself is changed (i.e. additional data is identified and loaded). It is
	// always either equal to or greater then the AddedDate attribute, never
	// less than.
	ModifiedDate string `json:"ModifiedDate"`
	// The total number of accounts loaded into the system. This is usually less
	// than the total number reported by the media due to duplication or other
	// data integrity issues in the source data.
	PwnCount int `json:"PwnCount"`
	// Contains an overview of the breach represented in HTML markup. The
	// description may include markup such as emphasis and strong tags as well
	// as hyperlinks.
	Description string `json:"Description"`
	// This attribute describes the nature of the data compromised in the breach
	// and contains an alphabetically ordered string array of impacted data
	// classes.
	DataClasses []string `json:"DataClasses"`
	// Indicates that the breach is considered [unverified]. An unverified
	// breach may not have been hacked from the indicated website. An unverified
	// breach is still loaded into HIBP when there's sufficient confidence that
	// a significant portion of the data is legitimate.
	//
	// [unverified]: https://haveibeenpwned.com/FAQs#UnverifiedBreach
	IsVerified bool `json:"IsVerified"`
	// 	Indicates that the breach is considered [fabricated]. A fabricated
	// breach is unlikely to have been hacked from the indicated website and
	// usually contains a large amount of manufactured data. However, it still
	// contains legitimate email addresses and asserts that the account owners
	// were compromised in the alleged breach.
	//
	// [fabricated]: https://haveibeenpwned.com/FAQs#FabricatedBreach
	IsFabricated bool `json:"IsFabricated"`
	// Indicates if the breach is considered [sensitive]. The public API will
	// not return any accounts for a breach flagged as sensitive.
	//
	// [sensitive]: https://haveibeenpwned.com/FAQs#SensitiveBreach
	IsSensitive bool `json:"IsSensitive"`
	//	Indicates if the breach has been [retired]. This data has been
	// permanently removed and will not be returned by the API.
	//
	// [retired]: https://haveibeenpwned.com/FAQs#RetiredBreach
	IsRetired bool `json:"IsRetired"`
	// Indicates if the breach is considered a [spam list]. This flag has no
	// impact on any other attributes but it means that the data has not come as
	// a result of a security compromise.
	//
	// [spam list]: https://haveibeenpwned.com/FAQs#SpamList
	IsSpamList bool `json:"IsSpamList"`
	// Indicates if the breach is sourced from [malware]. This flag has no
	// impact on any other attributes, it merely flags that the data was sourced
	// from a malware campaign rather than a security compromise of an online
	// service.
	//
	// [malware]: https://haveibeenpwned.com/FAQs#Malware
	IsMalware bool `json:"IsMalware"`
	// A URI that specifies where a logo for the breached service can be found.
	// Logos are always in PNG format.
	LogoPath string `json:"LogoPath"`
}

// Paste represents a data paste.
type Paste struct {
	// The paste service the record was retrieved from. Current values are:
	// Pastebin, Pastie, Slexy, Ghostbin, QuickLeak, JustPaste, AdHocUrl,
	// PermanentOptOut, OptOut.
	Source string `json:"Source"`
	// The ID of the paste as it was given at the source service. Combined with
	// the "Source" attribute, this can be used to resolve the URL of the paste.
	ID string `json:"Id"`
	// The title of the paste as observed on the source site. This may be null
	// and if so will be omitted from the response.
	Title string `json:"Title"`
	// The date and time (precision to the second) that the paste was posted.
	// This is taken directly from the paste site when this information is
	// available but may be null if no date is published.
	Date string `json:"Date"`
	// The number of emails that were found when processing the paste. Emails
	// are extracted by using the regular expression:
	//
	//   `\b[a-zA-Z0-9\.\-_\+]+@[a-zA-Z0-9\.\-_]+\.[a-zA-Z]+\b`
	EmailCount int `json:"EmailCount"`
}

// Client is a client for the HIBP API.
type Client struct {
	h           *http.Client
	key         string
	userAgent   string
	hibpBaseURL string
	ppBaseURL   string
}

// NewClient returns a new HIBP client.
func NewClient(apiKey, userAgent string) *Client {
	return &Client{
		h:           http.DefaultClient,
		key:         apiKey,
		userAgent:   userAgent,
		hibpBaseURL: defaultHIBPBaseURL,
		ppBaseURL:   defaultPPBaseURL,
	}
}

// SetHTTPClient causes the HIBP client to use a custom HTTP client.
func (c *Client) SetHTTPClient(h *http.Client) {
	c.h = h
}

// AccountBreachesRequest describes a [Client.AccountBreaches] request.
type AccountBreachesRequest struct {
	Account           string // Required. The account to retrieve breaches for.
	Domain            string // If set, only return breaches for this domain.
	TruncateResponse  bool   // If true, just return breach names.
	IncludeUnverified bool   // If true, also return "unverified" breaches.
}

// AccountBreaches returns all breaches for an account.
func (c *Client) AccountBreaches(ctx context.Context, req AccountBreachesRequest) ([]Breach, error) {
	return nil, nil
}

// AccountPastesRequest describes a [Client.AccountPastes] request.
type AccountPastesRequest struct {
	Account string // The account to retrieve pastes for.
}

// AccountPastes returns all pastes for an account.
func (c *Client) AccountPastes(ctx context.Context, req AccountPastesRequest) ([]Paste, error) {
	return nil, nil
}

// BreachRequest describes a [Client.Breach] request.
type BreachRequest struct {
	Name string // The name of the breach to retrieve.
}

// Breach returns a single breach by name.
func (c *Client) Breach(ctx context.Context, req BreachRequest) (*Breach, error) {
	return nil, nil
}

// Breaches returns all breaches in the system.
func (c *Client) Breaches(ctx context.Context) ([]Breach, error) {
	return nil, nil
}

// DataClasses returns all data classes in the system. A "data class" is an
// attribute of a record compromised in a breach. For example, many breaches
// expose data classes such as "Email addresses" and "Passwords".
func (c *Client) DataClasses(ctx context.Context) ([]string, error) {
	return nil, nil
}

// HashType represents the type of a Pwned Passwords hash.
type HashType int

// HashType constants.
const (
	HashTypeSHA1 HashType = iota
	HashTypeNTLM
)

// HashSuffixesRequest describes a [Client.HashSuffixes] request.
type HashSuffixesRequest struct {
	Prefix     string   // The prefix of the hash to search for.
	HashType   HashType // The type of hash to search for.
	AddPadding bool     // If true, pad server responses to enhance privacy.
}

// HashSuffixes returns, for a given password hash prefix, all seen suffixes and
// their frequencies.
func (c *Client) HashSuffixes(ctx context.Context, req HashSuffixesRequest) (map[string]int, error) {
	return nil, nil
}

// IsPwnedPassword returns true if the given password has been pwned. This is a
// helper function that checks both the SHA-1 and NTLM hash of the password.
func (c *Client) IsPwnedPassword(ctx context.Context, password string) (bool, error) {
	return false, nil
}