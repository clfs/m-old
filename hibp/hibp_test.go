package hibp

/*
Test accounts exist to demonstrate different behaviours. All accounts are on the domain "hibp-integration-tests.com", for example "account-exists@hibp-integration-tests.com".


Alias	Description
account-exists	Returns one breach and one paste.
multiple-breaches	Returns three breaches.
not-active-and-active-breach	Returns one breach being "Adobe". An inactive breach also exists against this account in the underlying data structure.
not-active-breach	Returns no breaches. An inactive data breach also exists against this account in the underlying data structure.
opt-out	Returns no breaches and no pastes. This account is opted-out of both pastes and breaches in the underlying data structure.
opt-out-breach	Returns no breaches and no pastes. This account is opted-out of breaches in the underlying data structure.
paste-sensitive-breach	Returns no breaches and one paste. A sensitive breach exists against this account in the underlying data structure.
permanent-opt-out	Returns no breaches and no pastes. This account is permanently opted-out of both breaches and pastes in the underlying data structure.
sensitive-and-other-breaches	Returns two non-sensitive breaches and no pastes. A sensitive breach exists against this account in the underlying data structure.
sensitive-breach	Returns no breaches and no pastes. A sensitive breach exists against this account in the underlying data structure.
unverified-breach	Returns one unverified breach and no pastes.
*/
/*
func NewTestServer(t *testing.T) *httptest.Server {
	t.Helper()

}

var TestAccounts = []string{
	"account-exists@hibp-integration-tests.com", // Returns one breach and one paste.
	"multiple-breaches@hibp-integration-tests.com", // Returns three breaches.
	"not-active-and-active-breach@hibp-integration-tests.com",
	"not-active-breach@hibp-integration-tests.com",
*/
