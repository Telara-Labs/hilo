package clients

import (
	"testing"

	"golang.org/x/sys/windows"
)

func TestPrivateACLRejectsPublicAndMissingDACL(t *testing.T) {
	u, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		t.Fatal(e)
	}
	for _, descriptor := range []string{"O:" + u.User.Sid.String() + "D:", "O:" + u.User.Sid.String() + "D:P(A;;FA;;;WD)", "O:" + u.User.Sid.String() + "D:P(A;;FA;;;" + u.User.Sid.String() + ")(A;;FR;;;WD)"} {
		sd, e := windows.SecurityDescriptorFromString(descriptor)
		if e != nil {
			t.Fatal(e)
		}
		if privateACL(sd, u.User.Sid) {
			t.Fatal("public or null ACL accepted")
		}
	}
	sd, e := userSD()
	if e != nil || !privateACL(sd, u.User.Sid) {
		t.Fatalf("owner-only ACL rejected %v", e)
	}
}
