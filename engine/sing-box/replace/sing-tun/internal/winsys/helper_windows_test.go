package winsys

import (
	"bytes"
	"runtime"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestCurrentProcessUserIDIsExact(t *testing.T) {
	blob, err := GetCurrentProcessUserID()
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.KeepAlive(blob)
	sd := (*windows.SECURITY_DESCRIPTOR)(unsafe.Pointer(blob.data))
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_SELF_RELATIVE == 0 || blob.size != sd.Length() {
		t.Fatal("WFP user identity must be a complete self-relative descriptor")
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil || acl.AceCount != 1 {
		t.Fatal("WFP user identity must have exactly one access ACE")
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(acl, 0, &ace); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 ||
		ace.Mask != 1 || !(*windows.SID)(unsafe.Pointer(&ace.SidStart)).Equals(user.User.Sid) {
		t.Fatal("WFP permit must match only the current process user")
	}

	// The App guard constructs its LocalSystem exception with the SY alias.
	// Exact blob comparison must recognize the process SID's numeric spelling.
	numeric, err := windows.SecurityDescriptorFromString("D:(A;;CC;;;S-1-5-18)")
	if err != nil {
		t.Fatal(err)
	}
	alias, err := windows.SecurityDescriptorFromString("D:(A;;CC;;;SY)")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unsafe.Slice((*byte)(unsafe.Pointer(numeric)), numeric.Length()),
		unsafe.Slice((*byte)(unsafe.Pointer(alias)), alias.Length())) {
		t.Fatal("Core and App LocalSystem descriptors must match exactly")
	}
}
