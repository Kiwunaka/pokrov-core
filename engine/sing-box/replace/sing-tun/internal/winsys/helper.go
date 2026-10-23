//go:build windows

package winsys

import (
	"os"
	"unsafe"

	"github.com/sagernet/sing/common"

	"golang.org/x/sys/windows"
)

func CreateDisplayData(name, description string) FWPM_DISPLAY_DATA0 {
	namePtr, err := windows.UTF16PtrFromString(name)
	common.Must(err)

	descriptionPtr, err := windows.UTF16PtrFromString(description)
	common.Must(err)

	return FWPM_DISPLAY_DATA0{
		Name:        namePtr,
		Description: descriptionPtr,
	}
}

func GetCurrentProcessAppID() (*FWP_BYTE_BLOB, error) {
	currentFile, err := os.Executable()
	if err != nil {
		return nil, err
	}

	curFilePtr, err := windows.UTF16PtrFromString(currentFile)
	if err != nil {
		return nil, err
	}

	windows.GetCurrentProcessId()

	var appID *FWP_BYTE_BLOB
	err = FwpmGetAppIdFromFileName0(curFilePtr, unsafe.Pointer(&appID))
	if err != nil {
		return nil, err
	}
	return appID, nil
}

// GetCurrentProcessUserID returns a Go-owned, self-relative descriptor for the
// process user, not an impersonated IPC caller. Keep the blob alive while WFP
// consumes its pointer; unlike GetCurrentProcessAppID it must not be freed by WFP.
func GetCurrentProcessUserID() (*FWP_BYTE_BLOB, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	// CC is FWP_ACTRL_MATCH_FILTER. No group or other executable user is allowed.
	sd, err := windows.SecurityDescriptorFromString("D:(A;;CC;;;" + user.User.Sid.String() + ")")
	if err != nil {
		return nil, err
	}
	return &FWP_BYTE_BLOB{size: sd.Length(), data: (*byte)(unsafe.Pointer(sd))}, nil
}
