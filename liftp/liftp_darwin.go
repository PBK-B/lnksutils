//go:build darwin

package liftp

/*
#cgo LDFLAGS: -framework Security

#include <Security/Authorization.h>
#include <Security/AuthorizationTags.h>
#include <string.h>
#include <stdlib.h>

static OSStatus lnks_authorize(char *prompt, AuthorizationRef *authRef) {
	AuthorizationItem right = {kAuthorizationRightExecute, 0, NULL, 0};
	AuthorizationRights rights = {1, &right};

	AuthorizationEnvironment environment = {0, NULL};
	AuthorizationItem promptItem = {kAuthorizationEnvironmentPrompt, 0, NULL, 0};
	if (prompt != NULL) {
		promptItem.valueLength = (UInt32)strlen(prompt);
		promptItem.value = prompt;
		environment.count = 1;
		environment.items = &promptItem;
	}

	OSStatus status = AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment, kAuthorizationFlagDefaults, authRef);
	if (status != errAuthorizationSuccess) {
		return status;
	}

	return AuthorizationCopyRights(
		*authRef,
		&rights,
		&environment,
		kAuthorizationFlagDefaults | kAuthorizationFlagInteractionAllowed | kAuthorizationFlagPreAuthorize | kAuthorizationFlagExtendRights,
		NULL
	);
}

static OSStatus lnks_exec_privileged(AuthorizationRef authRef, char *path, char **args) {
	#pragma clang diagnostic push
	#pragma clang diagnostic ignored "-Wdeprecated-declarations"
	OSStatus status = AuthorizationExecuteWithPrivileges(authRef, path, kAuthorizationFlagDefaults, args, NULL);
	#pragma clang diagnostic pop
	return status;
}
*/
import "C"

import (
	"errors"
	"os"
	"unsafe"
)

const errAuthorizationCanceled = -60006

func liftPrivilegeMacOS(why string) error {
	selfPath, err := os.Executable()
	if err != nil {
		return err
	}

	cPath := C.CString(selfPath)
	if cPath == nil {
		return errors.New("alloc executable path failed")
	}
	defer C.free(unsafe.Pointer(cPath))

	var cPrompt *C.char
	if why != "" {
		cPrompt = C.CString(why)
		if cPrompt == nil {
			return errors.New("alloc prompt failed")
		}
		defer C.free(unsafe.Pointer(cPrompt))
	}

	cArgs := make([]*C.char, 0, len(os.Args))
	for _, arg := range os.Args[1:] {
		cArg := C.CString(arg)
		if cArg == nil {
			for _, ptr := range cArgs {
				C.free(unsafe.Pointer(ptr))
			}
			return errors.New("alloc argument failed")
		}
		cArgs = append(cArgs, cArg)
	}
	defer func() {
		for _, ptr := range cArgs {
			C.free(unsafe.Pointer(ptr))
		}
	}()

	argv := make([]*C.char, 0, len(cArgs)+1)
	argv = append(argv, cArgs...)
	argv = append(argv, nil)

	var authRef C.AuthorizationRef
	status := C.lnks_authorize(cPrompt, &authRef)
	if status != C.errAuthorizationSuccess {
		if int(status) == errAuthorizationCanceled {
			return errors.New("用户取消密码输入")
		}
		return errors.New("macOS 授权失败")
	}
	defer C.AuthorizationFree(authRef, C.kAuthorizationFlagDefaults)

	status = C.lnks_exec_privileged(authRef, cPath, (**C.char)(unsafe.Pointer(&argv[0])))
	if status != C.errAuthorizationSuccess {
		if int(status) == errAuthorizationCanceled {
			return errors.New("用户取消密码输入")
		}
		return errors.New("macOS 提权执行失败")
	}

	os.Exit(0)
	return nil
}
