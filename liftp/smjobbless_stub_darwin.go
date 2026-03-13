//go:build darwin

package liftp

import "errors"

var errSMJobBlessSetupRequired = errors.New("SMJobBless 未配置：需要签名的 .app、privileged helper、launchd plist 和匹配的 code signing 配置")

// EnsurePrivilegedHelperInstalled is the future macOS entrypoint for the
// SMJobBless-based privilege architecture. A full implementation requires app
// bundle packaging, helper installation metadata, and signing identities.
func EnsurePrivilegedHelperInstalled(why string) error {
	_ = why
	return errSMJobBlessSetupRequired
}
