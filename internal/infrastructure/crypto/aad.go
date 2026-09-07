package crypto

import "strings"

// BuildAAD constructs the Additional Authenticated Data for AES-GCM.
func BuildAAD(method, path, cryptoVersion, cryptoSessionID, requestID, fieldPath, tenantID string) []byte {
	parts := []string{
		strings.ToUpper(method),
		path,
		cryptoVersion,
		cryptoSessionID,
		requestID,
		tenantID,
		fieldPath,
	}
	return []byte(strings.Join(parts, ":"))
}
