//go:build darwin && cgo

package machineenrollment

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security -framework IOKit
#include <stdlib.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <IOKit/IOKitLib.h>

enum { snykAlgPKCS1 = 0, snykAlgPSS = 1, snykAlgECDSA = 2 };

// snyk_copy_identities returns every identity in the keychain search list (which includes the
// System keychain), or NULL with status set. Looking identities up does not prompt.
static CFArrayRef snyk_copy_identities(OSStatus *status) {
	const void *keys[] = { kSecClass, kSecMatchLimit, kSecReturnRef };
	const void *values[] = { kSecClassIdentity, kSecMatchLimitAll, kCFBooleanTrue };
	CFDictionaryRef query = CFDictionaryCreate(kCFAllocatorDefault, keys, values, 3,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFTypeRef result = NULL;
	*status = SecItemCopyMatching(query, &result);
	CFRelease(query);
	if (*status != errSecSuccess) {
		return NULL;
	}
	if (CFGetTypeID(result) != CFArrayGetTypeID()) {
		CFRelease(result);
		*status = errSecInternalComponent;
		return NULL;
	}
	return (CFArrayRef)result;
}

// snyk_copy_certificate_der returns the DER of identity i's certificate, or NULL.
static CFDataRef snyk_copy_certificate_der(CFArrayRef identities, CFIndex i) {
	SecIdentityRef identity = (SecIdentityRef)CFArrayGetValueAtIndex(identities, i);
	SecCertificateRef cert = NULL;
	if (SecIdentityCopyCertificate(identity, &cert) != errSecSuccess) {
		return NULL;
	}
	CFDataRef der = SecCertificateCopyData(cert);
	CFRelease(cert);
	return der;
}

// snyk_sign_digest signs a SHA-256 digest with identity i's private key. This is where the
// keychain asks the user to allow access to the key.
static CFDataRef snyk_sign_digest(CFArrayRef identities, CFIndex i, int alg, const UInt8 *digest, CFIndex len, CFErrorRef *error) {
	SecIdentityRef identity = (SecIdentityRef)CFArrayGetValueAtIndex(identities, i);
	SecKeyRef key = NULL;
	OSStatus status = SecIdentityCopyPrivateKey(identity, &key);
	if (status != errSecSuccess) {
		*error = CFErrorCreate(kCFAllocatorDefault, kCFErrorDomainOSStatus, status, NULL);
		return NULL;
	}
	SecKeyAlgorithm algorithm = kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256;
	if (alg == snykAlgPSS) {
		algorithm = kSecKeyAlgorithmRSASignatureDigestPSSSHA256;
	} else if (alg == snykAlgECDSA) {
		algorithm = kSecKeyAlgorithmECDSASignatureDigestX962SHA256;
	}
	CFDataRef data = CFDataCreate(kCFAllocatorDefault, digest, len);
	CFDataRef sig = SecKeyCreateSignature(key, algorithm, data, error);
	CFRelease(data);
	CFRelease(key);
	return sig;
}

// snyk_copy_cstring returns s as a malloc'd UTF-8 C string.
static char *snyk_copy_cstring(CFStringRef s) {
	CFIndex max = CFStringGetMaximumSizeForEncoding(CFStringGetLength(s), kCFStringEncodingUTF8) + 1;
	char *buf = malloc(max);
	if (!CFStringGetCString(s, buf, max, kCFStringEncodingUTF8)) {
		buf[0] = 0;
	}
	return buf;
}

// snyk_copy_error_description returns err's description as a malloc'd C string.
static char *snyk_copy_error_description(CFErrorRef err) {
	CFStringRef desc = CFErrorCopyDescription(err);
	char *out = snyk_copy_cstring(desc);
	CFRelease(desc);
	return out;
}

// snyk_copy_platform_property returns a string property of the platform expert device (such as
// IOPlatformUUID) as a malloc'd C string, or NULL.
static char *snyk_copy_platform_property(const char *name) {
	io_service_t svc = IOServiceGetMatchingService(MACH_PORT_NULL, IOServiceMatching("IOPlatformExpertDevice"));
	if (!svc) {
		return NULL;
	}
	CFStringRef key = CFStringCreateWithCString(kCFAllocatorDefault, name, kCFStringEncodingUTF8);
	CFTypeRef value = IORegistryEntryCreateCFProperty(svc, key, kCFAllocatorDefault, 0);
	CFRelease(key);
	IOObjectRelease(svc);
	if (!value) {
		return NULL;
	}
	char *out = NULL;
	if (CFGetTypeID(value) == CFStringGetTypeID()) {
		out = snyk_copy_cstring((CFStringRef)value);
	}
	CFRelease(value);
	return out;
}
*/
import "C"

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
	"unsafe"
)

// SystemKeychain returns the macOS keychain, which searches the user's keychains and the System
// keychain, where device management installs its identities.
func SystemKeychain() Keychain {
	return systemKeychain{}
}

type systemKeychain struct{}

func (systemKeychain) Identity(acceptedIssuers [][]byte) (DeviceIdentity, error) {
	var status C.OSStatus
	identities := C.snyk_copy_identities(&status)
	if status == C.errSecItemNotFound {
		return nil, ErrNoIdentity
	}
	if status != C.errSecSuccess {
		return nil, fmt.Errorf("failed listing keychain identities: OSStatus %d", int(status))
	}

	count := int(C.CFArrayGetCount(identities))
	certs := make([]*x509.Certificate, count)
	for i := range count {
		der := C.snyk_copy_certificate_der(identities, C.CFIndex(i))
		if der == 0 {
			continue
		}
		cert, err := x509.ParseCertificate(cfDataBytes(der))
		C.CFRelease(C.CFTypeRef(der))
		if err == nil {
			certs[i] = cert
		}
	}

	i := selectCertificate(certs, acceptedIssuers, time.Now())
	if i < 0 {
		C.CFRelease(C.CFTypeRef(identities))
		return nil, ErrNoIdentity
	}
	return &keychainIdentity{identities: identities, index: C.CFIndex(i), cert: certs[i]}, nil
}

func (systemKeychain) DeviceInfo() DeviceInfo {
	return DeviceInfo{UDID: platformProperty("IOPlatformUUID"), Serial: platformProperty("IOPlatformSerialNumber")}
}

// keychainIdentity is an identity whose private key stays in the keychain.
type keychainIdentity struct {
	mu         sync.Mutex
	identities C.CFArrayRef
	index      C.CFIndex
	cert       *x509.Certificate
}

func (k *keychainIdentity) Certificate() *x509.Certificate {
	return k.cert
}

func (k *keychainIdentity) Public() crypto.PublicKey {
	return k.cert.PublicKey
}

// Sign implements crypto.Signer for SHA-256 digests, using PSS when opts asks for it.
func (k *keychainIdentity) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != crypto.SHA256 || len(digest) != crypto.SHA256.Size() {
		return nil, errors.New("keychain identities only sign SHA-256 digests")
	}
	var alg C.int
	switch k.cert.PublicKey.(type) {
	case *rsa.PublicKey:
		alg = C.snykAlgPKCS1
		if _, ok := opts.(*rsa.PSSOptions); ok {
			alg = C.snykAlgPSS
		}
	case *ecdsa.PublicKey:
		alg = C.snykAlgECDSA
	default:
		return nil, fmt.Errorf("unsupported identity key type %T", k.cert.PublicKey)
	}

	k.mu.Lock()
	defer k.mu.Unlock()
	if k.identities == 0 {
		return nil, errors.New("identity is closed")
	}

	var cfErr C.CFErrorRef
	sig := C.snyk_sign_digest(k.identities, k.index, alg, (*C.UInt8)(unsafe.Pointer(&digest[0])), C.CFIndex(len(digest)), &cfErr)
	if sig == 0 {
		if cfErr == 0 {
			return nil, errors.New("failed signing with keychain identity")
		}
		desc := C.snyk_copy_error_description(cfErr)
		defer C.free(unsafe.Pointer(desc))
		C.CFRelease(C.CFTypeRef(cfErr))
		return nil, fmt.Errorf("failed signing with keychain identity: %s", C.GoString(desc))
	}
	defer C.CFRelease(C.CFTypeRef(sig))
	return cfDataBytes(sig), nil
}

func (k *keychainIdentity) Close() {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.identities != 0 {
		C.CFRelease(C.CFTypeRef(k.identities))
		k.identities = 0
	}
}

func cfDataBytes(d C.CFDataRef) []byte {
	return C.GoBytes(unsafe.Pointer(C.CFDataGetBytePtr(d)), C.int(C.CFDataGetLength(d)))
}

func platformProperty(name string) string {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	value := C.snyk_copy_platform_property(cname)
	if value == nil {
		return ""
	}
	defer C.free(unsafe.Pointer(value))
	return C.GoString(value)
}
