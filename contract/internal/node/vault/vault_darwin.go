//go:build darwin && cgo

package vault

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#cgo CFLAGS: -Wno-deprecated-declarations
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <CommonCrypto/CommonDigest.h>

// Certificate-signed builds use an explicit stable requirement. Source builds
// use the default creator identity; never pass an empty trusted-applications ACL.
static OSStatus stableAccess(SecAccessRef *access) {
    SecCodeRef self = NULL; SecRequirementRef req = NULL;
    CFDictionaryRef info = NULL; CFStringRef text = NULL;
    OSStatus s = SecCodeCopySelf(kSecCSDefaultFlags, &self);
    if (!s) s = SecCodeCopySigningInformation(self, kSecCSSigningInformation, &info);
    CFNumberRef flags = info ? CFDictionaryGetValue(info, kSecCodeInfoFlags) : NULL;
    uint32_t f = 0;
    if (!s && (!flags || !CFNumberGetValue(flags, kCFNumberSInt32Type, &f))) s = errSecAuthFailed;
    if (!s && (f & kSecCodeSignatureAdhoc)) {
        // NULL access means the Keychain's creator-only default, not an ACL
        // whose NULL application list would allow every application.
        CFRelease(info); CFRelease(self); *access = NULL; return errSecSuccess;
    }
    if (!s) s = SecCodeCopyDesignatedRequirement(self, kSecCSDefaultFlags, &req);
    if (!s) s = SecRequirementCopyString(req, kSecCSDefaultFlags, &text);
    // Require exactly identifier AND leaf-certificate identity. Merely finding
    // "certificate" in an arbitrary requirement would also accept broad OR
    // expressions. Release signing must supply this explicit stable DR.
    CFArrayRef certs = info ? CFDictionaryGetValue(info, kSecCodeInfoCertificates) : NULL;
    CFStringRef identifier = info ? CFDictionaryGetValue(info, kSecCodeInfoIdentifier) : NULL;
    CFDataRef cert = (certs && CFArrayGetCount(certs)) ? SecCertificateCopyData((SecCertificateRef)CFArrayGetValueAtIndex(certs, 0)) : NULL;
    if (!s && (!cert || !identifier)) s = errSecAuthFailed;
    if (!s) {
        CFIndex length = CFStringGetLength(identifier);
        if (length == 0 || length > 255) s = errSecAuthFailed;
        for (CFIndex i=0; !s && i<length; i++) {
            UniChar c = CFStringGetCharacterAtIndex(identifier, i);
            if (!((c>='a'&&c<='z') || (c>='A'&&c<='Z') ||
                (c>='0'&&c<='9') || c=='.' || c=='-' || c=='_')) s=errSecAuthFailed;
        }
    }
    if (!s) {
        unsigned char digest[CC_SHA1_DIGEST_LENGTH]; char hex[41];
        CC_SHA1(CFDataGetBytePtr(cert), (CC_LONG)CFDataGetLength(cert), digest);
        for (int i=0;i<20;i++) snprintf(hex+2*i, 3, "%02x", digest[i]);
        CFStringRef wanted = CFStringCreateWithFormat(NULL, NULL,
            CFSTR("identifier \"%@\" and certificate leaf = H\"%s\""), identifier, hex);
        SecRequirementRef exact = NULL; CFStringRef canonical = NULL;
        s = SecRequirementCreateWithString(wanted, kSecCSDefaultFlags, &exact);
        if (!s) s = SecRequirementCopyString(exact, kSecCSDefaultFlags, &canonical);
        if (!s && !CFEqual(text, canonical)) s = errSecAuthFailed;
        if (canonical) CFRelease(canonical); if (exact) CFRelease(exact); CFRelease(wanted);
    }
    if (cert) CFRelease(cert);
    SecTrustedApplicationRef app = NULL;
    if (!s) s = SecTrustedApplicationCreateFromPath(NULL, &app);
    if (!s) {
        const void *apps[] = {app};
        CFArrayRef list = CFArrayCreate(NULL, apps, 1, &kCFTypeArrayCallBacks);
        s = SecAccessCreate(CFSTR("Telara Memory runtime authority"), list, access);
        CFRelease(list);
    }
    if (app) CFRelease(app); if (text) CFRelease(text);
    if (req) CFRelease(req); if (info) CFRelease(info); if (self) CFRelease(self);
    return s;
}
static int signingPolicyAvailable(void) {
    SecAccessRef access = NULL; OSStatus s = stableAccess(&access);
    if (access) CFRelease(access); return s == errSecSuccess;
}
static CFStringRef custodyService(void) {
    SecCodeRef self = NULL; CFDictionaryRef info = NULL;
    OSStatus s = SecCodeCopySelf(kSecCSDefaultFlags, &self);
    if (!s) s = SecCodeCopySigningInformation(self, kSecCSSigningInformation, &info);
    uint32_t flags = 0;
    CFNumberRef f = info ? CFDictionaryGetValue(info, kSecCodeInfoFlags) : NULL;
    if (!s && (!f || !CFNumberGetValue(f, kCFNumberSInt32Type, &flags))) s = errSecAuthFailed;
    CFStringRef result = NULL;
    if (!s && (flags & kSecCodeSignatureAdhoc)) {
        CFDataRef hash = CFDictionaryGetValue(info, kSecCodeInfoUnique);
        if (hash && CFDataGetLength(hash) > 0 && CFDataGetLength(hash) <= 64) {
            char hex[129]; CFIndex n = CFDataGetLength(hash);
            for (CFIndex i=0; i<n; i++) snprintf(hex+2*i, 3, "%02x", CFDataGetBytePtr(hash)[i]);
            result = CFStringCreateWithFormat(NULL, NULL, CFSTR("dev.telara.memory.runtime.%s"), hex);
        }
    } else if (!s) result = CFRetain(CFSTR("dev.telara.memory.runtime"));
    if (info) CFRelease(info); if (self) CFRelease(self);
    return result;
}
static CFMutableDictionaryRef query(const char *handle, SecKeychainRef kc, int adding, int legacy) {
    SecKeychainSetUserInteractionAllowed(false);
    CFMutableDictionaryRef q = CFDictionaryCreateMutable(NULL, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFStringRef h = CFStringCreateWithCString(NULL, handle, kCFStringEncodingUTF8);
    CFDictionarySetValue(q, kSecClass, kSecClassGenericPassword);
    CFStringRef service = legacy ? CFRetain(CFSTR("dev.telara.memory.runtime")) : custodyService();
    if (!service) { CFRelease(q); CFRelease(h); return NULL; }
    CFDictionarySetValue(q, kSecAttrService, service); CFRelease(service);
    CFDictionarySetValue(q, kSecAttrAccount, h);
    CFDictionarySetValue(q, kSecUseAuthenticationUI, kSecUseAuthenticationUIFail);
    CFRelease(h);
    if (kc) {
        if (adding) CFDictionarySetValue(q, kSecUseKeychain, kc);
        else {
            const void *v[] = {kc};
            CFArrayRef a = CFArrayCreate(NULL, v, 1, &kCFTypeArrayCallBacks);
            CFDictionarySetValue(q, kSecMatchSearchList, a);
            CFRelease(a);
        }
    }
    return q;
}
static OSStatus putSecret(const char *h, const void *p, size_t n, uintptr_t kc) {
    CFMutableDictionaryRef q = query(h, (SecKeychainRef)kc, 1, 0);
    if (!q) return errSecAuthFailed;
    SecAccessRef access = NULL;
    OSStatus accessStatus = stableAccess(&access);
    if (accessStatus) { CFRelease(q); return accessStatus; }
    if (access) { CFDictionarySetValue(q, kSecAttrAccess, access); CFRelease(access); }
    // No native plaintext copy. CFData borrows the Go caller's pinned bytes
    // only for the synchronous SecItemAdd call and cannot outlive it.
    CFDataRef data = CFDataCreateWithBytesNoCopy(NULL, p, n, kCFAllocatorNull);
    CFDictionarySetValue(q, kSecValueData, data);
    OSStatus s = SecItemAdd(q, NULL); // atomic duplicate refusal, no update
    CFRelease(data); CFRelease(q);
    return s;
}
static OSStatus getSecretSlot(const char *h, void *p, size_t *n, uintptr_t kc, int legacy) {
    CFMutableDictionaryRef q = query(h, (SecKeychainRef)kc, 0, legacy);
    if (!q) return errSecAuthFailed;
    CFDictionarySetValue(q, kSecReturnRef, kCFBooleanTrue);
    CFDictionarySetValue(q, kSecMatchLimit, kSecMatchLimitOne);
    CFTypeRef result = NULL;
    OSStatus s = SecItemCopyMatching(q, &result);
    CFRelease(q);
    if (!s) {
        if (!result || CFGetTypeID(result) != SecKeychainItemGetTypeID()) s = errSecParam;
        else {
            UInt32 count = 0; void *owned = NULL;
            s = SecKeychainItemCopyContent((SecKeychainItemRef)result, NULL, NULL, &count, &owned);
            if (!s && (count == 0 || count > *n)) s = errSecParam;
            if (!s) { *n = count; memcpy(p, owned, count); }
            // This API returns a caller-owned mutable allocation, unlike CFData.
            if (owned) { memset_s(owned, count, 0, count); SecKeychainItemFreeContent(NULL, owned); }
        }
    }
    if (result) CFRelease(result);
    return s;
}
static OSStatus getSecret(const char *h, void *p, size_t *n, uintptr_t kc) {
    OSStatus s = getSecretSlot(h, p, n, kc, 0);
    // Read round-1 creator-only items only if this build's own slot is absent.
    if (s == errSecItemNotFound) s = getSecretSlot(h, p, n, kc, 1);
    return s;
}
static OSStatus deleteSecretSlot(const char *h, uintptr_t kc, int legacy) {
    unsigned char probe[2560]; size_t n = sizeof(probe);
    OSStatus s = getSecretSlot(h, probe, &n, kc, legacy);
    memset_s(probe, sizeof(probe), 0, sizeof(probe));
    if (s) return s;
    CFMutableDictionaryRef q = query(h, (SecKeychainRef)kc, 0, legacy);
    if (!q) return errSecAuthFailed;
    s = SecItemDelete(q); CFRelease(q); return s;
}
static OSStatus deleteSecret(const char *h, uintptr_t kc) {
    OSStatus s = deleteSecretSlot(h, kc, 0);
    if (s == errSecItemNotFound) s = deleteSecretSlot(h, kc, 1);
    return s;
}
static OSStatus legacySlot(const char *h, uintptr_t kc, int *legacy) {
    unsigned char probe[2560]; size_t n = sizeof(probe);
    *legacy = 0;
    OSStatus s = getSecretSlot(h, probe, &n, kc, 0);
    if (s == errSecItemNotFound) { *legacy=1; n=sizeof(probe); s=getSecretSlot(h,probe,&n,kc,1); }
    memset_s(probe,sizeof(probe),0,sizeof(probe)); return s;
}
static int serviceName(char *out, size_t n) {
    CFStringRef name = custodyService(); if (!name) return 0;
    int ok = CFStringGetCString(name, out, n, kCFStringEncodingUTF8);
    CFRelease(name); return ok;
}
static OSStatus defaultKeychainPath(char *out, UInt32 *n) {
    SecKeychainSetUserInteractionAllowed(false);
    SecKeychainRef kc = NULL;
    OSStatus s = SecKeychainCopyDefault(&kc);
    if (!s) s = SecKeychainGetPath(kc,n,out);
    if (kc) CFRelease(kc); return s;
}
static OSStatus createKeychain(const char *path, const void *password, size_t n, uintptr_t *out) {
    SecKeychainSetUserInteractionAllowed(false);
    SecKeychainRef kc = NULL;
    OSStatus s = SecKeychainCreate(path, n, password, false, NULL, &kc);
    *out = (uintptr_t)kc; return s;
}
static OSStatus openKeychain(const char *path, uintptr_t *out) {
    SecKeychainSetUserInteractionAllowed(false);
    SecKeychainRef kc = NULL;
    OSStatus s = SecKeychainOpen(path, &kc); *out = (uintptr_t)kc; return s;
}
static void closeKeychain(uintptr_t kc) { if (kc) CFRelease((CFTypeRef)kc); }
*/
import "C"

import (
	"context"
	"fmt"
	"unsafe"
)

func signingPolicyAvailable() bool { return C.signingPolicyAvailable() != 0 }
func nativeService() (string, error) {
	b := make([]byte, 256)
	if C.serviceName((*C.char)(unsafe.Pointer(&b[0])), C.size_t(len(b))) == 0 {
		return "", ErrUnavailable
	}
	for i, c := range b {
		if c == 0 {
			return string(b[:i]), nil
		}
	}
	return "", ErrUnavailable
}

func status(s C.OSStatus) error {
	switch s {
	case C.errSecSuccess:
		return nil
	case C.errSecDuplicateItem:
		return ErrExists
	case C.errSecItemNotFound:
		return ErrNotFound
	default:
		return ErrUnavailable
	}
}
func (v *Vault) nativePut(_ context.Context, h string, b []byte) error {
	p := C.CString(h)
	defer C.free(unsafe.Pointer(p))
	return status(C.putSecret(p, unsafe.Pointer(&b[0]), C.size_t(len(b)), C.uintptr_t(v.keychain)))
}
func (v *Vault) nativeGet(_ context.Context, h string) ([]byte, error) { return v.nativeRead(h, false) }
func (v *Vault) nativeGetOwn(h string) ([]byte, error)                 { return v.nativeRead(h, true) }
func (v *Vault) nativeRead(h string, own bool) ([]byte, error) {
	p := C.CString(h)
	defer C.free(unsafe.Pointer(p))
	b := make([]byte, maxSecret)
	n := C.size_t(len(b))
	var result C.OSStatus
	if own {
		result = C.getSecretSlot(p, unsafe.Pointer(&b[0]), &n, C.uintptr_t(v.keychain), 0)
	} else {
		result = C.getSecret(p, unsafe.Pointer(&b[0]), &n, C.uintptr_t(v.keychain))
	}
	if err := status(result); err != nil {
		clear(b)
		return nil, err
	}
	return b[:int(n):int(n)], nil
}
func (v *Vault) nativeDelete(_ context.Context, h string) error {
	p := C.CString(h)
	defer C.free(unsafe.Pointer(p))
	err := status(C.deleteSecret(p, C.uintptr_t(v.keychain)))
	if err == ErrNotFound {
		return nil
	}
	return err
}

// These unexported helpers let native tests select a dedicated encrypted OS
// keychain without changing the user's login keychain or its search list.
func createIsolated(path string, password []byte) (*Vault, error) {
	p := C.CString(path)
	defer C.free(unsafe.Pointer(p))
	if len(password) == 0 {
		return nil, ErrInvalid
	}
	var kc C.uintptr_t
	if s := C.createKeychain(p, unsafe.Pointer(&password[0]), C.size_t(len(password)), &kc); s != C.errSecSuccess {
		return nil, fmt.Errorf("%w (OSStatus %d)", ErrUnavailable, int32(s))
	}
	return &Vault{keychain: uintptr(kc), keychainPath: path}, nil
}
func openIsolated(path string) (*Vault, error) {
	p := C.CString(path)
	defer C.free(unsafe.Pointer(p))
	var kc C.uintptr_t
	if err := status(C.openKeychain(p, &kc)); err != nil {
		return nil, err
	}
	return &Vault{keychain: uintptr(kc), keychainPath: path}, nil
}
func (v *Vault) closeIsolated() {
	C.closeKeychain(C.uintptr_t(v.keychain))
	v.keychain = 0
	v.closed = true
}

func (v *Vault) nativeDeleteSlot(h string, legacy bool) error {
	p := C.CString(h)
	defer C.free(unsafe.Pointer(p))
	var slot C.int
	if legacy {
		slot = 1
	}
	e := status(C.deleteSecretSlot(p, C.uintptr_t(v.keychain), slot))
	if e == ErrNotFound {
		return nil
	}
	return e
}
func (v *Vault) nativeLegacySlot(h string) ([]byte, error) {
	p := C.CString(h)
	defer C.free(unsafe.Pointer(p))
	var legacy C.int
	if e := status(C.legacySlot(p, C.uintptr_t(v.keychain), &legacy)); e != nil {
		return nil, e
	}
	return []byte{byte(legacy)}, nil
}

func nativeDefaultKeychain() ([]byte, error) {
	b := make([]byte, 4096)
	n := C.UInt32(len(b))
	if e := status(C.defaultKeychainPath((*C.char)(unsafe.Pointer(&b[0])), &n)); e != nil {
		return nil, e
	}
	if int(n) > len(b) {
		return nil, ErrUnavailable
	}
	b = b[:int(n)]
	for i, c := range b {
		if c == 0 {
			return b[:i], nil
		}
	}
	return b, nil
}
