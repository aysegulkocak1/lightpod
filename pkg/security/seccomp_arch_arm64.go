package security

// AUDIT_ARCH_AARCH64.
const auditArch = 0xc00000b7

// No secondary ABI here — 32-bit userspace shows up as AUDIT_ARCH_ARM and is
// rejected by the arch check.
const guardX32 = false
