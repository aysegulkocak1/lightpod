package security

// AUDIT_ARCH_X86_64. Anything arriving with a different arch is killed.
const auditArch = 0xc000003e

// x32 hides under the same arch value, so it needs a separate check.
const guardX32 = true
