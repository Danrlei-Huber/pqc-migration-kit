# Security & Operational Considerations

## Security Properties (Section 9)

### EUF-CMA (Existential Unforgeability under Chosen Message Attack)

**Definition**: Adversary cannot create message-signature pair (M, Sig) not previously signed

**Composite ML-DSA EUF-CMA Security**:
- ✅ EUF-CMA secure if **at least one** component is EUF-CMA secure AND PH collision-resistant
- If traditional component broken → remains EUF-CMA against quantum adversaries
- If ML-DSA broken → only EUF-CMA against classical adversaries
- X.509 certificates: Classic adversary cannot forge if ≥1 component EUF-CMA secure; Quantum adversary cannot forge if ML-DSA remains EUF-CMA secure

### SUF-CMA (Strong Unforgeability under Chosen Message Attack)

**Definition**: Adversary cannot create (M, Sig) that wasn't output by signing oracle

**Composite ML-DSA SUF-CMA Security**:
- ❌ NOT SUF-CMA secure against quantum adversaries
- Reason: Quantum adversary breaks traditional component's SUF-CMA
- Single component SUF-CMA failure can lead to composite SUF-CMA failure
- Even if both components SUF-CMA: two signings (M, sig1) & (M, sig2) with different signatures allows forgery of composite
- **CONSEQUENCE**: NOT RECOMMENDED for applications requiring SUF-CMA

⚠️ **Applications sensitive to SUF-CMA vs EUF-CMA difference MUST NOT use Composite ML-DSA**

### Non-Separability

**Weak Non-Separability (WNS)**: Cannot remove component signature without evidence

**Composite ML-DSA achieves WNS** because:
- Fixed Prefix "CompositeAlgorithmSignatures2025" remains in traditional signature
- ML-DSA component signed with Label context (fails verification if removed)

**Strong Non-Separability (SNS)**: Cannot extract component signature for arbitrary message

**Composite ML-DSA achieves SNS** in X.509 context:
- Algorithm label in signed object reveals attempted component extraction
- ML-DSA context binding strengthens defense

## Key Reuse Prohibition (Section 9.3)

### ✅ ALLOWED
- Fresh key generation per composite
- Each component allocated unique key material
- Composite key pair used only for composite operations

### ❌ PROHIBITED (Critical Security Risk)
- Reusing component keys in standalone algorithms
- Using same traditional key in multiple composites
- Importing pre-existing keys into composite
- Key reuse enables "stripping attacks"

### Security Impact of Key Reuse Violation
- EUF-CMA vulnerabilities introduced
- Cross-protocol attacks possible
- Certificate revocation check bypass risk
- CA may not detect revoked components if checking composite hash only

### Mitigation (Partial, NOT Full)
- Use ctx binding: ctx=Foobar-dual-cert-sig (application-specific)
- Per-application security analysis required
- NOT endorsed by specification

**Best Practice**: Always generate fresh keys for composite; never reuse components

## Prefix for Attack Mitigation (Section 9.4)

**Prefix Value**: `436F6D706F73697465416C676F726974686D5369676E61747572657332303235`  
ASCII: `CompositeAlgorithmSignatures2025`  
Length: 34 bytes

**Purpose**: 
- Prevent component signature extraction/reuse
- Extra protection via implementation guard

**Implementation Guard**:
```
// Pseudo-code
def Traditional_Verify(M, sig):
    if M starts with PREFIX:
        return error  # reject message starting with prefix
    return standard_verify(M, sig)
```

**Limitation**: Cannot verify messages legitimately starting with this byteset

## Backwards Compatibility (Section 10.3)

### What Composite ML-DSA Provides
- ✅ **Protocol-level backwards compatibility**: Fits existing X.509/PKIX extension points
- ✅ **Codebase migration flexibility**: Deploy PQC on mature traditional implementations
- ✅ **Cryptographic agility**: Leverages existing algorithm negotiation

### What Composite ML-DSA DOES NOT Provide
- ❌ **Application-level backwards compatibility**: Upgraded systems only understand OIDs
- ❌ **Legacy system interoperability**: Pre-composite systems cannot parse new algorithms
- ❌ **Transparent protocol modification**: Protocols unchanged, but algorithms must be recognized

### Migration Path
- Existing RSA/ECC ecosystem can add PQC protection incrementally
- FIPS-certified traditional component + experimental PQC component = acceptable for FIPS
- No need to replace entire cryptographic stack immediately

## FIPS Certification Guidance (Section 10.2)

### Design Goal
- Overall composite can be FIPS-approved even if one component NOT FIPS-validated

### Security Credit Model
- Credit FIPS-validated component with full security strength
- Credit non-FIPS component with **zero** security strength
- Composite = at least strength of FIPS component

### Black-Box Implementation
- Composite treats components as black-box implementations
- No imposed requirements for running in FIPS-modified modes
- However: KeyGen using ML-DSA.KeyGen_internal(seed) may not be available in some FIPS modules
- DRBG requirement: mldsaSeed = Random() MUST be FIPS-approved DRBG

### Implications
- Existing implementations of legacy algorithms can be embedded unchanged
- Pre-hashing internal to composite, no impact on component certification
- Design pattern supports future cryptographic migrations

## Deprecated Algorithm Handling (Section 9.5)

**Problem**: Single composite may contain mix of deprecated + active algorithms

**Path Forward**:
- Remove OIDs for standalone deprecated algorithms from policy
- Keep OIDs for composite algorithms using deprecated components
- Composite can remain valid after traditional component deprecated

**Implementation Complexity**:
- Cryptographic module may need to invoke deprecated algorithm
- Complex Bill-of-Materials tracking (shows deprecated algorithms still in use)
- Policy configuration more intricate

**Recommendation**: Define clear deprecation timelines; support fallback paths
