---
title: "Post-Quantum Key Encapsulation Mechanisms (PQ KEMs) for COSE"
abbrev: "PQ KEM for COSE"
category: std

docname: draft-ietf-jose-pqc-kem
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "COSE"
keyword:
 - PQC
 - COSE
 - Hybrid

venue:
  group: "cose"
  type: "Working Group"
  mail: "cose@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/cose/"

stand_alone: yes
pi: [toc, sortrefs, symrefs, strict, comments, docmapping]

author:
 -
    fullname: Tirumaleswar Reddy
    organization: Nokia
    city: Bangalore
    region: Karnataka
    country: India
    email: "kondtir@gmail.com"
 -
    fullname: Aritra Banerjee
    organization: Nokia
    city: London
    country: United Kingdom
    email: "aritra.banerjee@nokia.com"
 -
    ins: H. Tschofenig
    fullname: Hannes Tschofenig
    organization: University of the Bundeswehr Munich
    abbrev: UniBw M.
    city: Neubiberg
    region: Bavaria
    country: Germany
    code: 85577
    email: hannes.tschofenig@gmx.net

normative:
  RFC2119:
  RFC8174:
  RFC8949:
  RFC9052:
  RFC9053:
  COSE-IANA:
     author:
        org: IANA
     title: CBOR Object Signing and Encryption (COSE)
     target: https://www.iana.org/assignments/cose
  COSE-IANA-Curves:
     author:
        org: IANA
     title: COSE Elliptic Curves
     target: https://www.iana.org/assignments/cose

informative:

  PQCAPI:
     title: "PQC - API notes"
     target: https://csrc.nist.gov/CSRC/media/Projects/Post-Quantum-Cryptography/documents/example-files/api-notes.pdf
     date: false
  FO:
     title: "Secure Integration of Asymmetric and Symmetric Encryption Schemes"
     target: https://link.springer.com/article/10.1007/s00145-011-9114-1
     date: false
  HHK:
     title: "A Modular Analysis of the Fujisaki-Okamoto Transformation"
     target: https://link.springer.com/chapter/10.1007/978-3-319-70500-2_12
     date: false
  FIPS203:
     title: "FIPS-203: Module-Lattice-based Key-Encapsulation Mechanism Standard"
     target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf
     date: false
  SP-800-108r1:
     title: "Recommendation for Key Derivation Using Pseudorandom Functions"
     target: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1-upd1.pdf
     date: false
  NISTFINAL:
    title: "NIST Releases First 3 Finalized Post-Quantum Encryption Standards"
    target: https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards
  RSA:
     title: "A Method for Obtaining Digital Signatures and Public-Key Cryptosystems+"
     target: https://dl.acm.org/doi/pdf/10.1145/359340.359342
     date: false
  NIST.SP.800-56Ar3:
     author:
        org: National Institute of Standards and Technology
     title: Recommendation for Pair-Wise Key-Establishment Schemes Using Discrete Logarithm Cryptography, NIST Special Publication 800-56A Revision 3
     target: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar3.pdf
     date: April 2018

--- abstract

This document describes conventions for using Post-Quantum Key Encapsulation
Mechanisms (PQ-KEMs) with CBOR Object Signing and Encryption (COSE).

--- middle

# Introduction

Quantum computing is no longer perceived as a consequence of computational sciences and theoretical physics.  Considerable research efforts and enormous corporate and government funding for the development of practical quantum computing systems are being invested currently. As such, as quantum technology advances, there is the potential for future quantum computers to have a significant impact on current cryptographic systems.

Researchers have developed Post-Quantum Key Encapsulation Mechanisms (PQ-KEMs) to provide secure key establishment resistant against an adversary with access to a quantum computer.

The National Institute of Standards and Technology (NIST) has standardized
ML-KEM as a post-quantum key encapsulation mechanism in {{FIPS203}}. This
document specifies how ML-KEM is used to protect the confidentiality of content
encrypted with COSE against adversaries with access to quantum computers.

Although this mechanism could thus be used with any PQ-KEM, this document focuses on Module-Lattice-based Key Encapsulation Mechanisms (ML-KEMs). ML-KEM is a one-pass (store-and-forward) cryptographic mechanism for an originator to securely send keying material to a recipient
using the recipient's ML-KEM public key. Three parameters sets for ML-KEMs are specified by {{FIPS203}}. In order of increasing security strength (and decreasing performance), these parameter sets
are ML-KEM-512, ML-KEM-768, and ML-KEM-1024.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document makes use of the terms defined in {{?I-D.ietf-pquip-pqt-hybrid-terminology}}. The following terms are repeatedly used in this specification:

- KEM: Key Encapsulation Mechanism
- PQ-KEM: Post-Quantum Key Encapsulation Mechanism
- CEK: Content Encryption Key
- ML-KEM: Module-Lattice-based Key Encapsulation Mechanism

For the purposes of this document, it is helpful to be able to divide cryptographic algorithms into two classes:

"Traditional Algorithm": An asymmetric cryptographic algorithm based on integer
factorization, finite-field discrete logarithms, or elliptic-curve discrete
logarithms. In the context of COSE, examples of traditional key exchange
algorithms include Ephemeral-Static (ES) DH and Static-Static (SS) DH
{{RFC9052}}.

"Post-Quantum Algorithm":  An asymmetric cryptographic algorithm that is believed to be secure against attacks using quantum computers as well as classical computers. Post-quantum algorithms can also be called quantum-resistant or quantum-safe algorithms. Examples of Post-Quantum Algorithm include ML-KEM.

## Key Encapsulation Mechanisms {#KEMs}

For the purposes of this document, we consider a Key Encapsulation Mechanism (KEM) to be any asymmetric cryptographic scheme comprised of algorithms satisfying the following interfaces {{PQCAPI}}.

* def kemKeyGen() -> (pk, sk)
* def kemEncaps(pk) -> (ct, ss)
* def kemDecaps(ct, sk) -> ss

where pk is public key, sk is secret key, ct is the ciphertext representing an encapsulated key, and ss is shared secret.

This document uses the COSE header parameter `ek` to carry the KEM ciphertext
`ct` produced by ML-KEM encapsulation. This differs from the terminology used
in FIPS 203 and {{?RFC9936}}, where `ek` denotes the public ML-KEM
encapsulation key. In this document, the public ML-KEM encapsulation key is
represented as the public component of an AKP key, while the COSE header
parameter `ek` carries the encapsulated key, namely the KEM ciphertext `ct`.

KEMs are typically used in cases where two parties, hereby refereed to as the "encapsulater" and the "decapsulater", wish to establish a shared secret via public key cryptography, where the decapsulater has an asymmetric key pair and has previously shared the public key with the encapsulater.

# Design Rationales {#rational}

Sections 8.5.4 and 8.5.5 of COSE {{RFC9052}} define Direct Key Agreement and
Key Agreement with Key Wrap, respectively. This document specifies the use of
PQ-KEMs in these two modes. In Direct Key Agreement mode, the derived shared
secret is used as the content encryption key (CEK). In Key Agreement with Key
Wrap mode, the derived shared secret is used as a key-encryption key to wrap
the CEK.

Key Agreement with Key Wrap supports efficient encryption for multiple
recipients: the content is encrypted once with the CEK, and an individually
wrapped CEK is provided for each recipient.

It is essential to note that in the PQ-KEM, one needs to apply Fujisaki-Okamoto {{FO}} transform or its variant {{HHK}} on the PQC KEM part to ensure that the overall scheme is IND-CCA2 secure, as mentioned in {{?I-D.ietf-tls-hybrid-design}}. The FO transform is performed using the KDF such that the PQC KEM shared secret achieved is IND-CCA2 secure. As a consequence, one can re-use PQC KEM public keys but there is an upper bound that must be adhered to.

During the transition from traditional to post-quantum algorithms, protocols
may need to combine both types of algorithms. The use of hybrid post-quantum
KEMs with HPKE and COSE is outside the scope of this document.

# KEM PQC Algorithms

At time of writing, NIST have standardized three PQC algorithms, with more expected to be standardised in the future ({{NISTFINAL}}). These algorithms are not necessarily drop-in replacements for traditional asymmetric cryptographic algorithms. For instance, RSA {{RSA}} and ECC {{?RFC6090}} can be used as both a key encapsulation method (KEM) and as a signature scheme, whereas there is currently no post-quantum algorithm that can perform both functions.

## ML-KEM

ML-KEM offers several parameter sets with varying levels of security and performance trade-offs. This document specifies the use of the ML-KEM algorithm at three security levels: ML-KEM-512, ML-KEM-768, and ML-KEM-1024. ML-KEM key generation, encapsulation and decaspulation functions are defined in {{FIPS203}}. The main security property for KEMs standardized in the NIST Post-Quantum Cryptography Standardization Project is indistinguishability under adaptive chosen ciphertext attacks (IND-CCA2) (see Section 10.2 of {{?I-D.ietf-pquip-pqc-engineers}}). The public/private key sizes, ciphertext key size, and PQ security levels of ML-KEM are detailed in Section 12 of {{?I-D.ietf-pquip-pqc-engineers}}.

## PQ-KEM Encapsulation {#encrypt}

The encapsulation process is as follows:

1.  Generate an inital shared secret SS' and the associated ciphertext CT
    using the KEM encapsulation function and the recipient's public
    key recipPubKey.

~~~
          (SS', CT) = kemEncaps(recipPubKey)
~~~

2.  Derive a final shared secret SS of length SSLen bytes from
    the initial shared secret SS' using the underlying key derivation
    function:

~~~
          SS = KDF(SS', SSLen)
~~~

In Direct Key Agreement mode, the output of the KDF MUST have the key length
required by the content encryption algorithm used by the COSE_Encrypt
structure. In Key Agreement with Key Wrap mode, the output of the KDF MUST have
the key length required by the key wrap algorithm selected by the recipient
algorithm. For the algorithms defined in this specification, the KDF output
length is 128 bits for ML-KEM-512+A128KW, 192 bits for
ML-KEM-768+A192KW, and 256 bits for ML-KEM-1024+A256KW.

When Direct Key Agreement is employed, SS is the CEK. When Key Agreement with Key Wrapping is employed, SS is the key-encryption key used with AES Key Wrap to wrap the CEK; SS is not the CEK.

## PQ-KEM Decapsulation {#decrypt}

The decapsulation process is as follows:

1.  Decapsulate the ciphertext CT using the KEM decapsulation
    function and the recipient's private key to retrieve the initial shared
    secret SS':

~~~
          SS' = kemDecaps(recipPrivKey, CT)
~~~

    If the decapsulation operation outputs an error, output "decryption error", and stop.

2.  Derive the final shared secret SS of length SSLen bytes from
    the inital secret SS' using the underlying key derivation
    function:

~~~
          SS = KDF(SS', SSLen)
~~~

# KDF

## Key Derivation

The key derivation for COSE is performed using KMAC as defined in NIST
SP 800-108r1-upd1 {{SP-800-108r1}}. The KMAC(K, X, L, S) parameters are
instantiated as follows:

   *  K: the input key-derivation key. In this document this is the initial shared secret (SS') outputted from the
      kemEncaps() or kemDecaps() functions.

   *  X: The context structure defined in Section 5.2 of {{RFC9053}}, excluding
      the PartyUInfo and PartyVInfo fields. PartyUInfo is omitted because sender
      authentication is not available in PQ-KEMs. PartyVInfo is omitted because
      the recipient's identity is bound to the public key used for
      encapsulation. If mutually known private information is included, the
      sender and recipient MUST agree out of band to include it as SuppPrivInfo,
      as defined in {{NIST.SP.800-56Ar3}}.

   *  L: length of the output key in bits. In Direct Key Agreement mode, L is set to the key length required by the content encryption algorithm. In Key Agreement with Key Wrapping mode, L is set to the key length required by the key wrap algorithm; for ML-KEM-512+A128KW, ML-KEM-768+A192KW, and ML-KEM-1024+A256KW this is 128, 192, and 256 bits, respectively.

   *  S: the optional customization label. In this document this parameter is unused, that is it is the zero-length string "".

For all security levels of ML-KEM, KMAC256 is used.

# Post-Quantum KEM in COSE

This specification supports two uses of PQ-KEM in COSE, namely

*  PQ-KEM in a Direct Key Agreement mode.

*  PQ-KEM in a Key Agreement with Key Wrap mode.

In both modes, the COSE header parameter `ek`, defined in Section 7.2 of
{{?I-D.ietf-cose-hpke}}, is used to convey the ciphertext `ct` output by the
PQ-KEM encapsulation algorithm.

## Direct Key Agreement

The CEK will be generated using the process explained in {{encrypt}}.
Subsequently, the plaintext will be encrypted using the CEK. The resulting
ciphertext is either included in the COSE_Encrypt or is detached. If a payload is
transported separately then it is called "detached content". A nil CBOR
object is placed in the location of the ciphertext. See Section 5
of {{RFC9052}} for a description of detached payloads.

The COSE_Recipient structure for the recipient is organized as follows:

   * The sender MUST set the 'alg' parameter to indicate the use of the PQ-KEM algorithm.
   * This document RECOMMENDS the use of the 'kid' parameter
     (or other parameters) to explicitly identify the recipient public key
     used by the sender. If the COSE_Encrypt contains the 'kid' then the recipient may
     use it to select the appropriate private key.

## Key Agreement with Key Wrap

With the two layer structure the PQ-KEM information is conveyed in the COSE_recipient
structure, i.e. one COSE_recipient structure per recipient.

In this approach the following layers are involved:

- Layer 0 (corresponding to the COSE_Encrypt structure) contains the content (plaintext)
encrypted with the CEK. This ciphertext may be detached, and if not detached, then
it is included in the COSE_Encrypt structure.

- Layer 1 (corresponding to a recipient structure) contains parameters needed for
PQ-KEM to generate a shared secret used to encrypt the CEK. This layer conveys
the encrypted CEK in the "ciphertext" field (Section 5.1 of {{RFC9052}}).
The unprotected header MAY contain the kid parameter to identify the static recipient
public key the sender has been using with PQ-KEM.

This two-layer structure is used to encrypt content that can also be shared with
multiple parties at the expense of a single additional encryption operation.
As stated above, the specification uses a CEK to encrypt the content at layer 0.

# COSE Ciphersuite Registration {#COSE-PQ-KEM}

All security levels of ML-KEM internally use SHA3-256, SHA3-512, SHAKE128,
and SHAKE256. This internal usage influences the selection of the KDF described
in this document.

ML-KEM-512 MUST be used with a KDF capable of producing a key with at least
128 bits of security and, in Key Agreement with Key Wrap mode, with a key wrap
algorithm having a key length of at least 128 bits.

ML-KEM-768 MUST be used with a KDF capable of producing a key with at least
192 bits of security and, in Key Agreement with Key Wrap mode, with a key wrap
algorithm having a key length of at least 192 bits.

ML-KEM-1024 MUST be used with a KDF capable of producing a key with at least
256 bits of security and, in Key Agreement with Key Wrap mode, with a key wrap
algorithm having a key length of at least 256 bits.

{{ciphersuite-table}} lists the COSE algorithm values for the PQ-KEM
ciphersuites defined by this document.

~~~
+===============================+=========+===================================+=============+
| Name                          | COSE ID | Description                       | Recommended |
+===============================+=========+===================================+=============+
| ML-KEM-512                    | TBD1    | ML-KEM-512                        | No          |
+-------------------------------+---------+-----------------------------------+-------------+
| ML-KEM-768                    | TBD2    | ML-KEM-768                        | No          |
+-------------------------------+---------+-----------------------------------+-------------+
| ML-KEM-1024                   | TBD3    | ML-KEM-1024                       | No          |
+-------------------------------+---------+-----------------------------------+-------------+
| ML-KEM-512+A128KW             | TBD4    | ML-KEM-512 + AES128KW             | No          |
+-------------------------------+---------+-----------------------------------+-------------+
| ML-KEM-768+A192KW             | TBD5    | ML-KEM-768 + AES192KW             | No          |
+-------------------------------+---------+-----------------------------------+-------------+
| ML-KEM-1024+A256KW            | TBD6    | ML-KEM-1024 + AES256KW            | No          |
+-------------------------------+---------+-----------------------------------+-------------+
~~~
{: #ciphersuite-table title="COSE PQ-KEM Ciphersuites."}

# Use of AKP Key Type for PQC KEM Keys in COSE

The "AKP" (Algorithm Key Pair) key type, defined in
{{?I-D.ietf-cose-dilithium}}, is used to represent PQC KEM keys in COSE. A
COSE_Key with "kty" set to "AKP" represents a PQC KEM key pair. The public key
is carried in the "pub" parameter. If included, the private key is carried in
the "priv" parameter. Both parameters are byte strings containing the raw
algorithm-specific key material.

The "AKP" key type mandates the use of the "alg" parameter. While this requirement is suitable for PQ digital signature algorithms, applying the same model to PQ KEMs would require distinguishing between keys used
for Direct Key Agreement and those used for Key Agreement with Key Wrap.

Note: This differs from the "OKP" usage model and requires further discussion within the WG.

For ML-KEM algorithms, as specified in {{FIPS203}}, there are two possible
representations of a private key: a seed and a fully expanded private key
derived from the seed. This document specifies only the seed form. The "priv"
parameter MUST contain the 64-octet ML-KEM seed `d || z`, where `d` is the
first 32 octets and `z` is the last 32 octets. The ML-KEM public key and
expanded private key are derived from this seed using
`ML-KEM.KeyGen_internal(d, z)`, as specified in {{FIPS203}}. This document does
not define a 32-octet private seed representation and does not support carrying
the expanded private key in "priv". This avoids implicit,
implementation-specific key expansion.

# Security Considerations

PQC KEMs used in the manner described in this document MUST explicitly be designed to be secure in the event that the public key is reused, such as achieving IND-CCA2 security. ML-KEM has such security properties.

ML-KEM key generation and encapsulation both rely on high-quality random input.
For key generation, the 64-octet seed `d || z` contains 32 octets used to
deterministically derive the key pair and 32 octets used as a rejection value.
For encapsulation, ML-KEM uses fresh random input to produce the ciphertext and
shared secret. Implementations MUST use a cryptographically secure random number
generator for these values. Weak or repeated random input can make it
substantially easier for an attacker to reproduce keys or ciphertexts and can
undermine the security properties expected from ML-KEM.

ML-KEM encapsulation and decapsulation output only the shared secret and
ciphertext values described by this specification. Implementations MUST NOT use
intermediate ML-KEM values directly as COSE keying material, KDF input,
authentication input, or application data. Implementations SHOULD avoid exposing
intermediate values through APIs, logs, errors, or side channels.

# IANA Considerations {#IANA}

## COSE Algorithms Registrations

IANA is requested to add the following entries to the "COSE Algorithms"
registry {{COSE-IANA}}:

- Name: ML-KEM-512
- Value: TBD1
- Description: PQ-KEM that uses ML-KEM-512 PQ-KEM.
- Capabilities: [kty]
- Change Controller: IESG
- Reference: This document (TBD)
- Recommended: No

- Name: ML-KEM-768
- Value: TBD2
- Description: PQ-KEM that uses ML-KEM-768 PQ-KEM.
- Capabilities: [kty]
- Change Controller: IESG
- Reference: This document (TBD)
- Recommended: No

- Name: ML-KEM-1024
- Value: TBD3
- Description: PQ-KEM that uses ML-KEM-1024 PQ-KEM.
- Capabilities: [kty]
- Change Controller: IESG
- Reference: This document (TBD)
- Recommended: No

- Name: ML-KEM-512+A128KW
- Value: TBD4
- Description: PQ-KEM that uses ML-KEM-512 PQ-KEM and CEK wrapped with "A128KW".
- Capabilities: [kty]
- Change Controller: IESG
- Reference: This document (TBD)
- Recommended: No

- Name: ML-KEM-768+A192KW
- Value: TBD5
- Description: PQ-KEM that uses ML-KEM-768 and CEK wrapped with "A192KW".
- Capabilities: [kty]
- Change Controller: IESG
- Reference: This document (TBD)
- Recommended: No

- Name: ML-KEM-1024+A256KW
- Value: TBD6
- Description: PQ-KEM that uses ML-KEM-1024 and CEK wrapped with "A256KW".
- Capabilities: [kty]
- Change Controller: IESG
- Reference: This document (TBD)
- Recommended: No

## COSE Elliptic Curves Registrations

IANA is requested to register the following values in the "COSE Elliptic Curves" registry {{COSE-IANA-Curves}}.

### ML-KEM-512

| Name             | ML-KEM-512                                                              |
|------------------|-------------------------------------------------------------------------|
| Value            | TBD1                                                                    |
| Key Type         | AKP                                                                     |
| Description      | NIST Post-Quantum ML-KEM-512 |
| Change Controller| IETF                                                                    |
| Reference        | This document                                                           |
| Recommended      | No

### ML-KEM-768

| Name             | ML-KEM-768                                                              |
|------------------|-------------------------------------------------------------------------|
| Value            | TBD2                                                                    |
| Key Type         | AKP                                                                     |
| Description      | NIST Post-Quantum ML-KEM-768 |
| Change Controller| IETF                                                                    |
| Reference        | This document                                                           |
| Recommended      | No                                                                      |

### ML-KEM-1024

| Name             | ML-KEM-1024                                                             |
|------------------|-------------------------------------------------------------------------|
| Value            | TBD3                                                                   |
| Key Type         | AKP                                                                     |
| Description      | NIST Post-Quantum ML-KEM-1024 |
| Change Controller| IETF                                                                    |
| Reference        | This document                                                           |
| Recommended      | No                                                                      |

# Acknowledgments
{: numbered="false"}

The authors thank AJITOMI Daisuke, Brian Campbell, Daniel Huigens, Filip Skokan, Ilari Liusvaara, Neil Madden,
and Stepan Yakimovich for their contributions to this specification.
