---
title: "Post-Quantum Key Encapsulation Mechanisms (PQ KEMs) for JOSE and COSE"
abbrev: "PQ KEM for JOSE and COSE"
category: std

docname: draft-ietf-jose-pqc-kem
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "JOSE"
keyword:
 - PQC
 - COSE
 - JOSE
 - Hybrid

venue:
  group: "jose" 
  type: "Working Group"
  mail: "jose@ietf.org" 
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
    fullname: Hannes Tschofenig
    organization: University of Applied Sciences Bonn-Rhein-Sieg
    abbrev: H-BRS
    country: Germany
    email: "hannes.tschofenig@gmx.net"
 
normative:
  RFC2119:
  RFC8174:
  RFC7516:
  RFC8949:
  JOSE-IANA:
     author:
        org: IANA
     title: JSON Web Signature and Encryption Algorithms
     target: https://www.iana.org/assignments/jose/jose.xhtml
  JOSE-IANA-Curves:
     author:
        org: IANA
     title: JSON Web Key Elliptic Curve
     target: https://www.iana.org/assignments/jose/jose.xhtml
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

This document describes the conventions for using Post-Quantum Key Encapsulation Mechanisms (PQ-KEMs) within JOSE and COSE. 

--- middle

# Introduction

Quantum computing is no longer perceived as a consequence of computational sciences and theoretical physics.  Considerable research efforts and enormous corporate and government funding for the development of practical quantum computing systems are being invested currently. As such, as quantum technology advances, there is the potential for future quantum computers to have a significant impact on current cryptographic systems. 

Researchers have developed Post-Quantum Key Encapsulation Mechanisms (PQ-KEMs) to provide secure key establishment resistant against an adversary with access to a quantum computer.

As the National Institute of Standards and Technology (NIST) is still in the process of selecting the new post-quantum cryptographic algorithms that are secure against both quantum and classical computers, the purpose of this document is to propose a PQ-KEMs to protect the confidentiality of content encrypted using JOSE and COSE against the quantum threat.

Although this mechanism could thus be used with any PQ-KEM, this document focuses on Module-Lattice-based Key Encapsulation Mechanisms (ML-KEMs). ML-KEM is a one-pass (store-and-forward) cryptographic mechanism for an originator to securely send keying material to a recipient
using the recipient's ML-KEM public key. Three parameters sets for ML-KEMs are specified by {{FIPS203}}. In order of increasing security strength (and decreasing performance), these parameter sets
are ML-KEM-512, ML-KEM-768, and ML-KEM-1024.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document makes use of the terms defined in {{?I-D.ietf-pquip-pqt-hybrid-terminology}}. The following terms are repeately used in this specification:

- KEM: Key Encapsulation Mechanism
- PQ-KEM: Post-Quantum Key Encapsulation Mechanism
- CEK: Content Encryption Key
- ML-KEM: Module-Lattice-based Key Encapsulation Mechanism

For the purposes of this document, it is helpful to be able to divide cryptographic algorithms into two classes:

"Traditional Algorithm":  An asymmetric cryptographic algorithm based on integer factorisation, finite field discrete logarithms or elliptic curve discrete logarithms. In the context of JOSE, examples of traditional key exchange algorithms include Elliptic Curve Diffie-Hellman Ephemeral Static {{?RFC6090}} {{?RFC8037}}. In the context of COSE, examples of traditional key exchange algorithms include Ephemeral-Static (ES) DH and Static-Static (SS) DH {{?RFC9052}}. 

"Post-Quantum Algorithm":  An asymmetric cryptographic algorithm that is believed to be secure against attacks using quantum computers as well as classical computers. Post-quantum algorithms can also be called quantum-resistant or quantum-safe algorithms. Examples of Post-Quantum Algorithm include ML-KEM.

## Key Encapsulation Mechanisms {#KEMs}

For the purposes of this document, we consider a Key Encapsulation Mechanism (KEM) to be any asymmetric cryptographic scheme comprised of algorithms satisfying the following interfaces {{PQCAPI}}.  

* def kemKeyGen() -> (pk, sk)
* def kemEncaps(pk) -> (ct, ss)
* def kemDecaps(ct, sk) -> ss

where pk is public key, sk is secret key, ct is the ciphertext representing an encapsulated key, and ss is shared secret.

This document uses the JOSE header parameter "kemct" to carry the KEM
ciphertext `ct` produced by ML-KEM encapsulation. This name is aligned with the
`kemct` field in the CMS KEMRecipientInfo structure. The name "ek" is not used
for this JOSE value because FIPS 203 and {{?RFC9936}} use "ek" to denote the
public ML-KEM encapsulation key. For COSE, this document continues to use the
COSE HPKE header parameter "ek" to carry the KEM ciphertext.

KEMs are typically used in cases where two parties, hereby refereed to as the "encapsulater" and the "decapsulater", wish to establish a shared secret via public key cryptography, where the decapsulater has an asymmetric key pair and has previously shared the public key with the encapsulater.
  
# Design Rationales {#rational}

Section 4.6 of the JSON Web Algorithms (JWA) specification, see {{?RFC7518}}, defines two ways of using a key agreement:

- When Direct Key Agreement is employed, the shared secret established through the Traditional Algorithm will be the content encryption key (CEK).
- When Key Agreement with Key Wrapping is employed, the shared secret established through the Traditional Algorithm will wrap the CEK.

For efficient use with multiple recipients, the key wrap approach is used since the content can be encrypted once with the CEK, while each recipient receives an individually encrypted CEK. Similarly, Section 8.5.4 and Section 8.5.5 of COSE {{?RFC9052}} define the Direct Key Agreement and Key Agreement with Key Wrap, respectively. This document proposes the use of PQ-KEMs for these two modes.

It is essential to note that in the PQ-KEM, one needs to apply Fujisaki-Okamoto {{FO}} transform or its variant {{HHK}} on the PQC KEM part to ensure that the overall scheme is IND-CCA2 secure, as mentioned in {{?I-D.ietf-tls-hybrid-design}}. The FO transform is performed using the KDF such that the PQC KEM shared secret achieved is IND-CCA2 secure. As a consequence, one can re-use PQC KEM public keys but there is an upper bound that must be adhered to.

Note that during the transition from traditional to post-quantum algorithms, there may be a desire or a requirement for protocols that incorporate both types of algorithms until the post-quantum algorithms are fully 
trusted. HPKE {{?RFC9180}} is a KEM that can be extended to support hybrid post-quantum KEMs and the specification for the use of PQ/T Hybrid Key Encapsulation Mechanism (KEM) in Hybrid Public-Key Encryption (HPKE) for integration with JOSE and COSE is described in {{?I-D.reddy-cose-jose-pqc-hybrid-hpke}}.

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

In Direct Key Agreement mode, the output of the KDF MUST be a key of the same length as that used by encryption algorithm. In Key Agreement with Key Wrapping mode, the output of the KDF MUST be a key of the length needed for the specified key wrap algorithm. 

When Direct Key Agreement is employed, SS is the CEK. When Key Agreement with Key Wrapping is employed, SS is used to wrap the CEK.

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

## Key Derivation for JOSE

The key derivation for JOSE is performed using the KMAC defined in NIST SP 800-108r1-upd1 {{SP-800-108r1}}. The KMAC(K, X, L, S) parameters are instantiated as follows:

   *  K: the input key-derivation key. In this document this is the initial shared secret (SS') outputted from the 
      kemEncaps() or kemDecaps() functions.

   *  X: The context-specific data used for key derivation includes the concatenation of AlgorithmID, SuppPubInfo, and SuppPrivInfo, as defined in {{NIST.SP.800-56Ar3}}. The fields AlgorithmID and SuppPubInfo 
   are defined in Section 4.6.2 of {{RFC7518}} The fields PartyUInfo and PartyVInfo, also defined in that section, are intentionally excluded. PartyUInfo is omitted because post-quantum KEMs do not support sender authentication. PartyVInfo is excluded because the recipient’s identity is already bound to the public key used for encapsulation, making its inclusion unnecessary. If mutually known private information is required, both parties MUST agree out-of-band to include it as SuppPrivInfo.

   *  L: length of the output key in bits and it would be set to match the length of the key required for the AEAD operation.

   *  S: the optional customization label. In this document this parameter is unused, that is it is the zero-length string "".

For all security levels of ML-KEM, KMAC256 is used.

## Key Derivation for COSE

The key derivation for COSE is performed using the KMAC defined in NIST SP 800-108r1-upd1 [SP-800-108r1]. The KMAC(K, X, L, S) parameters are instantiated as follows:

   *  K: the input key-derivation key. In this document this is the initial shared secret (SS') outputted from the 
      kemEncaps() or kemDecaps() functions.

   *  X: The context structure defined in Section 5.2 of {{?RFC9053}} excluding PartyUInfo and PartyVInfo fields. PartyUInfo is omitted because sender authentication is not available in PQ KEMs. PartyVInfo is excluded because the recipient's identity is already bound to the public key used for encapsulation, making its inclusion redundant. If mutually known private information is to be included, both the sender and the recipient MUST agree out-of-band to include it as SuppPrivInfo in the key derivation function, as defined in {{NIST.SP.800-56Ar3}}. 
   
   *  L: length of the output key in bits and it would be set to match the length of the key required for the AEAD operation.

   *  S: the optional customization label. In this document this parameter is unused, that is it is the zero-length string "".

For all security levels of ML-KEM, KMAC256 is used.

# Post-quantum KEM in JOSE

As explained in {{rational}} JWA defines two ways to use public key cryptography with JWE:

* Direct Key Agreement
* Key Agreement with Key Wrapping

This specification describes these two modes of use for PQ-KEM in JWE. Unless otherwise stated, no changes to the procedures described in {{RFC7516}} have been made.

## Direct Key Agreement 

*  The "alg" header parameter MUST be a PQ-KEM algorithm chosen from the JSON Web Signature and Encryption Algorithms registry defined in {{JOSE-IANA}}. 

*  The CEK will be generated using the process explained in {{encrypt}}. The output of the {{encrypt}} MUST be a secret key of the same length as that used by the "enc" algorithm. 

* The usage for the "alg" and "enc" header parameters remain the same as in JWE {{RFC7516}}. Subsequently, the plaintext will be encrypted using the CEK, as detailed in Step 15 of Section 5.1 of {{RFC7516}}. 

* The header parameter "kemct" MUST include the output ('ct') from the PQ-KEM algorithm, encoded using base64url.

* The recipient MUST base64url decode the ciphertext from the "kemct" header parameter and then use it to derive the CEK using the process defined in {{decrypt}}. 

*  The JWE Encrypted Key MUST be absent.

Note that when using Direct Key Agreement in JOSE Compact Serialization, inefficiency arises due to double encoding of the KEM ciphertext. In this mode, the "kemct" parameter inside the protected header carries the KEM ciphertext, already base64url-encoded. Then, the entire protected header is base64url-encoded again as part of the compact serialization. 

## Key Agreement with Key Wrapping

* The derived key is generated using the process explained in {{encrypt}} and used to encrypt the CEK. 

* The parameter "kemct" MUST include the output ('ct') from the PQ-KEM algorithm, encoded using base64url.

* The JWE Encrypted Key MUST include the base64url-encoded encrypted CEK. 

* The 'enc' (Encryption Algorithm) header parameter MUST specify a content encryption algorithm from the JSON Web Signature and Encryption Algorithms registry, as defined in {{JOSE-IANA}}.

* The recipient MUST base64url decode the ciphertext from "kemct". Subsequently, it is used to derive the key, through the process defined in {{decrypt}}. The derived key will then be used to decrypt the CEK.

# Post-Quantum KEM in COSE

This specification supports two uses of PQ-KEM in COSE, namely

*  PQ-KEM in a Direct Key Agreement mode. 

*  PQ-KEM in a Key Agreement with Key Wrap mode.  

In both modes, the COSE header parameter 'ek' defined in Section 7.2 of {{?I-D.ietf-cose-hpke}}, 
is used to convey the output ('ct') from the PQ KEM Encaps algorithm.

## Direct Key Agreement

The CEK will be generated using the process explained in {{encrypt}}. 
Subsequently, the plaintext will be encrypted using the CEK. The resulting 
ciphertext is either included in the COSE_Encrypt or is detached. If a payload is
transported separately then it is called "detached content". A nil CBOR
object is placed in the location of the ciphertext. See Section 5
of {{?RFC9052}} for a description of detached payloads.

The COSE_Recipient structure for the recipient is organized as follows:

   * The sender MUST set the 'alg' parameter to indicate the use of the PQ-KEM algorithm.
   * This documents RECOMMENDS the use of the 'kid' parameter
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
the encrypted CEK in the "ciphertext" field (Section 5.1 of {{?RFC9052}}). 
The unprotected header MAY contain the kid parameter to identify the static recipient 
public key the sender has been using with PQ-KEM.

This two-layer structure is used to encrypt content that can also be shared with
multiple parties at the expense of a single additional encryption operation.
As stated above, the specification uses a CEK to encrypt the content at layer 0.

# JOSE Ciphersuite Registration {#JOSE-PQ-KEM}

This specification registers a number of PQ-KEM algorithms for use with JOSE. 

All security levels of ML-KEM internally utilize SHA3-256, SHA3-512, SHAKE128, and SHAKE256. This internal usage influences the selection of the KDF as described in this document.

ML-KEM-512 MUST be used with a KDF capable of outputting a key with at least 128 bits of security and with a key wrapping algorithm with a key length of at least 128 bits.

ML-KEM-768 MUST be used with a KDF capable of outputting a key with at least 192 bits of security and with a key wrapping algorithm with a key length of at least 192 bits.

ML-KEM-1024 MUST be used with a KDF capable of outputting a key with at least 256 bits of security and with a key wrapping algorithm with a key length of at least 256 bits.

* In Direct key agreement, the parameter "alg" MUST be specified, and its value MUST be one of the values specified in {{direct-table}}. (Note that future specifications MAY extend the list of algorithms.)

~~~
 +===============================+===================================+
 | alg                           | Description                       |
 +===============================+===================================+
 | ML-KEM-512                    | ML-KEM-512                        |
 +===============================+===================================+
 | ML-KEM-768                    | ML-KEM-768                        |
 +===============================+===================================+
 | ML-KEM-1024                   | ML-KEM-1024                       |
 +===============================+===================================+
~~~
{: #direct-table title="Direct Key Agreement: Algorithms."}

* In Key Agreement with Key Wrapping, the parameter "alg" MUST be specified, and its value MUST be one of the values specified in the table {{keywrap-table}}.

~~~
 +=================================+===================================+
 | alg                             | Description                       |
 +=================================+===================================+
 | ML-KEM-512+A128KW               | ML-KEM-512 + AES128KW             |
 +=================================+===================================+
 | ML-KEM-768+A192KW               | ML-KEM-768 + AES192KW             |
 +=================================+===================================+
 | ML-KEM-1024+A256KW              | ML-KEM-1024 + AES256KW            |
 +=================================+===================================+
~~~
{: #keywrap-table title="Key Agreement with Key Wrapping: Algorithms."}

# COSE Ciphersuite Registration {#COSE-PQ-KEM}

{{mapping-table}} maps the JOSE algorithm names to the COSE algorithm values (for the PQ-KEM ciphersuites defined by this document).

~~~
+===============================+=========+===================================+=============+
| JOSE                          | COSE ID | Description                       | Recommended |
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
{: #mapping-table title="Mapping between JOSE and COSE PQ-KEM Ciphersuites."}

# Use of AKP Key Type for PQC KEM Keys in JOSE and COSE

The "AKP" (Algorithm Key Pair) key type, defined in {{?I-D.ietf-cose-dilithium}} is used in this specification to
represent PQC KEM keys for JOSE and COSE. When used with JOSE or COSE algorithms that rely on PQC KEMs, a key with "kty" set to "AKP" represents an PQC KEM key pair. The public key is carried in the "pub" parameter. If included, the private key is carried in the "priv" parameter. When expressed as a JWK, the "pub" and "priv" values are base64url-encoded.

The "AKP" key type mandates the use of the "alg" parameter. While this requirement is suitable for PQ digital signature algorithms, applying the same model to PQ KEMs would require distinguishing between keys used
for Direct Key Agreement and those used for Key Agreement with Key Wrap.

Note: This differs from the "OKP" usage model and requires further discussion within the WG.

For ML-KEM algorithms, as specified in {{FIPS203}}, there are two possible representations of a private key: a seed and a fully expanded private key derived from the seed. This document specifies the use of only the seed form for private keys. To promote interoperability, the "priv" parameter MUST contain the 64-octet ML-KEM seed `d || z`, where `d` is the first 32 octets and `z` is the last 32 octets. The ML-KEM public key and expanded private key are derived from this seed using `ML-KEM.KeyGen_internal(d, z)`, as specified in {{FIPS203}}. This document does not define a 32-octet private seed representation and does not support carrying the expanded private key representation in "priv". This approach follows the JOSE convention that a private-key parameter contains the algorithm-specific private-key material directly and avoids implicit, implementation-specific key expansion.

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
intermediate ML-KEM values directly as JOSE or COSE keying material, KDF input,
authentication input, or application data. Implementations SHOULD avoid exposing
intermediate values through APIs, logs, errors, or side channels.

# IANA Considerations {#IANA}

## JOSE

The following entry is added to the "JSON Web Signature and Encryption Header Parameters" registry:

- Header Parameter Name: kemct
- Header Parameter Description: KEM ciphertext
- Header Parameter Usage Location(s): JWE
- Change Controller: IESG
- Specification Document(s): [[TBD: This RFC]]

The following entries are added to the "JSON Web Signature and Encryption Algorithms" registry:

- Algorithm Name: ML-KEM-512
- Algorithm Description: PQ-KEM that uses ML-KEM-512 PQ-KEM.
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): [[TBD: This RFC]]
- Algorithm Analysis Documents(s): TODO

- Algorithm Name: ML-KEM-768
- Algorithm Description: PQ-KEM that uses ML-KEM-768 PQ-KEM.
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): [[TBD: This RFC]]
- Algorithm Analysis Documents(s): TODO

- Algorithm Name: ML-KEM-1024
- Algorithm Description: PQ-KEM that uses ML-KEM-1024 PQ-KEM.
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): [[TBD: This RFC]]
- Algorithm Analysis Documents(s): TODO

- Algorithm Name: ML-KEM-512+A128KW
- Algorithm Description: PQ-KEM that uses ML-KEM-512 PQ-KEM and CEK wrapped with "A128KW".
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): [[TBD: This RFC]]
- Algorithm Analysis Documents(s): TODO

- Algorithm Name: ML-KEM-768+A192KW
- Algorithm Description: PQ-KEM that uses ML-KEM-768 and CEK wrapped with "A192KW".
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): [[TBD: This RFC]]
- Algorithm Analysis Documents(s): TODO

- Algorithm Name: ML-KEM-1024+A256KW
- Algorithm Description: PQ-KEM that uses ML-KEM-1024 and CEK wrapped with "A256KW".
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): [[TBD: This RFC]]
- Algorithm Analysis Documents(s): TODO

## JSON Web Key Elliptic Curves Registrations

IANA is requested to register the following values in the "JSON Web Key Elliptic Curve" registry {{JOSE-IANA-Curves}}.

### ML-KEM-512

| Curve Name              | ML-KEM-512                                                              |
|-------------------------|-------------------------------------------------------------------------|
| Curve Description       | NIST Post-Quantum ML-KEM-512 algorithm |
| JOSE Implementation Requirements | Optional                                                      |
| Change Controller       | IESG                                                                   |
| Specification Document(s) | This document   

### ML-KEM-768

| Curve Name              | ML-KEM-768                                                              |
|-------------------------|-------------------------------------------------------------------------|
| Curve Description       | NIST Post-Quantum ML-KEM-768 algorithm |
| JOSE Implementation Requirements | Optional                                                      |
| Change Controller       | IESG                                                                   |
| Specification Document(s) | This document                                                       |

### ML-KEM-1024

| Curve Name              | ML-KEM-1024                                                             |
|-------------------------|-------------------------------------------------------------------------|
| Curve Description       | NIST Post-Quantum ML-KEM-1024 algorithm |
| JOSE Implementation Requirements | Optional                                                      |
| Change Controller       | IESG                                                                   |
| Specification Document(s) | This document                                                       |


## COSE

The following has to be added to the "COSE Algorithms" registry:

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

- Name: ML-KEM-768
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

- Name: ML-KEM-768+192KW
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
| Value            | TBD2                                                                    |
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

# Test Vectors
{: numbered="false"}

The following test vectors are non-normative. They are generated with the
experimental JOSE implementation used during development of this draft.

The vectors use the following common inputs:

* Plaintext: "pqc kem test payload"
* AAD: "external-aad"
* KEM encapsulation seed (hex):

~~~
a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf
~~~

* JWE initialization vector (hex):

~~~
b0b1b2b3b4b5b6b7b8b9babb
~~~

For the key-wrap examples, the CEK is the leftmost bytes of:

~~~
c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf
~~~

The AKP private key parameter `priv` is the 64-octet ML-KEM seed `d || z`.
The first 32 octets are `d`; the last 32 octets are `z`. The public key and
expanded private key are derived from this seed using `ML-KEM.KeyGen_internal(d,
z)`, as specified in FIPS 203.

=============== NOTE: '\' line wrapping per RFC 8792 ================

## ML-KEM-512
{: numbered="false"}

Public JWK:

~~~ json
{
  "kty": "AKP",
  "alg": "ML-KEM-512",
  "pub": "t_mc34cEvCrOhiUbRjmmghJdonimWRiF1pdjsSGfiqWLFlR7FzF8hXYEG9HJ-FNHeyS3F4tJ1MsXO2qOOJxNbcGJghOhhHyXY3Fw09UPLHMc4FoeddoD3Lki3LmRb2cjuAKBpSQNQeLH7ObE0_eSDxFCeTxsKjYny0e6JtBj2LhAVIyKLjhFYsu9B4MuuimhbTHCysx4l0YegqI98wjB7ddEMDJJgSsnjuoT80MiZvA3iGCd5uMjEJDBdazPwGObqlGP70DNC8sKjLKYN4g9BwO1fTBZY9wfS-lwQghko3ExavKwxiUnO3nPoiVwtSq1VWEFVbyh2WBHdTWehDaeHUxHzjAaDcWgjnqdQRaen6BIZnVr-Bh3qNVDvTk2LnxsC2IqIfsu8CIgrYSY3nKN84k9aTSd1RE64OuCKYNVwrsnQsRWvkpspvMYfexp9LOkMNVAK5VwC2seZKNy7OyklIFpyUwXZPqItjbD6vYLotyQv9wg1lyoDehrl1F0_kyKYfOMbpFPdbgc6tI_nWg130QxgEsSdECTQCyWpbN7eXuQ5Xddg5CRvAeUzxXJzWF1qnPLhwAh3igm-lCY95nEdTKUBiBfsHyyS4Js1GlcwzyDA4FZsAUYldmpStK5UZGUWEZFSQW0I9UG3hsvkgp4mscgF7iYgJMtC_sX0oEampUJ6wkb0eaIo3yZkjdhRptOKGG-ZmCibvYzlPoefnZuHqBS8wSps3aDLPm77zi_eDLO6NoKe4K_fYobvss-mkQVI0nOsGsH4UhUCNInTHIaJttlIzPAYDa02tE4nZi9m7R29IUzKtghgdCN1AeD5OJRxJVFQ-el1DwJ-RsqcNu8NtCx1hmgdrYVlFUB_DXERMgQCAu7AkMFYAU79iAlPym8lCM0fqiK2NqBM1fHl3dWyjPBysNnSffGo8iJsNctZgdAhZN3BwgSkaOB2Ea0kaMVAyUg8QqKEWS8FCU-NJIQ0SUXixidd5Nvp0iIFitPWUFK2lh4_8kIh6EfJoZddCKBN3UB3V5heTKuz3edcP77m-acNqUvKjVebxKz9oSQpKA"
}
~~~

Private JWK:

~~~ json
{
  "kty": "AKP",
  "alg": "ML-KEM-512",
  "pub": "t_mc34cEvCrOhiUbRjmmghJdonimWRiF1pdjsSGfiqWLFlR7FzF8hXYEG9HJ-FNHeyS3F4tJ1MsXO2qOOJxNbcGJghOhhHyXY3Fw09UPLHMc4FoeddoD3Lki3LmRb2cjuAKBpSQNQeLH7ObE0_eSDxFCeTxsKjYny0e6JtBj2LhAVIyKLjhFYsu9B4MuuimhbTHCysx4l0YegqI98wjB7ddEMDJJgSsnjuoT80MiZvA3iGCd5uMjEJDBdazPwGObqlGP70DNC8sKjLKYN4g9BwO1fTBZY9wfS-lwQghko3ExavKwxiUnO3nPoiVwtSq1VWEFVbyh2WBHdTWehDaeHUxHzjAaDcWgjnqdQRaen6BIZnVr-Bh3qNVDvTk2LnxsC2IqIfsu8CIgrYSY3nKN84k9aTSd1RE64OuCKYNVwrsnQsRWvkpspvMYfexp9LOkMNVAK5VwC2seZKNy7OyklIFpyUwXZPqItjbD6vYLotyQv9wg1lyoDehrl1F0_kyKYfOMbpFPdbgc6tI_nWg130QxgEsSdECTQCyWpbN7eXuQ5Xddg5CRvAeUzxXJzWF1qnPLhwAh3igm-lCY95nEdTKUBiBfsHyyS4Js1GlcwzyDA4FZsAUYldmpStK5UZGUWEZFSQW0I9UG3hsvkgp4mscgF7iYgJMtC_sX0oEampUJ6wkb0eaIo3yZkjdhRptOKGG-ZmCibvYzlPoefnZuHqBS8wSps3aDLPm77zi_eDLO6NoKe4K_fYobvss-mkQVI0nOsGsH4UhUCNInTHIaJttlIzPAYDa02tE4nZi9m7R29IUzKtghgdCN1AeD5OJRxJVFQ-el1DwJ-RsqcNu8NtCx1hmgdrYVlFUB_DXERMgQCAu7AkMFYAU79iAlPym8lCM0fqiK2NqBM1fHl3dWyjPBysNnSffGo8iJsNctZgdAhZN3BwgSkaOB2Ea0kaMVAyUg8QqKEWS8FCU-NJIQ0SUXixidd5Nvp0iIFitPWUFK2lh4_8kIh6EfJoZddCKBN3UB3V5heTKuz3edcP77m-acNqUvKjVebxKz9oSQpKA",
  "priv": "EBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4_QEFCQ0RFRkdISUpLTE1OTw"
}
~~~

Flattened JWE JSON Serialization:

~~~ json
{
  "protected": "eyJhbGciOiJNTC1LRU0tNTEyIiwiZW5jIjoiQTEyOEdDTSIsImtlbWN0IjoiRUcycm5f\\\nRW11M05YVGNsaDZOR3hNYVFDcGVZeERtM1ZXMEJxOGJ3elBXM0hQM1hjbmdHZVFZaFl3\\\nbXNfSEJXUFpzNk1DZW12ZF94djdVX2dPOXQ0Y1VIQm15OTNSaWxuOVFNNXNpeDZEODVw\\\nRlRYRU0yaUdxRTdEWWgxX3lsVjktZldYNGRhM19wZjlXVTd1aV82bWwzSno0UG5qYklv\\\nS2lFVEI1Y0diUmFJNk8tTkVDaE82LWlKajFoNUFaQ1NSLWJnaktNMTBERXdRUHpOREJm\\\nT3BQcjdJSFQ4cFBpelk2WG5mblNaRlQxY3ZiTFA4blNYSkNiVmFoMkJkS0NKTkFWT2Ff\\\nN0gtdnlpMHVYRzlZSjZEYWFYbm90dmp1UHRsdzVtRFVkYUlFdWNxNnM1MzVvMnVOaTBM\\\nQzhEX3dlOHRwT042YTNqNWJDVWFnS3BxdEduejdrbUJfVHZNd0ZLZTRrcXZhZ3pCbmRL\\\nTkVyOFZxaWlMZHlMMzdmbWhjY0NMQTlZaUFFY2NrOHhDUHdCdVpDUFR3c2xsX2hLcjBB\\\nSUtHSm13WklxUVdmUXE1UHk0OWU2NFFqbHU5ZzhuNlRFazFKMXRQakdGdFp4Z0lsTFR4\\\nSFEzeEF4YWcyYnEzNWxhcHdVY0FZSlhsQkxPdW9BektNU19VT0d5bjh0RWhtamN0Z0Yy\\\nNXhGNEZ4elYyOGtxUUhncUp3VHI3MjZjcVB3QlAwSG0yamE4eExVU29vSUM5TklvWlRm\\\nSWI4T3k3ZkVxNE5PNzh4QnZGOFlsdU1wZC1fMkJpdU9QcXpENnE0TmFuTzlJVm9kTlhs\\\nMF9zZW5zOER0VWhnTEszSG4yREYtMTFCQlRqVkdPRmFFT2s5MmticDRjRFU3WTlhR3VN\\\nT3pNSWM1LXJFdEZtYXZuQTRtYnBOdGlkMjQ3VVpFalVCb0xTY3dTM1pnOG9CUnJ0a2dU\\\nNHZSeTF6bnM5ek1WOVV3dFlpeDByTE1rekVZbndsb3NoR2FTSFRwRFh0NFdoZkhXR2pY\\\nMFk4RHNsY3lfMUN6Zzg5X1pQMUJjVXB3OTVqdFVUWlFfUzlPQTFRQWR0WE9YY1lhSlNT\\\nQ3RULUg4cUdrcl92N3NnX3hWLTE0SzhBc0twU1JQa1FhQ1JKS3FaRVN3SDV5dVpva2pQ\\\ndHFtYk14dkZndmhNbGlSTmtGRkRYaWdhSHIwcUxudXlFUktFZjY2RUdaWTUxUWp6aUVa\\\nQ0ZQTmpLeG9vd21NLTVwcTBWSDR0d3JfNGZHWVJUTUJHSV8waVNGYnNpQU1QbjF4VEt0\\\ncER3THdLV2MzZmJwbFRnTXkxWnltRC1OckxXVXpzTng3WVhqYUktNTBjUjcwa3J3YiJ9",
  "aad": "ZXh0ZXJuYWwtYWFk",
  "iv": "sLGys7S1tre4ubq7",
  "ciphertext": "2_fxcDfSskbGhZa8P5jG8Vwio8A",
  "tag": "d4Lk47RpbBGiW37y5JvHIg"
}
~~~

## ML-KEM-768
{: numbered="false"}

Public JWK:

~~~ json
{
  "kty": "AKP",
  "alg": "ML-KEM-768",
  "pub": "xzfOXckgmbVPNdQ2w3qGmVSfthZe9zJgmFlH3mUz2JduKHRYpxEvd0NvHlaewghSVvt0PgeJxBwaQaNolaPMQGKL-8CGcQoASlBVz8g3D3wqCLw7lJZQEpoeCmFrzgkHzXKG4FKapONMbJkk3FuKHtJ1YAFcZYx5CJRZBphZriATlDV2yntU_lsM7XmHjCYlqnebEchekmsq0aJzb1cQ_saLHQC3L6PET4OI3kafgbhGExtQ5gcPhtYgoPps1sZldIwbwWq3xgWHnfM2XeQ1KBIJoJJqQkkmMVxNH6qa-Ng9n2U0qkIWkMRCtpaULpCkt6ZDhNmzM6ywWdwwHOEfnRGcSwmPjsw5A6IN6XKuWPg9LQsGuHM9AKzBvhByhxPOlQzAfrseU9oETOSZ84YvZ9oHZRN_PepN7BHDnzEIKGaEx7xiK8AEpry-GSZOECwjrhDIP8IpZsCWu1YiTHdwEsUJY1MKjEhL7QCxsga5-1cDrXpxiIXJ4UMa9DZRZmKdFkABjjSmKJR_9pmL28RCWiJ3R8eI5PmzE5ugzjS7w-V2NLl1bydw7pAnFYpp1Yh3QeOnRvUrQBZhhVJ_r9MiajwrUZkvZUHFt0rLMeCJ65XC91AuyqPNQWM5XaKMjysn2BtIwnjAucMMowxIS3C_OzJBbVayNFPIjOB6rZyp_xFkzaGArriemPmU-fOEmvKQyyGUQXc7q1pSrtxlsnVK4cbKduBNJ8KAx5XGKahEtPOQHIW8SYc3InlX-syTN1SwJKONQqs6MUizVonEK4NwtWAhqIQaYyEp8mYc7LyQyrdb65Rs1GaKK0JkYIVQnvWi0QxL6fBglxxVomm7WtdS2nl5qwwvtmsYrgoJYcS8bWGxINWcF0ch5XRh5RGavaVf1yKl9vnFfrJKdFpyjfxl_BicSmuzEQMkp3RkFotxslqAZfFBN1C3HTWyX6mpaiuuKPwCe4BIqCnN5QJ5CSwSeWMFthUUIGi5mFx8uJNfWlunDXO4hZLIZswNhSxDpDtBtow10bNYjrUk6zMn4dh1cWw-xuaG1GqyziB99sReo5pwXbICcYa4oKfNNRyC3DMWURcmhGSlDHVIWGLDTeQuJhXNtwMV22O8KCRTeqCpJrKcgUxy19RQ9IKIvLe6nSth5LmEagcXhSPGWzQQF-pJ4lebA5Bhidw4wTRzFbcLu-mfrYxRx7ewSIpzf3Wr8cjJ42QEI7WbowYBI2ZFS7xa10XLufoa68cerLRwlbVfsjR0MMa8UvVUS0G5VsYrJPnCaAAJqGFOOQMmKRomEnJWf5ZMKUuTYNCMcdYDOTdxBkzBGAWcklABAiqdnUVntPep6WxUgaM8ulCmkThBSbOG5vgRYpEGXMKNDHowgHe7hxAvCIVCddk_RXykLUtzJrchsoUGExtxOKOH1iY2oJURk1N-x5N71BpykhQeOODEvrofR2J2hEF0paCbnCWv65s25Xod4BSaXQam_bBCaDKRlmu8ShmQCsR5eAZk7ER-YmgYJ8kmk0K59fdPKElcMdxbN4NTbhZKfVqJ-wlk-oTYFWnxosG9V9Iz3VsCczaXH68"
}
~~~

Private JWK:

~~~ json
{
  "kty": "AKP",
  "alg": "ML-KEM-768",
  "pub": "xzfOXckgmbVPNdQ2w3qGmVSfthZe9zJgmFlH3mUz2JduKHRYpxEvd0NvHlaewghSVvt0PgeJxBwaQaNolaPMQGKL-8CGcQoASlBVz8g3D3wqCLw7lJZQEpoeCmFrzgkHzXKG4FKapONMbJkk3FuKHtJ1YAFcZYx5CJRZBphZriATlDV2yntU_lsM7XmHjCYlqnebEchekmsq0aJzb1cQ_saLHQC3L6PET4OI3kafgbhGExtQ5gcPhtYgoPps1sZldIwbwWq3xgWHnfM2XeQ1KBIJoJJqQkkmMVxNH6qa-Ng9n2U0qkIWkMRCtpaULpCkt6ZDhNmzM6ywWdwwHOEfnRGcSwmPjsw5A6IN6XKuWPg9LQsGuHM9AKzBvhByhxPOlQzAfrseU9oETOSZ84YvZ9oHZRN_PepN7BHDnzEIKGaEx7xiK8AEpry-GSZOECwjrhDIP8IpZsCWu1YiTHdwEsUJY1MKjEhL7QCxsga5-1cDrXpxiIXJ4UMa9DZRZmKdFkABjjSmKJR_9pmL28RCWiJ3R8eI5PmzE5ugzjS7w-V2NLl1bydw7pAnFYpp1Yh3QeOnRvUrQBZhhVJ_r9MiajwrUZkvZUHFt0rLMeCJ65XC91AuyqPNQWM5XaKMjysn2BtIwnjAucMMowxIS3C_OzJBbVayNFPIjOB6rZyp_xFkzaGArriemPmU-fOEmvKQyyGUQXc7q1pSrtxlsnVK4cbKduBNJ8KAx5XGKahEtPOQHIW8SYc3InlX-syTN1SwJKONQqs6MUizVonEK4NwtWAhqIQaYyEp8mYc7LyQyrdb65Rs1GaKK0JkYIVQnvWi0QxL6fBglxxVomm7WtdS2nl5qwwvtmsYrgoJYcS8bWGxINWcF0ch5XRh5RGavaVf1yKl9vnFfrJKdFpyjfxl_BicSmuzEQMkp3RkFotxslqAZfFBN1C3HTWyX6mpaiuuKPwCe4BIqCnN5QJ5CSwSeWMFthUUIGi5mFx8uJNfWlunDXO4hZLIZswNhSxDpDtBtow10bNYjrUk6zMn4dh1cWw-xuaG1GqyziB99sReo5pwXbICcYa4oKfNNRyC3DMWURcmhGSlDHVIWGLDTeQuJhXNtwMV22O8KCRTeqCpJrKcgUxy19RQ9IKIvLe6nSth5LmEagcXhSPGWzQQF-pJ4lebA5Bhidw4wTRzFbcLu-mfrYxRx7ewSIpzf3Wr8cjJ42QEI7WbowYBI2ZFS7xa10XLufoa68cerLRwlbVfsjR0MMa8UvVUS0G5VsYrJPnCaAAJqGFOOQMmKRomEnJWf5ZMKUuTYNCMcdYDOTdxBkzBGAWcklABAiqdnUVntPep6WxUgaM8ulCmkThBSbOG5vgRYpEGXMKNDHowgHe7hxAvCIVCddk_RXykLUtzJrchsoUGExtxOKOH1iY2oJURk1N-x5N71BpykhQeOODEvrofR2J2hEF0paCbnCWv65s25Xod4BSaXQam_bBCaDKRlmu8ShmQCsR5eAZk7ER-YmgYJ8kmk0K59fdPKElcMdxbN4NTbhZKfVqJ-wlk-oTYFWnxosG9V9Iz3VsCczaXH68",
  "priv": "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj9AQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVpbXF1eXw"
}
~~~

Flattened JWE JSON Serialization:

~~~ json
{
  "protected": "eyJhbGciOiJNTC1LRU0tNzY4IiwiZW5jIjoiQTE5MkdDTSIsImtlbWN0IjoiOTFzUGRM\\\nY19EWkc2OFBVdzBXVmQwUUhZMFp5cFo2dEFUMENRWkJDSE1pNmp6cTFBNUhfQUxZcEk3\\\naFp1Nk4zQjRLcXU5emJicXJhUHJmbTJOR2lfUmhYR1JXTzJ1VjhfV2VKcGVicktnejZk\\\nNm5UbVJrNjd3U1d2dGJINEkwZXFRWTgwYjFQN0FpQTd3ak9OOWt5LWlJR2RMUjlmZ1pu\\\nU2JNcjlmS3JqMXR5Z29wejhNWHNTYjl6RVpMMjhPNkl3MXBhc3Atc0xSU0lxWVIwYXdj\\\naHI1XzZnTWZzN0tHX2J1TlRlT3RqMzlLM3V6SmZ0VWY2a2llY2pvMGxtcjZfUHA3THBk\\\nb2RMMEdhemVQdjNwQURQYml0SmZja2xVTml1MDgtbjJ0N3Nqcnd3SWxINHVXZzhsdnRZ\\\nQVU3dkdZMmZKYW00MWwyZEFMZG1ZY1VFQzR1ZGUyNFIxUHNya1dxeXZLOUVYTVI5czI0\\\nWDM3T3dlVTJBdW5YbUdIMFZtR015OFpFc05DcFJWUDBVVF9LZWloSklIcFpsMF9ySEdl\\\nT25uZjFOajNJZFVhWGt1M0k2RzdVMlBpOWpPWElDV3JoSTNvdFBPZEttRVlnUm5feFJY\\\nb1FUWkxmVW93a19ncWRMMUM0SUJHdFUyVnZTYVgweFEyN2Q3bEZsRWlWd2JQdERTY05K\\\nYmQ0bHBBVkVuNVJYWWpLR3lnN1VIVTN4eG9nNTVYQldiZThVUkxGcUU2LTNLWEdrU0Fk\\\nYmtDUS1WMlYyd05rc1hwakZYVlhMZm5NMnphUksxY1RYei1XQlNLNWxiTndUc3FkWFFk\\\nMmZiNGRmQmxWT2hwMEhEamhpdFFDSVZxME9sLXdMV2NhRmprVVpBMWhNc3BPSHBlTnNY\\\neXYyMi01Yy1pXzM0cy03S252Q0hJeEFQRUlIcEtlLUNoMndCVFhoOWhHMjktR1k2RUkw\\\nQmNvd01tNVNTVXRNTGZhVFBXTHVXRTdWejlXUGpKejIzNzRYY2oyb0NJbXN4X29zY0lh\\\nelR0cVlpZjMyUDNFOU4wYTV5RmtjREJJR0d1RmxLMDNkdnJSWE0tWWl4VlVYYW9qcVZk\\\nSE9ndmNxY0p0QW1peElicGRNaG15UDVNQWxGQ3pCLXdxOTBZQ0R1Yy1WSm93QVF5X29w\\\nRHFPWnRaenBqSk1ZVXpWS0VRejk5eWRLd2I4bUt3LWJjRnAxdmR6STJ6eUNRYWRQTzVU\\\nU1ZrN0JGSVVfUjExQ0pOVUdmVWpxaGY1UnhGSFR3MURKMjRrZXZQX1ZEYVU0RmlUazhl\\\nNklVYjlEaHUwbnh6X2hfTXd0RkpnOTE1Q1pQWXVOUlVoTXBKQm5EdnMybzV3Y3F6VzBt\\\nMkdPZTVtYmN3WWQybEJTX3Y0Z3JncWM1ZUo0STFSbnhGZDRPTWptRHk0Yzg3ZjdtdDEw\\\ndFYzQzJTSFRnMnY2RUZDZWF4MDRQMllkU1hjQjF2WlZXU204QjdlYWpya2swVzNyMHZT\\\nSEpneGhYUEhXSmJyWHpuVEVSOHcyc2tka1RPeUxRczBSLVpDTlpodXBPel9pTmlfc0VF\\\neWZtNDFKOEExVk1WeDAySktYREhqWDhmZ2hETk9WRFhGa19PN252NGVDd2h1cXBKWUh1\\\nS0ppYkYyOWtESUljVXY3V3A1MGJpNTlUT05CcGVpMzEyLVJBLU9pLUVYM21qRjRIalJ3\\\nWHRXNmlxNl9YeWs0dl9la1ZVZ1B2cndkTXdRSkVjV1kxZ2FGbHZ3T2pjMTA0WGp6MW9V\\\nRlh3OGhLbWVjbm9KSHBTa1RjUHF1Vl8tNDdDSGNUWUJaZkJaSk9wbno4TDFQOEtaZEZm\\\nanpGT2VNMGl5b0ZJLVU2RVMxbVhLcWE2bHpmMFdWWE1HUm1UYVEtMlJqYjdpN2JOY1I5\\\nU0xrOXFROWFVNThRa2N0TWMifQ",
  "aad": "ZXh0ZXJuYWwtYWFk",
  "iv": "sLGys7S1tre4ubq7",
  "ciphertext": "sZgViZ32UgZWmnkqJVYQy30OW5w",
  "tag": "zswF71G0kLpahy1iXKFzfg"
}
~~~

## ML-KEM-1024
{: numbered="false"}

Public JWK:

~~~ json
{
  "kty": "AKP",
  "alg": "ML-KEM-1024",
  "pub": "cDFjF2OKVJIUcTaxPMBc6aACVkhNYtG7HzmypKopCcqLpSEe1nqT6HBMPfWR9TkldKgA-fdm5YReC3yvjypN2ZKTd6ZXqZBNZjOQL8CM75XGz_ELStsOpxMvuNskEuJFG1S4W8amtRAjIUPDqIGqOHzGa5yiDleBo7M3mPFAKUdV6aMmrMGLNqe33PloN8SxDNu_a6xj76Ono_V5pRUSaONkZqBb6MKk_wsFRrvFyrRo-KEtmcIVD8YbPdenaqyxuxw4L6o1ShET62e-6MIU30li3wMuZ6K4xUsB_3xt9FAc7FaM2Du5uoCxQACzgGgnqpNqvbFWJ-uB1WOCYmGdByexy6GWyDaH8nuTa-aVmikyGLxq_CGwcJd1WcU2Tomnj6swt5GKwRSmnNSdVYa82MZ9WJpuLowORhaleoFMACcAuFc-1MqvJlTL6MhVrglReOQZyUoXsMBty2BWOxczQJdMz2lYm4srigmrvFt-2Ey8dvhiszqjHSesfspdxTRhRSOrBvNFacYGjkJN3Nu4KYiD9DSmBesLRRgxpKq8z1ia4rEjQNcUwhaULvhLiCVyU2FLM3BQeMOxlkw-DcysAZE3YxfD89aYDIc_mPAo7zRBXTBtmvlSecYoQIwlaKAHHigbt5iRFCuLV_lq9hJ8EQs4Nak55bVNjeAFhmiYiXF0TqZi0sI1FKQqITgoJMlPBrUZzLaAOGBzEnI8iKw_hMqtHUV_rsHNB5kzPgXCfucLcbSYvpWSr5p3yUye8keJCSLFlulBSkcyxXBh5mfMh7mGUChHfMsNHjzPdwmck7xyWoohSKQbXWV3AO0LmAMMena5WkG9hFeij2c4f5c5ViME3bHFMusb6KA1Oad1AfGYOxs3_Xp6YHFKWmQpgngXaHyiGqtRX6S9_lrBxXA2pDPIiqZwYDSq1kW_KUac8Ee5kmslu-e1o_wu56pGtnQn7ZEi93t-rHNXSCURZ1cs2rVSFBBzH3Stauo68NkktgguKAs8wJwPOOWzDiUGzXSGRXfHBCQrqWeCgUxrWEFBoINmgXRsV2q0l9O8B4Vz4oo4l3d9HOF8JWvDuEnMsSoCCrSwkkAUKBsMaKiXF7WSLBUwpKGYj1S9h_y8rhqlYFcbOgUucjA4V7mtqpWQhnYmuThCu_JUsnFAyUdJN0s5KYZfSCKhnHK2DhAiwcNloLOhKsXGmTtPk5WCFhUOsWWb2Nmi6lSUZceJfZgX2ZpGhlBFemibcsCVYQV5ghWGLboiyXsiS_ezs5qniDhVaTbJ0fR6kuS-o4ohuTeXiMJyoJOYwCWDiWe2i5Sv_AwVdnmgSOxxxEgrNTW-SAqTsLd50fqkQoVlTFFGEwdxwNxIGJiqP-CvMLNvjTs6eILNkAQRaIcDeppVccQ-nFkUv3OWcvp_NLsQOaUeKlskCSEEvpQ1K8xJ3ahU5HSt8Rg5OwwwrmeqOeUYtGhEy8dhUmAj_OOxPZuYOABNtelGVUu3UVka2RrOVIuY9AaMWUdNG1QWAtGZHsVoL-JbYLk75yFp-LQhRNIrKWUXIHVfS8d8SDythrTLD_Uz9oZqDmY_pPGkWdGcYMorJFlZeOpTmwKFVLvA05VfEwxH6SGYVIqP42dXfoENwPjEtBSGbdxuiUrDxChHkuh8HVBeZrETYAfN1UKgVBYsCTe4hjqbpvk2ypW9x7GhD6AfEIYJHGSM2XCBKsUoyeQqGdgeqtssIWV8W7EfIJoilFMyKmCS9Hk9qoQoT8oF6liu3TuZg7ycplyn6DdYXuDKCpfKUuNr7vi9l-ZHvDMLKRzNUvpuoaifM1YIe6U-DaCkaPtXOkCa54i8Cfib2XJUEaQx8VQOXekZQJxLZCCDhiotCauYTDmyvaV4JKkxNec5J9C8w5RKrnnAg4J64OUN1hnJ7aoK8VakCqBqKmCZ0KEGYVAl7hWN-JkxkakfbBB9AjeMLlS9m1G9AOXA9HuykSqi3GfGuZG_C9OvwowzgmBmlnop7eI3PpksdaM4p9SLbIvAtQZJ6GB7VYy1yrym1oMJLFjCWKqtAhiLFxoEOtdcNT7jeoGRi4wgEWAI-uYb_7RGJvCB9S0"
}
~~~

Private JWK:

~~~ json
{
  "kty": "AKP",
  "alg": "ML-KEM-1024",
  "pub": "cDFjF2OKVJIUcTaxPMBc6aACVkhNYtG7HzmypKopCcqLpSEe1nqT6HBMPfWR9TkldKgA-fdm5YReC3yvjypN2ZKTd6ZXqZBNZjOQL8CM75XGz_ELStsOpxMvuNskEuJFG1S4W8amtRAjIUPDqIGqOHzGa5yiDleBo7M3mPFAKUdV6aMmrMGLNqe33PloN8SxDNu_a6xj76Ono_V5pRUSaONkZqBb6MKk_wsFRrvFyrRo-KEtmcIVD8YbPdenaqyxuxw4L6o1ShET62e-6MIU30li3wMuZ6K4xUsB_3xt9FAc7FaM2Du5uoCxQACzgGgnqpNqvbFWJ-uB1WOCYmGdByexy6GWyDaH8nuTa-aVmikyGLxq_CGwcJd1WcU2Tomnj6swt5GKwRSmnNSdVYa82MZ9WJpuLowORhaleoFMACcAuFc-1MqvJlTL6MhVrglReOQZyUoXsMBty2BWOxczQJdMz2lYm4srigmrvFt-2Ey8dvhiszqjHSesfspdxTRhRSOrBvNFacYGjkJN3Nu4KYiD9DSmBesLRRgxpKq8z1ia4rEjQNcUwhaULvhLiCVyU2FLM3BQeMOxlkw-DcysAZE3YxfD89aYDIc_mPAo7zRBXTBtmvlSecYoQIwlaKAHHigbt5iRFCuLV_lq9hJ8EQs4Nak55bVNjeAFhmiYiXF0TqZi0sI1FKQqITgoJMlPBrUZzLaAOGBzEnI8iKw_hMqtHUV_rsHNB5kzPgXCfucLcbSYvpWSr5p3yUye8keJCSLFlulBSkcyxXBh5mfMh7mGUChHfMsNHjzPdwmck7xyWoohSKQbXWV3AO0LmAMMena5WkG9hFeij2c4f5c5ViME3bHFMusb6KA1Oad1AfGYOxs3_Xp6YHFKWmQpgngXaHyiGqtRX6S9_lrBxXA2pDPIiqZwYDSq1kW_KUac8Ee5kmslu-e1o_wu56pGtnQn7ZEi93t-rHNXSCURZ1cs2rVSFBBzH3Stauo68NkktgguKAs8wJwPOOWzDiUGzXSGRXfHBCQrqWeCgUxrWEFBoINmgXRsV2q0l9O8B4Vz4oo4l3d9HOF8JWvDuEnMsSoCCrSwkkAUKBsMaKiXF7WSLBUwpKGYj1S9h_y8rhqlYFcbOgUucjA4V7mtqpWQhnYmuThCu_JUsnFAyUdJN0s5KYZfSCKhnHK2DhAiwcNloLOhKsXGmTtPk5WCFhUOsWWb2Nmi6lSUZceJfZgX2ZpGhlBFemibcsCVYQV5ghWGLboiyXsiS_ezs5qniDhVaTbJ0fR6kuS-o4ohuTeXiMJyoJOYwCWDiWe2i5Sv_AwVdnmgSOxxxEgrNTW-SAqTsLd50fqkQoVlTFFGEwdxwNxIGJiqP-CvMLNvjTs6eILNkAQRaIcDeppVccQ-nFkUv3OWcvp_NLsQOaUeKlskCSEEvpQ1K8xJ3ahU5HSt8Rg5OwwwrmeqOeUYtGhEy8dhUmAj_OOxPZuYOABNtelGVUu3UVka2RrOVIuY9AaMWUdNG1QWAtGZHsVoL-JbYLk75yFp-LQhRNIrKWUXIHVfS8d8SDythrTLD_Uz9oZqDmY_pPGkWdGcYMorJFlZeOpTmwKFVLvA05VfEwxH6SGYVIqP42dXfoENwPjEtBSGbdxuiUrDxChHkuh8HVBeZrETYAfN1UKgVBYsCTe4hjqbpvk2ypW9x7GhD6AfEIYJHGSM2XCBKsUoyeQqGdgeqtssIWV8W7EfIJoilFMyKmCS9Hk9qoQoT8oF6liu3TuZg7ycplyn6DdYXuDKCpfKUuNr7vi9l-ZHvDMLKRzNUvpuoaifM1YIe6U-DaCkaPtXOkCa54i8Cfib2XJUEaQx8VQOXekZQJxLZCCDhiotCauYTDmyvaV4JKkxNec5J9C8w5RKrnnAg4J64OUN1hnJ7aoK8VakCqBqKmCZ0KEGYVAl7hWN-JkxkakfbBB9AjeMLlS9m1G9AOXA9HuykSqi3GfGuZG_C9OvwowzgmBmlnop7eI3PpksdaM4p9SLbIvAtQZJ6GB7VYy1yrym1oMJLFjCWKqtAhiLFxoEOtdcNT7jeoGRi4wgEWAI-uYb_7RGJvCB9S0",
  "priv": "MDEyMzQ1Njc4OTo7PD0-P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ubw"
}
~~~

Flattened JWE JSON Serialization:

~~~ json
{
  "protected": "eyJhbGciOiJNTC1LRU0tMTAyNCIsImVuYyI6IkEyNTZHQ00iLCJrZW1jdCI6ImJKTUpn\\\nelRWTkM0RkhDVWNEcExJbDVmNWZHSkptWE1FVEdRYXRZQzdMUzNEYjFOSlRVMTNhVkZv\\\nRDBxSGhXS04xUm1UWjVjTkVqcXNGb1VOQ2NXQ0tmWkJDSE5NV0dGSTZteXZfVzNldzVD\\\ncVJEUXZBS1c0eko5WHFHb1UycWJUaVRzamVIWm03YkM1Z3lYNzlHWDRYVDVla3NCMWpK\\\ncTg0aXlIelRoSEMxWGVwUkgzLUtTeE93Ti1OWjBBZm5vZ202dktWbWI0a25nMWtWWC16\\\ncGNsc215dW9JYTA1VWllbF92enEzQWFmcno5MGd6bVNuaFRCZElwQUQtWTM1MnExNnV3\\\nLVRHSWNmSHlxbkFHRFBHa1BWM1oyRF9iRFNxaGV0ZkpvS0poRXFLbU5XbGs5LVl0LTdf\\\nOUwtZnFlaDJ1cjF4aG05RFVBSHdrR0NNQmFyQUxXYkYzOXhaaWNWMUgzN2VpV1haS3pr\\\nOVotbXJiSFRPeFZUbDA1aXVrbWtGb1lkWmY5WEF1MTZ6OVlfZ3plMGlVLXh3cU1MTVVT\\\nekJxWUNZZkFMTmVNNUJYLXVxdnZUSjJOTEhycl9HbUlxWHdmMnlsbGcySHhTdVAxUG9o\\\nbm40T3JUZTZUUC1vQzhGa2xqSDhZNzdZTHNSaFlYOEduZXdWcVAxcW9uSFpaWEhKdzV0\\\neENpblFyRmtOZWhZSDlLdGx5RTJSMGZ1cjdXOF9hb1FUVXI5czN4cVVTS3NPd2dNdW0y\\\nT2xMM21GV0FXUC1MTjU3bGtSeUhnRzFNWU9PNGpGM245UUxlTTNfZDJGcDdYUmRkSE13\\\nUTk5WWlZYUwzZmpZS0piclhRVFhnMGNoZHFoSFF1X3d3VmE5Ynd0UzJJWmpZbHRVRERt\\\neHEzLXFKWXhycXRBbnZFa1BfN0Q2OWVDdXVwSWdLZUkyMWJXRFFhU2pXV2hBVUlYbENw\\\nejZpQXAzNnVDSTBwWWo3dTAxX2VMd3BtNUJFMHRXNzZQYlFCUWI4YTZvYTVjVjdZd194\\\nSWs2bnZuYWpSendaV21IbkRZVnY5QVV0SVBweV9BaWZDeVlUcE1XWVRwRFczOFZwYkdN\\\neVpZT1lXVzZIWTlKTTJpY2VhbG1EaGpYY0NhbU5MZzJ3Q0lQT0wyR1ZQNW9hUDhDOUZf\\\nQXVvb2JIV2FGX0k4c1lDbjcyZXdvYjVCbzhidzlDZ0g4elY3Z04xUnVQTVNRSGI0bnMy\\\nUUVfRmpaS0hzOFJXV1Z3dEF2aFRQQWVuX0N5UzM1Zmd4V1JleGlrWlNrOFdKaGFLYjB0\\\nVFJzQ1N4Snc3b2s1QmZXMXliY05JWXZiY0Jtdy1oMkJFNGotTVZua1RUYmZqMHA4VGN2\\\nVk9ybVhmLTl5dXYxQWNfZkk3WEhqTF9DRGpvOWtkMkUxdkFuUXFXNFJmRHIyTjBUdW9J\\\nQ2RNUndralByUDA4VmJ0bTYxNVJZUWwwc0p1d1IwU2g0b2xVMDRlaWYwbEt1UF90N0Ni\\\nYWlqOVhmdkV3WmtyRGIwcWdzWkNhckdjZmdxSTJMY1FRV29uRW93OGN1Z1JRbnJxU2hy\\\nSFBqS2xxQU5EV3BZNVFPalcwZFFNcmlSM1dwS1NGcDUxdnlpZHJjZS14M05QOFhoWmtU\\\nZ0xYTDVpbU1PR2xNbEV4N2RXaktxcDhrQU1yOF9hTjlNUTJSMmRYUERzbWRac0lYWHhp\\\nR2dIWHE1a05lZHlZc2lJRWt6OWxSYmlSVWtTdVBwUjVfM0VBUjNYQlNyazNoc2lUcmJS\\\nMmI0ODEtWDFYcXNyYmJSRVRQQ0FSZlQ0OFh4N3VldHphSThTUE5CekhvbDN0TjlYMmRZ\\\ndmhlaTgxUHBEV20ybDRNeDU0Y0g4aUxkTHU0OXl1OHRWOElIS1dZSkhxLWxjNGxNTnp6\\\nLWxKWmFTdzNvRm1WNWdaV05DUlZiVFVaVXhvQjg2d29qZkV3RjY5Qk1seW5MTGd5QlBi\\\nQjV6NVM4MlMwc2pWSE9SR01WQ0h3ME0yckpmY3QtcHJkalRaZEZNdTl1bW1SZXlyaWRx\\\nZ3FNLW51SFpwS1k3anl5NndHN3VZem5nam1KWHFVS0tGUWdxN0NJWXdDUXd5QlJYRUZy\\\nMURRemNNblgzYlZta1BQX0FQZURQYXJsSkJKM05UbXVYYUtDV00wZm50cDFsejlRRDVW\\\neFpyMnU1NW4yM0NIU2ZyZGNvUHgxSTBwMng5TFNudzJqR1JDYkpRTmp4dHVBamZzUFha\\\nX3ZoRTNLOHBjN2F1SWpscS1UMmJWZ3ZtWW1KTndrODRtaGJvaE9ndzlrWm13YkRVa1Bt\\\nVGdDaWMycTBaR01FWTNTWHJxY3BQYUM0bk5EXzJMVWtIUVVGSS1TanZXOVN2LUtPUGgy\\\nZXk5RUFWS0N3MVVaeklXbGxrS2pyeVRFcW5xUnZ4eEozcU9Wck93dm5UaGhEVjZOY3VE\\\nREd2UGEwczZQRjhIOG1QQkpXZ09yWVVRcE1YSk12eC15QlMyZV8zM1NfWkpUQXhEUW80\\\nT1JkWTRzd0tXdXVwUnRhV3NYZmR0Rk1Sbk1oeWdUUE9Yd3hQNkFDSUVYaWV5Mzcyand1\\\nVWgwSjdkemd2WkUxQmtLTUNWMVpQYng0OGFlejlfVGhfZDBrSkQ5ZnFBM21mREN6Zk50\\\nUUdFU0t1cncxejFRelNPQi1HZzR3b3JyMEV2c1NGZmpONUFpZk0tWjNGQ1dsRVZlSWw4\\\nbDduWHptc0I2UHhETXo5eWVfb3pYTFQzYXlJUzRJWHJQMlpYVzRwR2RZMnRKYyJ9",
  "aad": "ZXh0ZXJuYWwtYWFk",
  "iv": "sLGys7S1tre4ubq7",
  "ciphertext": "FDe4L600BXL6yMj8D9a1eVmrAx0",
  "tag": "g6qHZSEEmEbMdhgzqJJTvA"
}
~~~

## ML-KEM-512+A128KW
{: numbered="false"}

Public JWK:

~~~ json
{
  "kty": "AKP",
  "alg": "ML-KEM-512",
  "pub": "t_mc34cEvCrOhiUbRjmmghJdonimWRiF1pdjsSGfiqWLFlR7FzF8hXYEG9HJ-FNHeyS3F4tJ1MsXO2qOOJxNbcGJghOhhHyXY3Fw09UPLHMc4FoeddoD3Lki3LmRb2cjuAKBpSQNQeLH7ObE0_eSDxFCeTxsKjYny0e6JtBj2LhAVIyKLjhFYsu9B4MuuimhbTHCysx4l0YegqI98wjB7ddEMDJJgSsnjuoT80MiZvA3iGCd5uMjEJDBdazPwGObqlGP70DNC8sKjLKYN4g9BwO1fTBZY9wfS-lwQghko3ExavKwxiUnO3nPoiVwtSq1VWEFVbyh2WBHdTWehDaeHUxHzjAaDcWgjnqdQRaen6BIZnVr-Bh3qNVDvTk2LnxsC2IqIfsu8CIgrYSY3nKN84k9aTSd1RE64OuCKYNVwrsnQsRWvkpspvMYfexp9LOkMNVAK5VwC2seZKNy7OyklIFpyUwXZPqItjbD6vYLotyQv9wg1lyoDehrl1F0_kyKYfOMbpFPdbgc6tI_nWg130QxgEsSdECTQCyWpbN7eXuQ5Xddg5CRvAeUzxXJzWF1qnPLhwAh3igm-lCY95nEdTKUBiBfsHyyS4Js1GlcwzyDA4FZsAUYldmpStK5UZGUWEZFSQW0I9UG3hsvkgp4mscgF7iYgJMtC_sX0oEampUJ6wkb0eaIo3yZkjdhRptOKGG-ZmCibvYzlPoefnZuHqBS8wSps3aDLPm77zi_eDLO6NoKe4K_fYobvss-mkQVI0nOsGsH4UhUCNInTHIaJttlIzPAYDa02tE4nZi9m7R29IUzKtghgdCN1AeD5OJRxJVFQ-el1DwJ-RsqcNu8NtCx1hmgdrYVlFUB_DXERMgQCAu7AkMFYAU79iAlPym8lCM0fqiK2NqBM1fHl3dWyjPBysNnSffGo8iJsNctZgdAhZN3BwgSkaOB2Ea0kaMVAyUg8QqKEWS8FCU-NJIQ0SUXixidd5Nvp0iIFitPWUFK2lh4_8kIh6EfJoZddCKBN3UB3V5heTKuz3edcP77m-acNqUvKjVebxKz9oSQpKA"
}
~~~

Private JWK:

~~~ json
{
  "kty": "AKP",
  "alg": "ML-KEM-512",
  "pub": "t_mc34cEvCrOhiUbRjmmghJdonimWRiF1pdjsSGfiqWLFlR7FzF8hXYEG9HJ-FNHeyS3F4tJ1MsXO2qOOJxNbcGJghOhhHyXY3Fw09UPLHMc4FoeddoD3Lki3LmRb2cjuAKBpSQNQeLH7ObE0_eSDxFCeTxsKjYny0e6JtBj2LhAVIyKLjhFYsu9B4MuuimhbTHCysx4l0YegqI98wjB7ddEMDJJgSsnjuoT80MiZvA3iGCd5uMjEJDBdazPwGObqlGP70DNC8sKjLKYN4g9BwO1fTBZY9wfS-lwQghko3ExavKwxiUnO3nPoiVwtSq1VWEFVbyh2WBHdTWehDaeHUxHzjAaDcWgjnqdQRaen6BIZnVr-Bh3qNVDvTk2LnxsC2IqIfsu8CIgrYSY3nKN84k9aTSd1RE64OuCKYNVwrsnQsRWvkpspvMYfexp9LOkMNVAK5VwC2seZKNy7OyklIFpyUwXZPqItjbD6vYLotyQv9wg1lyoDehrl1F0_kyKYfOMbpFPdbgc6tI_nWg130QxgEsSdECTQCyWpbN7eXuQ5Xddg5CRvAeUzxXJzWF1qnPLhwAh3igm-lCY95nEdTKUBiBfsHyyS4Js1GlcwzyDA4FZsAUYldmpStK5UZGUWEZFSQW0I9UG3hsvkgp4mscgF7iYgJMtC_sX0oEampUJ6wkb0eaIo3yZkjdhRptOKGG-ZmCibvYzlPoefnZuHqBS8wSps3aDLPm77zi_eDLO6NoKe4K_fYobvss-mkQVI0nOsGsH4UhUCNInTHIaJttlIzPAYDa02tE4nZi9m7R29IUzKtghgdCN1AeD5OJRxJVFQ-el1DwJ-RsqcNu8NtCx1hmgdrYVlFUB_DXERMgQCAu7AkMFYAU79iAlPym8lCM0fqiK2NqBM1fHl3dWyjPBysNnSffGo8iJsNctZgdAhZN3BwgSkaOB2Ea0kaMVAyUg8QqKEWS8FCU-NJIQ0SUXixidd5Nvp0iIFitPWUFK2lh4_8kIh6EfJoZddCKBN3UB3V5heTKuz3edcP77m-acNqUvKjVebxKz9oSQpKA",
  "priv": "EBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4_QEFCQ0RFRkdISUpLTE1OTw"
}
~~~

Flattened JWE JSON Serialization:

~~~ json
{
  "protected": "eyJhbGciOiJNTC1LRU0tNTEyK0ExMjhLVyIsImVuYyI6IkExMjhHQ00iLCJrZW1jdCI6\\\nIkVHMnJuX0VtdTNOWFRjbGg2Tkd4TWFRQ3BlWXhEbTNWVzBCcThid3pQVzNIUDNYY25n\\\nR2VRWWhZd21zX0hCV1BaczZNQ2VtdmRfeHY3VV9nTzl0NGNVSEJteTkzUmlsbjlRTTVz\\\naXg2RDg1cEZUWEVNMmlHcUU3RFloMV95bFY5LWZXWDRkYTNfcGY5V1U3dWlfNm1sM0p6\\\nNFBuamJJb0tpRVRCNWNHYlJhSTZPLU5FQ2hPNi1pSmoxaDVBWkNTUi1iZ2pLTTEwREV3\\\nUVB6TkRCZk9wUHI3SUhUOHBQaXpZNlhuZm5TWkZUMWN2YkxQOG5TWEpDYlZhaDJCZEtD\\\nSk5BVk9hXzdILXZ5aTB1WEc5WUo2RGFhWG5vdHZqdVB0bHc1bURVZGFJRXVjcTZzNTM1\\\nbzJ1TmkwTEM4RF93ZTh0cE9ONmEzajViQ1VhZ0twcXRHbno3a21CX1R2TXdGS2U0a3F2\\\nYWd6Qm5kS05FcjhWcWlpTGR5TDM3Zm1oY2NDTEE5WWlBRWNjazh4Q1B3QnVaQ1BUd3Ns\\\nbF9oS3IwQUlLR0ptd1pJcVFXZlFxNVB5NDllNjRRamx1OWc4bjZURWsxSjF0UGpHRnRa\\\neGdJbExUeEhRM3hBeGFnMmJxMzVsYXB3VWNBWUpYbEJMT3VvQXpLTVNfVU9HeW44dEVo\\\nbWpjdGdGMjV4RjRGeHpWMjhrcVFIZ3FKd1RyNzI2Y3FQd0JQMEhtMmphOHhMVVNvb0lD\\\nOU5Jb1pUZkliOE95N2ZFcTROTzc4eEJ2RjhZbHVNcGQtXzJCaXVPUHF6RDZxNE5hbk85\\\nSVZvZE5YbDBfc2VuczhEdFVoZ0xLM0huMkRGLTExQkJUalZHT0ZhRU9rOTJrYnA0Y0RV\\\nN1k5YUd1TU96TUljNS1yRXRGbWF2bkE0bWJwTnRpZDI0N1VaRWpVQm9MU2N3UzNaZzhv\\\nQlJydGtnVDR2Unkxem5zOXpNVjlVd3RZaXgwckxNa3pFWW53bG9zaEdhU0hUcERYdDRX\\\naGZIV0dqWDBZOERzbGN5XzFDemc4OV9aUDFCY1Vwdzk1anRVVFpRX1M5T0ExUUFkdFhP\\\nWGNZYUpTU0N0VC1IOHFHa3JfdjdzZ194Vi0xNEs4QXNLcFNSUGtRYUNSSktxWkVTd0g1\\\neXVab2tqUHRxbWJNeHZGZ3ZoTWxpUk5rRkZEWGlnYUhyMHFMbnV5RVJLRWY2NkVHWlk1\\\nMVFqemlFWkNGUE5qS3hvb3dtTS01cHEwVkg0dHdyXzRmR1lSVE1CR0lfMGlTRmJzaUFN\\\nUG4xeFRLdHBEd0x3S1djM2ZicGxUZ015MVp5bUQtTnJMV1V6c054N1lYamFJLTUwY1I3\\\nMGtyd2IifQ",
  "encrypted_key": "XuIrp6nvQGFRFzojRkZ-oxOxbDvOob9h",
  "aad": "ZXh0ZXJuYWwtYWFk",
  "iv": "sLGys7S1tre4ubq7",
  "ciphertext": "Uv_qVKYs3G-hDNoDdxYWGFm6Nec",
  "tag": "VjsU9vGZWRzGfZkFJGQjxg"
}
~~~

## ML-KEM-768+A192KW
{: numbered="false"}

Public JWK:

~~~ json
{
  "kty": "AKP",
  "alg": "ML-KEM-768",
  "pub": "xzfOXckgmbVPNdQ2w3qGmVSfthZe9zJgmFlH3mUz2JduKHRYpxEvd0NvHlaewghSVvt0PgeJxBwaQaNolaPMQGKL-8CGcQoASlBVz8g3D3wqCLw7lJZQEpoeCmFrzgkHzXKG4FKapONMbJkk3FuKHtJ1YAFcZYx5CJRZBphZriATlDV2yntU_lsM7XmHjCYlqnebEchekmsq0aJzb1cQ_saLHQC3L6PET4OI3kafgbhGExtQ5gcPhtYgoPps1sZldIwbwWq3xgWHnfM2XeQ1KBIJoJJqQkkmMVxNH6qa-Ng9n2U0qkIWkMRCtpaULpCkt6ZDhNmzM6ywWdwwHOEfnRGcSwmPjsw5A6IN6XKuWPg9LQsGuHM9AKzBvhByhxPOlQzAfrseU9oETOSZ84YvZ9oHZRN_PepN7BHDnzEIKGaEx7xiK8AEpry-GSZOECwjrhDIP8IpZsCWu1YiTHdwEsUJY1MKjEhL7QCxsga5-1cDrXpxiIXJ4UMa9DZRZmKdFkABjjSmKJR_9pmL28RCWiJ3R8eI5PmzE5ugzjS7w-V2NLl1bydw7pAnFYpp1Yh3QeOnRvUrQBZhhVJ_r9MiajwrUZkvZUHFt0rLMeCJ65XC91AuyqPNQWM5XaKMjysn2BtIwnjAucMMowxIS3C_OzJBbVayNFPIjOB6rZyp_xFkzaGArriemPmU-fOEmvKQyyGUQXc7q1pSrtxlsnVK4cbKduBNJ8KAx5XGKahEtPOQHIW8SYc3InlX-syTN1SwJKONQqs6MUizVonEK4NwtWAhqIQaYyEp8mYc7LyQyrdb65Rs1GaKK0JkYIVQnvWi0QxL6fBglxxVomm7WtdS2nl5qwwvtmsYrgoJYcS8bWGxINWcF0ch5XRh5RGavaVf1yKl9vnFfrJKdFpyjfxl_BicSmuzEQMkp3RkFotxslqAZfFBN1C3HTWyX6mpaiuuKPwCe4BIqCnN5QJ5CSwSeWMFthUUIGi5mFx8uJNfWlunDXO4hZLIZswNhSxDpDtBtow10bNYjrUk6zMn4dh1cWw-xuaG1GqyziB99sReo5pwXbICcYa4oKfNNRyC3DMWURcmhGSlDHVIWGLDTeQuJhXNtwMV22O8KCRTeqCpJrKcgUxy19RQ9IKIvLe6nSth5LmEagcXhSPGWzQQF-pJ4lebA5Bhidw4wTRzFbcLu-mfrYxRx7ewSIpzf3Wr8cjJ42QEI7WbowYBI2ZFS7xa10XLufoa68cerLRwlbVfsjR0MMa8UvVUS0G5VsYrJPnCaAAJqGFOOQMmKRomEnJWf5ZMKUuTYNCMcdYDOTdxBkzBGAWcklABAiqdnUVntPep6WxUgaM8ulCmkThBSbOG5vgRYpEGXMKNDHowgHe7hxAvCIVCddk_RXykLUtzJrchsoUGExtxOKOH1iY2oJURk1N-x5N71BpykhQeOODEvrofR2J2hEF0paCbnCWv65s25Xod4BSaXQam_bBCaDKRlmu8ShmQCsR5eAZk7ER-YmgYJ8kmk0K59fdPKElcMdxbN4NTbhZKfVqJ-wlk-oTYFWnxosG9V9Iz3VsCczaXH68"
}
~~~

Private JWK:

~~~ json
{
  "kty": "AKP",
  "alg": "ML-KEM-768",
  "pub": "xzfOXckgmbVPNdQ2w3qGmVSfthZe9zJgmFlH3mUz2JduKHRYpxEvd0NvHlaewghSVvt0PgeJxBwaQaNolaPMQGKL-8CGcQoASlBVz8g3D3wqCLw7lJZQEpoeCmFrzgkHzXKG4FKapONMbJkk3FuKHtJ1YAFcZYx5CJRZBphZriATlDV2yntU_lsM7XmHjCYlqnebEchekmsq0aJzb1cQ_saLHQC3L6PET4OI3kafgbhGExtQ5gcPhtYgoPps1sZldIwbwWq3xgWHnfM2XeQ1KBIJoJJqQkkmMVxNH6qa-Ng9n2U0qkIWkMRCtpaULpCkt6ZDhNmzM6ywWdwwHOEfnRGcSwmPjsw5A6IN6XKuWPg9LQsGuHM9AKzBvhByhxPOlQzAfrseU9oETOSZ84YvZ9oHZRN_PepN7BHDnzEIKGaEx7xiK8AEpry-GSZOECwjrhDIP8IpZsCWu1YiTHdwEsUJY1MKjEhL7QCxsga5-1cDrXpxiIXJ4UMa9DZRZmKdFkABjjSmKJR_9pmL28RCWiJ3R8eI5PmzE5ugzjS7w-V2NLl1bydw7pAnFYpp1Yh3QeOnRvUrQBZhhVJ_r9MiajwrUZkvZUHFt0rLMeCJ65XC91AuyqPNQWM5XaKMjysn2BtIwnjAucMMowxIS3C_OzJBbVayNFPIjOB6rZyp_xFkzaGArriemPmU-fOEmvKQyyGUQXc7q1pSrtxlsnVK4cbKduBNJ8KAx5XGKahEtPOQHIW8SYc3InlX-syTN1SwJKONQqs6MUizVonEK4NwtWAhqIQaYyEp8mYc7LyQyrdb65Rs1GaKK0JkYIVQnvWi0QxL6fBglxxVomm7WtdS2nl5qwwvtmsYrgoJYcS8bWGxINWcF0ch5XRh5RGavaVf1yKl9vnFfrJKdFpyjfxl_BicSmuzEQMkp3RkFotxslqAZfFBN1C3HTWyX6mpaiuuKPwCe4BIqCnN5QJ5CSwSeWMFthUUIGi5mFx8uJNfWlunDXO4hZLIZswNhSxDpDtBtow10bNYjrUk6zMn4dh1cWw-xuaG1GqyziB99sReo5pwXbICcYa4oKfNNRyC3DMWURcmhGSlDHVIWGLDTeQuJhXNtwMV22O8KCRTeqCpJrKcgUxy19RQ9IKIvLe6nSth5LmEagcXhSPGWzQQF-pJ4lebA5Bhidw4wTRzFbcLu-mfrYxRx7ewSIpzf3Wr8cjJ42QEI7WbowYBI2ZFS7xa10XLufoa68cerLRwlbVfsjR0MMa8UvVUS0G5VsYrJPnCaAAJqGFOOQMmKRomEnJWf5ZMKUuTYNCMcdYDOTdxBkzBGAWcklABAiqdnUVntPep6WxUgaM8ulCmkThBSbOG5vgRYpEGXMKNDHowgHe7hxAvCIVCddk_RXykLUtzJrchsoUGExtxOKOH1iY2oJURk1N-x5N71BpykhQeOODEvrofR2J2hEF0paCbnCWv65s25Xod4BSaXQam_bBCaDKRlmu8ShmQCsR5eAZk7ER-YmgYJ8kmk0K59fdPKElcMdxbN4NTbhZKfVqJ-wlk-oTYFWnxosG9V9Iz3VsCczaXH68",
  "priv": "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj9AQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVpbXF1eXw"
}
~~~

Flattened JWE JSON Serialization:

~~~ json
{
  "protected": "eyJhbGciOiJNTC1LRU0tNzY4K0ExOTJLVyIsImVuYyI6IkExOTJHQ00iLCJrZW1jdCI6\\\nIjkxc1BkTGNfRFpHNjhQVXcwV1ZkMFFIWTBaeXBaNnRBVDBDUVpCQ0hNaTZqenExQTVI\\\nX0FMWXBJN2hadTZOM0I0S3F1OXpiYnFyYVByZm0yTkdpX1JoWEdSV08ydVY4X1dlSnBl\\\nYnJLZ3o2ZDZuVG1SazY3d1NXdnRiSDRJMGVxUVk4MGIxUDdBaUE3d2pPTjlreS1pSUdk\\\nTFI5ZmdablNiTXI5ZktyajF0eWdvcHo4TVhzU2I5ekVaTDI4TzZJdzFwYXNwLXNMUlNJ\\\ncVlSMGF3Y2hyNV82Z01mczdLR19idU5UZU90ajM5SzN1ekpmdFVmNmtpZWNqbzBsbXI2\\\nX1BwN0xwZG9kTDBHYXplUHYzcEFEUGJpdEpmY2tsVU5pdTA4LW4ydDdzanJ3d0lsSDR1\\\nV2c4bHZ0WUFVN3ZHWTJmSmFtNDFsMmRBTGRtWWNVRUM0dWRlMjRSMVBzcmtXcXl2SzlF\\\nWE1SOXMyNFgzN093ZVUyQXVuWG1HSDBWbUdNeThaRXNOQ3BSVlAwVVRfS2VpaEpJSHBa\\\nbDBfckhHZU9ubmYxTmozSWRVYVhrdTNJNkc3VTJQaTlqT1hJQ1dyaEkzb3RQT2RLbUVZ\\\nZ1JuX3hSWG9RVFpMZlVvd2tfZ3FkTDFDNElCR3RVMlZ2U2FYMHhRMjdkN2xGbEVpVndi\\\nUHREU2NOSmJkNGxwQVZFbjVSWFlqS0d5ZzdVSFUzeHhvZzU1WEJXYmU4VVJMRnFFNi0z\\\nS1hHa1NBZGJrQ1EtVjJWMndOa3NYcGpGWFZYTGZuTTJ6YVJLMWNUWHotV0JTSzVsYk53\\\nVHNxZFhRZDJmYjRkZkJsVk9ocDBIRGpoaXRRQ0lWcTBPbC13TFdjYUZqa1VaQTFoTXNw\\\nT0hwZU5zWHl2MjItNWMtaV8zNHMtN0tudkNISXhBUEVJSHBLZS1DaDJ3QlRYaDloRzI5\\\nLUdZNkVJMEJjb3dNbTVTU1V0TUxmYVRQV0x1V0U3Vno5V1BqSnoyMzc0WGNqMm9DSW1z\\\neF9vc2NJYXpUdHFZaWYzMlAzRTlOMGE1eUZrY0RCSUdHdUZsSzAzZHZyUlhNLVlpeFZV\\\nWGFvanFWZEhPZ3ZjcWNKdEFtaXhJYnBkTWhteVA1TUFsRkN6Qi13cTkwWUNEdWMtVkpv\\\nd0FReV9vcERxT1p0WnpwakpNWVV6VktFUXo5OXlkS3diOG1Ldy1iY0ZwMXZkekkyenlD\\\nUWFkUE81VFNWazdCRklVX1IxMUNKTlVHZlVqcWhmNVJ4RkhUdzFESjI0a2V2UF9WRGFV\\\nNEZpVGs4ZTZJVWI5RGh1MG54el9oX013dEZKZzkxNUNaUFl1TlJVaE1wSkJuRHZzMm81\\\nd2NxelcwbTJHT2U1bWJjd1lkMmxCU192NGdyZ3FjNWVKNEkxUm54RmQ0T01qbUR5NGM4\\\nN2Y3bXQxMHRWM0MyU0hUZzJ2NkVGQ2VheDA0UDJZZFNYY0IxdlpWV1NtOEI3ZWFqcmtr\\\nMFczcjB2U0hKZ3hoWFBIV0piclh6blRFUjh3MnNrZGtUT3lMUXMwUi1aQ05aaHVwT3pf\\\naU5pX3NFRXlmbTQxSjhBMVZNVngwMkpLWERIalg4ZmdoRE5PVkRYRmtfTzdudjRlQ3do\\\ndXFwSllIdUtKaWJGMjlrRElJY1V2N1dwNTBiaTU5VE9OQnBlaTMxMi1SQS1PaS1FWDNt\\\nakY0SGpSd1h0VzZpcTZfWHlrNHZfZWtWVWdQdnJ3ZE13UUpFY1dZMWdhRmx2d09qYzEw\\\nNFhqejFvVUZYdzhoS21lY25vSkhwU2tUY1BxdVZfLTQ3Q0hjVFlCWmZCWkpPcG56OEwx\\\nUDhLWmRGZmp6Rk9lTTBpeW9GSS1VNkVTMW1YS3FhNmx6ZjBXVlhNR1JtVGFRLTJSamI3\\\naTdiTmNSOVNMazlxUTlhVTU4UWtjdE1jIn0",
  "encrypted_key": "y4wmof_bTqmjuLdqBgQwdO9jCX1eYh_o6ncBOKXSaMo",
  "aad": "ZXh0ZXJuYWwtYWFk",
  "iv": "sLGys7S1tre4ubq7",
  "ciphertext": "SrksVxZPdV0PSHzlGU6azIqgKCs",
  "tag": "KwMctpSu3DPyrR_H31P8ug"
}
~~~

## ML-KEM-1024+A256KW
{: numbered="false"}

Public JWK:

~~~ json
{
  "kty": "AKP",
  "alg": "ML-KEM-1024",
  "pub": "cDFjF2OKVJIUcTaxPMBc6aACVkhNYtG7HzmypKopCcqLpSEe1nqT6HBMPfWR9TkldKgA-fdm5YReC3yvjypN2ZKTd6ZXqZBNZjOQL8CM75XGz_ELStsOpxMvuNskEuJFG1S4W8amtRAjIUPDqIGqOHzGa5yiDleBo7M3mPFAKUdV6aMmrMGLNqe33PloN8SxDNu_a6xj76Ono_V5pRUSaONkZqBb6MKk_wsFRrvFyrRo-KEtmcIVD8YbPdenaqyxuxw4L6o1ShET62e-6MIU30li3wMuZ6K4xUsB_3xt9FAc7FaM2Du5uoCxQACzgGgnqpNqvbFWJ-uB1WOCYmGdByexy6GWyDaH8nuTa-aVmikyGLxq_CGwcJd1WcU2Tomnj6swt5GKwRSmnNSdVYa82MZ9WJpuLowORhaleoFMACcAuFc-1MqvJlTL6MhVrglReOQZyUoXsMBty2BWOxczQJdMz2lYm4srigmrvFt-2Ey8dvhiszqjHSesfspdxTRhRSOrBvNFacYGjkJN3Nu4KYiD9DSmBesLRRgxpKq8z1ia4rEjQNcUwhaULvhLiCVyU2FLM3BQeMOxlkw-DcysAZE3YxfD89aYDIc_mPAo7zRBXTBtmvlSecYoQIwlaKAHHigbt5iRFCuLV_lq9hJ8EQs4Nak55bVNjeAFhmiYiXF0TqZi0sI1FKQqITgoJMlPBrUZzLaAOGBzEnI8iKw_hMqtHUV_rsHNB5kzPgXCfucLcbSYvpWSr5p3yUye8keJCSLFlulBSkcyxXBh5mfMh7mGUChHfMsNHjzPdwmck7xyWoohSKQbXWV3AO0LmAMMena5WkG9hFeij2c4f5c5ViME3bHFMusb6KA1Oad1AfGYOxs3_Xp6YHFKWmQpgngXaHyiGqtRX6S9_lrBxXA2pDPIiqZwYDSq1kW_KUac8Ee5kmslu-e1o_wu56pGtnQn7ZEi93t-rHNXSCURZ1cs2rVSFBBzH3Stauo68NkktgguKAs8wJwPOOWzDiUGzXSGRXfHBCQrqWeCgUxrWEFBoINmgXRsV2q0l9O8B4Vz4oo4l3d9HOF8JWvDuEnMsSoCCrSwkkAUKBsMaKiXF7WSLBUwpKGYj1S9h_y8rhqlYFcbOgUucjA4V7mtqpWQhnYmuThCu_JUsnFAyUdJN0s5KYZfSCKhnHK2DhAiwcNloLOhKsXGmTtPk5WCFhUOsWWb2Nmi6lSUZceJfZgX2ZpGhlBFemibcsCVYQV5ghWGLboiyXsiS_ezs5qniDhVaTbJ0fR6kuS-o4ohuTeXiMJyoJOYwCWDiWe2i5Sv_AwVdnmgSOxxxEgrNTW-SAqTsLd50fqkQoVlTFFGEwdxwNxIGJiqP-CvMLNvjTs6eILNkAQRaIcDeppVccQ-nFkUv3OWcvp_NLsQOaUeKlskCSEEvpQ1K8xJ3ahU5HSt8Rg5OwwwrmeqOeUYtGhEy8dhUmAj_OOxPZuYOABNtelGVUu3UVka2RrOVIuY9AaMWUdNG1QWAtGZHsVoL-JbYLk75yFp-LQhRNIrKWUXIHVfS8d8SDythrTLD_Uz9oZqDmY_pPGkWdGcYMorJFlZeOpTmwKFVLvA05VfEwxH6SGYVIqP42dXfoENwPjEtBSGbdxuiUrDxChHkuh8HVBeZrETYAfN1UKgVBYsCTe4hjqbpvk2ypW9x7GhD6AfEIYJHGSM2XCBKsUoyeQqGdgeqtssIWV8W7EfIJoilFMyKmCS9Hk9qoQoT8oF6liu3TuZg7ycplyn6DdYXuDKCpfKUuNr7vi9l-ZHvDMLKRzNUvpuoaifM1YIe6U-DaCkaPtXOkCa54i8Cfib2XJUEaQx8VQOXekZQJxLZCCDhiotCauYTDmyvaV4JKkxNec5J9C8w5RKrnnAg4J64OUN1hnJ7aoK8VakCqBqKmCZ0KEGYVAl7hWN-JkxkakfbBB9AjeMLlS9m1G9AOXA9HuykSqi3GfGuZG_C9OvwowzgmBmlnop7eI3PpksdaM4p9SLbIvAtQZJ6GB7VYy1yrym1oMJLFjCWKqtAhiLFxoEOtdcNT7jeoGRi4wgEWAI-uYb_7RGJvCB9S0"
}
~~~

Private JWK:

~~~ json
{
  "kty": "AKP",
  "alg": "ML-KEM-1024",
  "pub": "cDFjF2OKVJIUcTaxPMBc6aACVkhNYtG7HzmypKopCcqLpSEe1nqT6HBMPfWR9TkldKgA-fdm5YReC3yvjypN2ZKTd6ZXqZBNZjOQL8CM75XGz_ELStsOpxMvuNskEuJFG1S4W8amtRAjIUPDqIGqOHzGa5yiDleBo7M3mPFAKUdV6aMmrMGLNqe33PloN8SxDNu_a6xj76Ono_V5pRUSaONkZqBb6MKk_wsFRrvFyrRo-KEtmcIVD8YbPdenaqyxuxw4L6o1ShET62e-6MIU30li3wMuZ6K4xUsB_3xt9FAc7FaM2Du5uoCxQACzgGgnqpNqvbFWJ-uB1WOCYmGdByexy6GWyDaH8nuTa-aVmikyGLxq_CGwcJd1WcU2Tomnj6swt5GKwRSmnNSdVYa82MZ9WJpuLowORhaleoFMACcAuFc-1MqvJlTL6MhVrglReOQZyUoXsMBty2BWOxczQJdMz2lYm4srigmrvFt-2Ey8dvhiszqjHSesfspdxTRhRSOrBvNFacYGjkJN3Nu4KYiD9DSmBesLRRgxpKq8z1ia4rEjQNcUwhaULvhLiCVyU2FLM3BQeMOxlkw-DcysAZE3YxfD89aYDIc_mPAo7zRBXTBtmvlSecYoQIwlaKAHHigbt5iRFCuLV_lq9hJ8EQs4Nak55bVNjeAFhmiYiXF0TqZi0sI1FKQqITgoJMlPBrUZzLaAOGBzEnI8iKw_hMqtHUV_rsHNB5kzPgXCfucLcbSYvpWSr5p3yUye8keJCSLFlulBSkcyxXBh5mfMh7mGUChHfMsNHjzPdwmck7xyWoohSKQbXWV3AO0LmAMMena5WkG9hFeij2c4f5c5ViME3bHFMusb6KA1Oad1AfGYOxs3_Xp6YHFKWmQpgngXaHyiGqtRX6S9_lrBxXA2pDPIiqZwYDSq1kW_KUac8Ee5kmslu-e1o_wu56pGtnQn7ZEi93t-rHNXSCURZ1cs2rVSFBBzH3Stauo68NkktgguKAs8wJwPOOWzDiUGzXSGRXfHBCQrqWeCgUxrWEFBoINmgXRsV2q0l9O8B4Vz4oo4l3d9HOF8JWvDuEnMsSoCCrSwkkAUKBsMaKiXF7WSLBUwpKGYj1S9h_y8rhqlYFcbOgUucjA4V7mtqpWQhnYmuThCu_JUsnFAyUdJN0s5KYZfSCKhnHK2DhAiwcNloLOhKsXGmTtPk5WCFhUOsWWb2Nmi6lSUZceJfZgX2ZpGhlBFemibcsCVYQV5ghWGLboiyXsiS_ezs5qniDhVaTbJ0fR6kuS-o4ohuTeXiMJyoJOYwCWDiWe2i5Sv_AwVdnmgSOxxxEgrNTW-SAqTsLd50fqkQoVlTFFGEwdxwNxIGJiqP-CvMLNvjTs6eILNkAQRaIcDeppVccQ-nFkUv3OWcvp_NLsQOaUeKlskCSEEvpQ1K8xJ3ahU5HSt8Rg5OwwwrmeqOeUYtGhEy8dhUmAj_OOxPZuYOABNtelGVUu3UVka2RrOVIuY9AaMWUdNG1QWAtGZHsVoL-JbYLk75yFp-LQhRNIrKWUXIHVfS8d8SDythrTLD_Uz9oZqDmY_pPGkWdGcYMorJFlZeOpTmwKFVLvA05VfEwxH6SGYVIqP42dXfoENwPjEtBSGbdxuiUrDxChHkuh8HVBeZrETYAfN1UKgVBYsCTe4hjqbpvk2ypW9x7GhD6AfEIYJHGSM2XCBKsUoyeQqGdgeqtssIWV8W7EfIJoilFMyKmCS9Hk9qoQoT8oF6liu3TuZg7ycplyn6DdYXuDKCpfKUuNr7vi9l-ZHvDMLKRzNUvpuoaifM1YIe6U-DaCkaPtXOkCa54i8Cfib2XJUEaQx8VQOXekZQJxLZCCDhiotCauYTDmyvaV4JKkxNec5J9C8w5RKrnnAg4J64OUN1hnJ7aoK8VakCqBqKmCZ0KEGYVAl7hWN-JkxkakfbBB9AjeMLlS9m1G9AOXA9HuykSqi3GfGuZG_C9OvwowzgmBmlnop7eI3PpksdaM4p9SLbIvAtQZJ6GB7VYy1yrym1oMJLFjCWKqtAhiLFxoEOtdcNT7jeoGRi4wgEWAI-uYb_7RGJvCB9S0",
  "priv": "MDEyMzQ1Njc4OTo7PD0-P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ubw"
}
~~~

Flattened JWE JSON Serialization:

~~~ json
{
  "protected": "eyJhbGciOiJNTC1LRU0tMTAyNCtBMjU2S1ciLCJlbmMiOiJBMjU2R0NNIiwia2VtY3Qi\\\nOiJiSk1KZ3pUVk5DNEZIQ1VjRHBMSWw1ZjVmR0pKbVhNRVRHUWF0WUM3TFMzRGIxTkpU\\\nVTEzYVZGb0QwcUhoV0tOMVJtVFo1Y05FanFzRm9VTkNjV0NLZlpCQ0hOTVdHRkk2bXl2\\\nX1czZXc1Q3FSRFF2QUtXNHpKOVhxR29VMnFiVGlUc2plSFptN2JDNWd5WDc5R1g0WFQ1\\\nZWtzQjFqSnE4NGl5SHpUaEhDMVhlcFJIMy1LU3hPd04tTlowQWZub2dtNnZLVm1iNGtu\\\nZzFrVlgtenBjbHNteXVvSWEwNVVpZWxfdnpxM0FhZnJ6OTBnem1TbmhUQmRJcEFELVkz\\\nNTJxMTZ1dy1UR0ljZkh5cW5BR0RQR2tQVjNaMkRfYkRTcWhldGZKb0tKaEVxS21OV2xr\\\nOS1ZdC03XzlMLWZxZWgydXIxeGhtOURVQUh3a0dDTUJhckFMV2JGMzl4WmljVjFIMzdl\\\naVdYWkt6azlaLW1yYkhUT3hWVGwwNWl1a21rRm9ZZFpmOVhBdTE2ejlZX2d6ZTBpVS14\\\nd3FNTE1VU3pCcVlDWWZBTE5lTTVCWC11cXZ2VEoyTkxIcnJfR21JcVh3ZjJ5bGxnMkh4\\\nU3VQMVBvaG5uNE9yVGU2VFAtb0M4Rmtsakg4WTc3WUxzUmhZWDhHbmV3VnFQMXFvbkha\\\nWlhISnc1dHhDaW5RckZrTmVoWUg5S3RseUUyUjBmdXI3VzhfYW9RVFVyOXMzeHFVU0tz\\\nT3dnTXVtMk9sTDNtRldBV1AtTE41N2xrUnlIZ0cxTVlPTzRqRjNuOVFMZU0zX2QyRnA3\\\nWFJkZEhNd1E5OVlpWWFMM2ZqWUtKYnJYUVRYZzBjaGRxaEhRdV93d1ZhOWJ3dFMySVpq\\\nWWx0VUREbXhxMy1xSll4cnF0QW52RWtQXzdENjllQ3V1cElnS2VJMjFiV0RRYVNqV1do\\\nQVVJWGxDcHo2aUFwMzZ1Q0kwcFlqN3UwMV9lTHdwbTVCRTB0Vzc2UGJRQlFiOGE2b2E1\\\nY1Y3WXdfeElrNm52bmFqUnp3WldtSG5EWVZ2OUFVdElQcHlfQWlmQ3lZVHBNV1lUcERX\\\nMzhWcGJHTXlaWU9ZV1c2SFk5Sk0yaWNlYWxtRGhqWGNDYW1OTGcyd0NJUE9MMkdWUDVv\\\nYVA4QzlGX0F1b29iSFdhRl9JOHNZQ243MmV3b2I1Qm84Ync5Q2dIOHpWN2dOMVJ1UE1T\\\nUUhiNG5zMlFFX0ZqWktIczhSV1dWd3RBdmhUUEFlbl9DeVMzNWZneFdSZXhpa1pTazhX\\\nSmhhS2IwdFRSc0NTeEp3N29rNUJmVzF5YmNOSVl2YmNCbXctaDJCRTRqLU1WbmtUVGJm\\\najBwOFRjdlZPcm1YZi05eXV2MUFjX2ZJN1hIakxfQ0RqbzlrZDJFMXZBblFxVzRSZkRy\\\nMk4wVHVvSUNkTVJ3a2pQclAwOFZidG02MTVSWVFsMHNKdXdSMFNoNG9sVTA0ZWlmMGxL\\\ndVBfdDdDYmFpajlYZnZFd1prckRiMHFnc1pDYXJHY2ZncUkyTGNRUVdvbkVvdzhjdWdS\\\nUW5ycVNockhQaktscUFORFdwWTVRT2pXMGRRTXJpUjNXcEtTRnA1MXZ5aWRyY2UteDNO\\\nUDhYaFprVGdMWEw1aW1NT0dsTWxFeDdkV2pLcXA4a0FNcjhfYU45TVEyUjJkWFBEc21k\\\nWnNJWFh4aUdnSFhxNWtOZWR5WXNpSUVrejlsUmJpUlVrU3VQcFI1XzNFQVIzWEJTcmsz\\\naHNpVHJiUjJiNDgxLVgxWHFzcmJiUkVUUENBUmZUNDhYeDd1ZXR6YUk4U1BOQnpIb2wz\\\ndE45WDJkWXZoZWk4MVBwRFdtMmw0TXg1NGNIOGlMZEx1NDl5dTh0VjhJSEtXWUpIcS1s\\\nYzRsTU56ei1sSlphU3czb0ZtVjVnWldOQ1JWYlRVWlV4b0I4NndvamZFd0Y2OUJNbHlu\\\nTExneUJQYkI1ejVTODJTMHNqVkhPUkdNVkNIdzBNMnJKZmN0LXByZGpUWmRGTXU5dW1t\\\nUmV5cmlkcWdxTS1udUhacEtZN2p5eTZ3Rzd1WXpuZ2ptSlhxVUtLRlFncTdDSVl3Q1F3\\\neUJSWEVGcjFEUXpjTW5YM2JWbWtQUF9BUGVEUGFybEpCSjNOVG11WGFLQ1dNMGZudHAx\\\nbHo5UUQ1VnhacjJ1NTVuMjNDSFNmcmRjb1B4MUkwcDJ4OUxTbncyakdSQ2JKUU5qeHR1\\\nQWpmc1BYWl92aEUzSzhwYzdhdUlqbHEtVDJiVmd2bVltSk53azg0bWhib2hPZ3c5a1pt\\\nd2JEVWtQbVRnQ2ljMnEwWkdNRVkzU1hycWNwUGFDNG5ORF8yTFVrSFFVRkktU2p2VzlT\\\ndi1LT1BoMmV5OUVBVktDdzFVWnpJV2xsa0tqcnlURXFucVJ2eHhKM3FPVnJPd3ZuVGho\\\nRFY2TmN1RERHdlBhMHM2UEY4SDhtUEJKV2dPcllVUXBNWEpNdngteUJTMmVfMzNTX1pK\\\nVEF4RFFvNE9SZFk0c3dLV3V1cFJ0YVdzWGZkdEZNUm5NaHlnVFBPWHd4UDZBQ0lFWGll\\\neTM3Mmp3dVVoMEo3ZHpndlpFMUJrS01DVjFaUGJ4NDhhZXo5X1RoX2Qwa0pEOWZxQTNt\\\nZkRDemZOdFFHRVNLdXJ3MXoxUXpTT0ItR2c0d29ycjBFdnNTRmZqTjVBaWZNLVozRkNX\\\nbEVWZUlsOGw3blh6bXNCNlB4RE16OXllX296WExUM2F5SVM0SVhyUDJaWFc0cEdkWTJ0\\\nSmMifQ",
  "encrypted_key": "DVOhPU21CuUajdOnwCk1jmejdipeDMDhhbaZPmFrFh5VaHlWJ1dlQA",
  "aad": "ZXh0ZXJuYWwtYWFk",
  "iv": "sLGys7S1tre4ubq7",
  "ciphertext": "3eFYygOCnqfnw-jJzmOoB2ieHG4",
  "tag": "rxI3XvqGAbQC9cnLJaQ8jQ"
}
~~~

