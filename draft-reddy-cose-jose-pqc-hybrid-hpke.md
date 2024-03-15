---
title: "PQ/T Hybrid KEM: HPKE with JOSE/COSE"
abbrev: "PQ/T Hybrid KEM: HPKE with JOSE/COSE"
category: std

docname: draft-reddy-cose-jose-pqc-hybrid-hpke
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
 - JOSE
 - Hybrid
 - HPKE

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


 
normative:

informative:
 
  FIPS203-ipd:
     title: "Module-Lattice-based Key-Encapsulation Mechanism Standard"
     target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.ipd.pdf
     date: false
  HPKE-IANA:
     author:
        org: IANA
     title: Hybrid Public Key Encryption (HPKE) IANA Registry
     target: https://www.iana.org/assignments/hpke/hpke.xhtml
     date: false

     
--- abstract

This document outlines the construction of a PQ/T Hybrid Key Encapsulation Mechanism (KEM) in Hybrid Public-Key Encryption (HPKE) for integration with JOSE and COSE. It specifies the utilization of both traditional and Post-Quantum Cryptography (PQC) algorithms, referred to as PQ/T Hybrid KEM, within the context of JOSE and COSE.

--- middle

# Introduction

The migration to Post-Quantum Cryptography (PQC) is unique in the history of modern digital cryptography in that neither the traditional algorithms nor the post-quantum algorithms are fully trusted to protect data for the required data lifetimes. The traditional algorithms, such as RSA and elliptic curve, will fall to quantum cryptalanysis, while the post-quantum algorithms face uncertainty about the underlying mathematics, compliance issues, unknown vulnerabilities, hardware and software implementations that have not had sufficient maturing time to rule out classical cryptanalytic attacks and implementation bugs.

During the transition from traditional to post-quantum algorithms, there is a desire or a requirement for protocols that use both algorithm types. Hybrid key exchange refers to using multiple key exchange algorithms simultaneously and combining the result with the goal of providing security even if all but one of the component algorithms is broken. It is motivated by transition to post-quantum cryptography. 

HPKE offers a variant of public-key encryption of arbitrary-sized plaintexts for a recipient public key. The specifications for the use of HPKE with JOSE and COSE are described in {{?I-D.rha-jose-hpke-encrypt}} and {{?I-D.ietf-cose-hpke}}, respectively. HPKE can be extended to support PQ/T Hybrid KEM as defined in {{?I-D.connolly-cfrg-xwing-kem}}. This specification defines PQ/T Hybrid KEM in HPKE for use with JOSE and COSE. 

# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document makes use of the terms defined in {{?I-D.ietf-pquip-pqt-hybrid-terminology}}. For the purposes of this document, it is helpful to be able to divide cryptographic algorithms into two classes:

"Traditional Algorithm":  An asymmetric cryptographic algorithm based on integer factorisation, finite field discrete logarithms, elliptic curve discrete logarithms, or related mathematical problems. In the context of JOSE, examples of traditional key exchange algorithms include Elliptic Curve Diffie-Hellman Ephemeral Static {{?RFC6090}} {{?RFC8037}}. In the context of COSE, examples of traditional key exchange algorithms include Ephemeral-Static (ES) DH and Static-Static (SS) DH {{?RFC9052}}. 

"Post-Quantum Algorithm":  An asymmetric cryptographic algorithm that is believed to be secure against attacks using quantum computers as well as classical computers. Examples of PQC key exchange algorithms include ML-KEM.

"Post-Quantum Traditional (PQ/T) Hybrid Scheme":  A multi-algorithm scheme where at least one component algorithm is a post-quantum algorithm and at least one is a traditional algorithm.

"PQ/T Hybrid Key Encapsulation Mechanism":  A multi-algorithm KEM made up of two or more component KEM algorithms where at least one is a post-quantum algorithm and at least one is a traditional algorithm.

# Construction

ML-KEM is a one-pass (store-and-forward) cryptographic mechanism for an originator to securely send keying material to a recipient using the recipient's ML-KEM public key. Three parameters sets for ML-KEMs are specified by {{FIPS203-ipd}}. In order of increasing security strength (and decreasing performance), these parameter sets
are ML-KEM-512, ML-KEM-768, and ML-KEM-1024. {{?I-D.connolly-cfrg-xwing-kem}} uses a multi-algorithm scheme,
where one component algorithm is a post-quantum algorithm and another one is a traditional algorithm. The Combiner function defined in Section 5.3 of {{?I-D.connolly-cfrg-xwing-kem}} combines the output of a post-quantum KEM and a traditional KEM to generate a single shared secret.

# Ciphersuite Registration

This specification registers a number of PQ/T Hybrid KEMs for use with HPKE. A ciphersuite is thereby a combination of several algorithm configurations:

- HPKE Mode
- KEM algorithm (Traditional Algorithm + PQ KEM, for example, X25519Kyber768)
- KDF algorithm
- AEAD algorithm

The "KEM", "KDF", and "AEAD" values are conceptually taken from the HPKE IANA registry {{HPKE-IANA}}. Hence, JOSE and COSE cannot use an algorithm combination that is not already available with HPKE.

The HPKE PQ/T hybrid ciphersuites for JOSE and COSE are defined in {{IANA}}.

# Security Considerations

The shared secrets computed in the hybrid key exchange should be computed in a way that achieves the "hybrid" property: the resulting secret is secure as long as at least one of the component key exchange algorithms is unbroken. PQC KEMs used in the manner described in this document MUST explicitly be designed to be secure in the event that the public key is reused, such as achieving IND-CCA2 security. ML-KEM has such security properties.

# IANA Considerations {#IANA}

## JOSE

This document requests IANA to add new values to the "JSON Web Signature and Encryption Algorithms" registry.

## JOSE Algorithms Registry 

- Algorithm Name: HPKE-Base-X25519Kyber768-SHA256-AES256GCM
- Algorithm Description: Cipher suite for JOSE-HPKE in Base Mode that uses the X25519Kyber768Draft00 Hybrid 
  KEM, the HKDF-SHA256 KDF, and the AES-256-GCM AEAD.
- Algorithm Usage Location(s): "alg, enc"
- JOSE Implementation Requirements: Optional
- Change Controller: IANA
- Specification Document(s): [[TBD: This RFC]]
- Algorithm Analysis Documents(s): TODO

- Algorithm Name: HPKE-Base-X25519Kyber768-SHA256-ChaCha20Poly1305
- Algorithm Description: Cipher suite for JOSE-HPKE in Base Mode that uses the X25519Kyber768Draft00 Hybrid  
   KEM, the HKDF-SHA256 KDF, and the ChaCha20Poly1305 AEAD.
- Algorithm Usage Location(s): "alg, enc"
- JOSE Implementation Requirements: Optional
- Change Controller: IANA
- Specification Document(s): [[TBD: This RFC]]
- Algorithm Analysis Documents(s): TODO

## COSE

This document requests IANA to add new values to the 'COSE Algorithms' registry.

### COSE Algorithms Registry 

*  Name: HPKE-Base-X25519Kyber768-SHA256-AES256GCM
*  Value: TBD1 
*  Description: Cipher suite for JOSE-HPKE in Base Mode that uses the X25519Kyber768Draft00 Hybrid KEM, the  
   HKDF-SHA256 KDF, and the AES-256-GCM AEAD.
*  Capabilities: [kty]
*  Change Controller: IANA
*  Reference: [[TBD: This RFC]]

*  Name: HPKE-Base-X25519Kyber768-SHA256-ChaCha20Poly1305
*  Value: TBD2
*  Description: Cipher suite for JOSE-HPKE in Base Mode that uses the X25519Kyber768Draft00 Hybrid      
   KEM, the HKDF-SHA256 KDF, and the ChaCha20Poly1305 AEAD.
*  Capabilities: [kty]
*  Change Controller: IANA
*  Reference: [[TBD: This RFC]]

# Acknowledgments
{: numbered="false"}

Thanks to Ilari Liusvaara for the discussion and comments.