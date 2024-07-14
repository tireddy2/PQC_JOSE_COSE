---
title: "Post-Quantum Key Encapsulation Mechanisms (PQ KEMs) for JOSE and COSE"
abbrev: "PQ KEM for JOSE and COSE"
category: std

docname: draft-reddy-cose-jose-pqc-kem
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
    city: Munich
    country: Germany
    email: "aritra.banerjee@nokia.com"
 -
    fullname: Hannes Tschofenig
    organization:
    city:
    country: Germany
    email: "hannes.tschofenig@gmx.net"
 
normative:
  RFC2119:
  RFC8174:
  RFC7516:
  JOSE-IANA:
     author:
        org: IANA
     title: JSON Web Signature and Encryption Algorithms
     target: https://www.iana.org/assignments/jose/jose.xhtml


informative:
  FIPS204:
     title: "FIPS 203 (Initial Public Draft): Module-Lattice-based Key-Encapsulation Mechanism Standard"
     target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.ipd.pdf
     date: false
 
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
  FIPS203-ipd:
     title: "Module-Lattice-based Key-Encapsulation Mechanism Standard"
     target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.ipd.pdf
     date: false 
     
--- abstract

This document describes the conventions for using Post-Quantum Key Encapsulation Mechanisms (PQ-KEMs) within JOSE and COSE. 

--- middle

# Introduction

Quantum computing is no longer perceived as a conjecture of computational sciences and theoretical physics.  Considerable research efforts and enormous corporate and government funding for the development of practical quantum computing systems are being invested currently. As such, as quantum technology advances, there is the potential for future quantum computers to have a significant impact on current cryptographic systems. 

Researchers have developed Post-Quantum Key Encapsulation Mechanisms (PQ-KEMs) to provide secure key establishment resistant against an adversary with access to a quantum computer.

As the National Institute of Standards and Technology (NIST) is still in the process of selecting the new post-quantum cryptographic algorithms that are secure against both quantum and classical computers, the purpose of this document is to propose a PQ-KEMs to protect the confidentiality of content encrypted using JOSE and COSE against the quantum threat.

Although this mechanism could thus be used with any PQ-KEM, this document focuses on Module-Lattice-based Key Encapsulation Mechanisms (ML-KEMs). ML-KEM is a one-pass (store-and-forward) cryptographic mechanism for an originator to securely send keying material to a recipient
using the recipient's ML-KEM public key. Three parameters sets for ML-KEMs are specified by {{FIPS203-ipd}}. In order of increasing security strength (and decreasing performance), these parameter sets
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

## Key Encapsulation Mechanisms

For the purposes of this document, we consider a Key Encapsulation Mechanism (KEM) to be any asymmetric cryptographic scheme comprised of algorithms satisfying the following interfaces {{PQCAPI}}.  

* def kemKeyGen() -> (pk, sk)
* def kemEncaps(pk) -> (ct, ss)
* def kemDecaps(ct, sk) -> ss

where pk is public key, sk is secret key, ct is the ciphertext representing an encapsulated key, and ss is shared secret.

KEMs are typically used in cases where two parties, hereby refereed to as the "encapsulater" and the "decapsulater", wish to establish a shared secret via public key cryptography, where the decapsulater has an asymmetric key pair and has previously shared the public key with the encapsulater.
  
# Design Rationales {#rational}

Section 4.6 of the JSON Web Algorithms (JWA) specification, see {{?RFC7518}}, defines two ways of using a key agreement:

- When Direct Key Agreement is employed, the shared secret established through the Traditional Algorithm will be the content encryption key (CEK).
- When Key Agreement with Key Wrapping is employed, the shared secret established through the Traditional Algorithm will wrap the CEK.

For efficient use with multiple recipient the key wrap approach is used since the content can be encrypted once with the CEK but each CEK is encrypted per recipient. Similarly, Section 8.5.4 and Section 8.5.5 of COSE {{?RFC9052}} define the Direct Key Agreement and Key Agreement with Key Wrap, respectively. This document proposes the use of PQ-KEMs for these two modes.

It is essential to note that in the PQ-KEM, one needs to apply Fujisaki-Okamoto {{FO}} transform or its variant {{HHK}} on the PQC KEM part to ensure that the overall scheme is IND-CCA2 secure, as mentioned in {{?I-D.ietf-tls-hybrid-design}}. The FO transform is performed using the KDF such that the PQC KEM shared secret achieved is IND-CCA2 secure. As a consequence, one can re-use PQC KEM public keys but there is an upper bound that must be adhered to.

Note that during the transition from traditional to post-quantum algorithms, there may be a desire or a requirement for protocols that incorporate both types of algorithms until the post-quantum algorithms are fully 
trusted. HPKE {{?RFC9180}} is a KEM that can be extended to support hybrid post-quantum KEMs and the specification for the use of PQ/T Hybrid Key Encapsulation Mechanism (KEM) in Hybrid Public-Key Encryption (HPKE) for integration with JOSE and COSE is described in {{?I-D.reddy-cose-jose-pqc-hybrid-hpke}}.

# KEM PQC Algorithms

The National Institute of Standards and Technology (NIST) started a process to solicit, evaluate, and standardize one or more quantum-resistant public-key cryptographic algorithms, as seen [here](https://csrc.nist.gov/projects/post-quantum-cryptography). Said process has reached its [first announcement](https://csrc.nist.gov/publications/detail/nistir/8413/final) in July 5, 2022, which stated which candidates to be standardized for KEM:

* Key Encapsulation Mechanisms (KEMs): ML-KEM [FIPS204], previously known as Kyber, is a module learning with errors (MLWE)-based KEM. Three security levels have been defined in the NIST PQC Project, namely Level 1, 3, and 5. These levels correspond to the hardness of breaking AES-128, AES-192 and AES-256, respectively.

NIST announced as well that they will be [opening a fourth round](https://csrc.nist.gov/csrc/media/Projects/post-quantum-cryptography/documents/round-4/guidelines-for-submitting-tweaks-fourth-round.pdf) to standardize an alternative KEM, and a [call](https://csrc.nist.gov/csrc/media/Projects/pqc-dig-sig/documents/call-for-proposals-dig-sig-sept-2022.pdf) for new candidates for a post-quantum signature algorithm.

## ML-KEM

ML-KEM offers several parameter sets with varying levels of security and performance trade-offs. This document specifies the use of the ML-KEM algorithm at three security levels: ML-KEM-512, ML-KEM-768, and ML-KEM-1024. ML-KEM key generation, encapsulation and decaspulation functions are defined in [FIPS204]. The main security property for KEMs standardized in the NIST Post-Quantum Cryptography Standardization Project is indistinguishability under adaptive chosen ciphertext attacks (IND-CCA2) (see Section 10.2 of {{?I-D.ietf-pquip-pqc-engineers}}). The public/private key sizes, ciphertext key size, and PQ security levels of ML-KEM are detailed in Section 12 of {{?I-D.ietf-pquip-pqc-engineers}}.

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

TBD: ML-KEM can be used directly without HPKE. However, HPKE with ML-KEM is specifically discussed in the document draft-connolly-cfrg-hpke-mlkem. Specifications like TLS (draft-connolly-tls-mlkem-key-agreement) and IKEv2 (draft-kampanakis-ml-kem-ikev2) utilize ML-KEM directly, without employing HPKE with ML-KEM.

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

The key derivation for JOSE is performed using the KMAC defined in NIST SP 800-56Cr2 [SP800-56C]. The KMAC(K, X, L, S) parameters are instantiated as follows:

   *  K: the input key-derivation key. In this document this is the initial shared secret (SS') outputted from the 
      kemEncaps() or kemDecaps() functions.

   *  X: JOSE context-specific data defined in Section 4.6.2 of {{?RFC7518}}, i.e., concat(AlgorithmID, PartyUInfo, PartyVInfo, 
      SuppPubInfo, SuppPrivInfo).

   *  L: length of the output key in bits and it would be set to match the length of the key required for the AEAD operation.

   *  S: the optional customization label. In this document this parameter is unused, that is it is the zero-length string "".

For all security levels of ML-KEM, KMAC256 is used.

## Key Derivation for COSE

The key derivation for COSE is performed using the KMAC defined in NIST SP 800-56Cr2 [SP800-56C]. The KMAC(K, X, L, S) parameters are instantiated as follows:

   *  K: the input key-derivation key. In this document this is the initial shared secret (SS') outputted from the 
      kemEncaps() or kemDecaps() functions.

   *  X: The context structure defined in Section 5.2 of {{?RFC9053}}.

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

* The usage for the "alg" and "enc" header parameters remain the same as in JWE {{RFC7516}}: both header parameters, "alg" and "enc", MUST be placed in the JWE Protected Header. Subsequently, the plaintext will be encrypted using the CEK, as detailed in Step 15 of Section 5.1 of {{RFC7516}}. 

* The JWE Encrypted Key MUST include the output ('ct') from the PQ-KEM algorithm, encoded using base64url. In the JWE Compact Serialization, it avoids double base64url encoding.

* The recipient MUST base64url decode the ciphertext from the JWE Encrypted Key and then use it to derive the CEK using the process defined in {{decrypt}}. 

*  The JWE Encrypted Key MUST be absent.

## Key Agreement with Key Wrapping

* The derived key is generated using the process explained in {{encrypt}} and used to encrypt the CEK. 

* The parameter "ek" MUST include the output ('ct') from the PQ-KEM algorithm, encoded using base64url.

* The JWE Encrypted Key MUST include the base64url-encoded encrypted CEK. 

* The 'enc' (Encryption Algorithm) header parameter MUST specify a content encryption algorithm from the JSON Web Signature and Encryption Algorithms registry, as defined in {{JOSE-IANA}}.

* The recipient MUST base64url decode the ciphertext from "ek". Subsequently, it is used to derive the key, through the process defined in {{decrypt}}. The derived key will then be used to decrypt the CEK.

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
 | MLKEM512                      | ML-KEM-512                        |
 +===============================+===================================+
 | MLKEM768                      | ML-KEM-768                        |
 +===============================+===================================+
 | MLKEM1024                     | ML-KEM-1024                       |
 +===============================+===================================+
~~~
{: #direct-table title="Direct Key Agreement: Algorithms."}

* In Key Agreement with Key Wrapping, the parameter "alg" MUST be specified, and its value MUST be one of the values specified in the table {{keywrap-table}}.

~~~
 +=================================+===================================+
 | alg                             | Description                       |
 +=================================+===================================+
 | MLKEM512-AES128KW               | ML-KEM-512 + AES128KW             |
 +=================================+===================================+
 | MLKEM768-AES192KW               | ML-KEM-768 + AES192KW             |
 +=================================+===================================+
 | MLKEM1024-AES256KW              | ML-KEM-1024 + AES256KW            |
 +=================================+===================================+
~~~
{: #keywrap-table title="Key Agreement with Key Wrapping: Algorithms."}

# COSE Ciphersuite Registration {#COSE-PQ-KEM}

{{mapping-table}} maps the JOSE algorithm names to the COSE algorithm values (for the PQ-KEM ciphersuites defined by this document).

~~~
+===============================+=========+===================================+=============+
| JOSE                          | COSE ID | Description                       | Recommended |
+===============================+=========+===================================+=============+
| MLKEM512                      | TBD1    | ML-KEM-512                        | No          |
+-------------------------------+---------+-----------------------------------+-------------+
| MLKEM768                      | TBD2    | ML-KEM-768                        | No          |
+-------------------------------+---------+-----------------------------------+-------------+
| MLKEM1024                     | TBD3    | ML-KEM-1024                       | No          |
+-------------------------------+---------+-----------------------------------+-------------+
| MLKEM512+AES128KW             | TBD4    | ML-KEM-512  + AES128KW            | No          |
+-------------------------------+---------+-----------------------------------+-------------+
| MLKEM768+AES192KW             | TBD5    | ML-KEM-768  + AES192KW            | No          |
+-------------------------------+---------+-----------------------------------+-------------+
| MLKEM1024+AES256KW            | TBD6    | ML-KEM-1024  + AES256KW           | No          |
+-------------------------------+---------+-----------------------------------+-------------+
~~~
{: #mapping-table title="Mapping between JOSE and COSE PQ-KEM Ciphersuites."}

# Security Considerations

PQC KEMs used in the manner described in this document MUST explicitly be designed to be secure in the event that the public key is reused, such as achieving IND-CCA2 security. ML-KEM has such security properties.

# IANA Considerations {#IANA}

## JOSE

The following entries are added to the "JSON Web Signature and Encryption Algorithms" registry:

- Algorithm Name: MLKEM512
- Algorithm Description: PQ-KEM that uses ML-KEM-512 PQ-KEM.
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IANA
- Specification Document(s): [[TBD: This RFC]]
- Algorithm Analysis Documents(s): TODO

- Algorithm Name: MLKEM768
- Algorithm Description: PQ-KEM that uses ML-KEM-768 PQ-KEM.
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IANA
- Specification Document(s): [[TBD: This RFC]]
- Algorithm Analysis Documents(s): TODO

- Algorithm Name: MLKEM1024
- Algorithm Description: PQ-KEM that uses ML-KEM-1024 PQ-KEM.
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IANA
- Specification Document(s): [[TBD: This RFC]]
- Algorithm Analysis Documents(s): TODO

- Algorithm Name: MLKEM512+A128KW
- Algorithm Description: PQ-KEM that uses ML-KEM-512 PQ-KEM and CEK wrapped with "A128KW".
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IANA
- Specification Document(s): [[TBD: This RFC]]
- Algorithm Analysis Documents(s): TODO

- Algorithm Name: MLKEM768+A192KW
- Algorithm Description: PQ-KEM that uses ML-KEM-768 and CEK wrapped with "A192KW".
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IANA
- Specification Document(s): [[TBD: This RFC]]
- Algorithm Analysis Documents(s): TODO

- Algorithm Name: MLKEM1024+A256KW
- Algorithm Description: PQ-KEM that uses ML-KEM-1024 and CEK wrapped with "A256KW".
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IANA
- Specification Document(s): [[TBD: This RFC]]
- Algorithm Analysis Documents(s): TODO

## COSE

The following has to be added to the "COSE Algorithms" registry:

- Name: MLKEM512
- Value: TBD1
- Description: PQ-KEM that uses ML-KEM-512 PQ-KEM.
- Capabilities: [kty]
- Change Controller: IANA
- Reference: This document (TBD)
- Recommended: No

- Name: MLKEM768
- Value: TBD2
- Description: PQ-KEM that uses ML-KEM-768 PQ-KEM.
- Capabilities: [kty]
- Change Controller: IANA
- Reference: This document (TBD)
- Recommended: No

- Name: MLKEM1024
- Value: TBD3
- Description: PQ-KEM that uses ML-KEM-1024 PQ-KEM.
- Capabilities: [kty]
- Change Controller: IANA
- Reference: This document (TBD)
- Recommended: No

- Name: MLKEM512+A128KW
- Value: TBD4
- Description: PQ-KEM that uses ML-KEM-512 PQ-KEM and CEK wrapped with "A128KW".
- Capabilities: [kty]
- Change Controller: IANA
- Reference: This document (TBD)
- Recommended: No

- Name: MLKEM768+192KW
- Value: TBD5
- Description: PQ-KEM that uses ML-KEM-768 and CEK wrapped with "A192KW".
- Capabilities: [kty]
- Change Controller: IANA
- Reference: This document (TBD)
- Recommended: No

- Name: MLKEM1024+A256KW
- Value: TBD6
- Description: PQ-KEM that uses ML-KEM-1024 and CEK wrapped with "A256KW".
- Capabilities: [kty]
- Change Controller: IANA
- Reference: This document (TBD)
- Recommended: No


# Acknowledgments
{: numbered="false"}

Thanks to Ilari Liusvaara, Neil Madden and AJITOMI Daisuke for the discussion and comments.
