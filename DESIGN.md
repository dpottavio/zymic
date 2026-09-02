# Zymic AEAD Stream Format

*Format version 2*

Zymic is a stream-oriented encryption format designed for secure
storage of data at rest. It employs Authenticated Encryption with
Associated Data (AEAD) to ensure both the confidentiality and
integrity of the data. This document defines the structure, key
derivation, encoding, and decoding procedures that comprise the Zymic
format.

## Definition of Terms

AAD -- Additional Authenticated Data. Data that is in plaintext form
but authenticated by an AEAD cipher.

AEAD -- Authenticated Encryption with Associated Data. A cipher design
that achieves confidentiality and authenticity of encrypted data.

Authentication Tag -- An authentication value produced by an AEAD
cipher and used to verify the authenticity of encrypted data.

Ciphertext -- The encrypted output of a plaintext message, produced by
an encryption algorithm.

CSPRNG -- Cryptographically Secure Pseudorandom Number Generator. An
algorithm that produces values suitable for cryptographic use.

KDF -- Key Derivation Function. A cryptographic algorithm used to
derive one or more encryption keys from a source key or secret.

KDK -- Key Derivation Key. A key used for deriving other encryption
keys.

MAC -- Message Authentication Code. A keyed authentication value used
to confirm the authenticity of data.

Plaintext -- The original, unencrypted data input to an encryption
algorithm.

## Overview

Zymic is an AEAD stream protocol designed to secure plaintext
data. The protocol operates by dividing plaintext into discrete
segments, each of which is independently encrypted using an AEAD
cipher and the Stream's Data Key.

Each encrypted segment produces a ciphertext and an accompanying
Authentication Tag. These are encapsulated into binary structures
known as Frames. A series of these Frames, in order, constitutes a
Stream.

Each Stream is encrypted using a unique Data Key -- a symmetric key
derived from a higher-level Parent Key using a KDF. The Parent Key,
also known as the KDK, is not directly used for encryption but serves
as the root material from which Data Keys are generated.

Streams are strictly ordered: Frames must appear in their original
sequence and any reordering or removal can be detected. Each Stream
begins with a Header, a block of metadata bound to the Frame sequence
through authenticated key derivation. The Header and its associated
Frames together form a complete encrypted Stream.

Streams are immutable. Once a Stream has been encoded, its Header and
Frames MUST NOT be modified. Any change to the plaintext MUST be
encoded as a new Stream.

```
<--------------- Stream ---------------->

+--------+---------+---------+---------+
| Header | Frame 1 | Frame 2 | Frame 3 |
+--------+---------+---------+---------+
```

## Frames

A Frame represents a single encrypted segment within a Stream. There
are two types of Frames:

* Body Frame -- A fixed-length Frame equal to the configured Frame
  Length.

* End Frame -- A variable-length Frame that marks the end of the
  Stream. Its length is less than or equal to the Frame Length.

A Stream consists of zero or more Body Frames followed by exactly one
End Frame. If the End Frame is missing, the Stream is considered
truncated and invalid.

Any bytes following the End Frame are not part of the Stream.

Truncation can only be detected by authenticating Frames through the
terminal End Frame. Successfully decrypting a prefix of the Stream
proves the integrity of only that prefix; it does not prove that the
stored Stream is complete.

Each Frame is assigned a monotonically increasing sequence
number. This number determines the correct ordering of Frames and is
included in the AEAD nonce during encryption. Any modification or
reordering of sequence numbers results in an authenticity violation
and will cause decryption to fail.

The table below is a binary specification of a Frame. All integers are
unsigned and interpreted in little-endian format.

|    Offset     |       Field      |      Bytes      | AAD  | Nonce |
|---------------|------------------|-----------------|------|-------|
|      0        | Sequence Number  |       4         |      |  ✅   |
|      4        | End Length       |       4         |  ✅  |       |
|      8        | Payload          |  (conditional)  |      |       |
| (conditional) | Tag              |   (algorithm)   |      |       |

### Frame Overhead
Frame Overhead is the combined serialized length of all non-Payload
fields in a Frame. It is computed as:

```
Frame Overhead = 8 + Tag Length
```

Where 8 is the combined length of the Sequence Number and End Length
fields. Tag Length is determined by the Algorithm field in the Stream
Header. For Algorithm `0`, Frame Overhead is 24 bytes.

### Sequence Number
An unsigned integer used to specify the order of a Stream. The decoder
MUST verify that the observed Sequence Number is strictly increasing
with no gaps; any reordering or omission invalidates the stream.

Sequence Numbers are 32-bit values and MUST begin at `0` for the
first Frame of a Stream. The encoder MUST increment the Sequence
Number by exactly `1` for each subsequent Frame, including the End
Frame.

The Sequence Number determines the AEAD nonce and therefore MUST NOT
wrap under the same Data Key. If the next Frame would require a
Sequence Number of `2^32`, the encoder MUST fail and MUST NOT emit any
additional Frames under that Data Key.

The AEAD nonce is the Sequence Number encoded as an unsigned
little-endian integer with the width specified by Nonce Bytes for the
selected [Algorithm](#algorithm). Nonce Bytes MUST be at least 4.

Because each Sequence Number occurs exactly once in an immutable
Stream, this construction produces a unique nonce for every Frame
encrypted under a Data Key.

### End Length
Specifies the length of the payload only if the Frame is an End
Frame. For Body Frames, this field is always set to `0xffffffff` (a
reserved constant).

The payload length of a Body Frame is derived as:

Payload Length = Frame Length - Frame Overhead

The serialized End Length field is included as AAD.

### Payload
The ciphertext produced by AEAD encryption. Its length is determined
as described in the End Length section.

### Tag
The Authentication Tag generated by the AEAD cipher, authenticating
the Metadata and Payload. It is verified during decryption to ensure
integrity and authenticity.

The size of the Tag field is determined by the AEAD algorithm used by
the Stream. Currently only AES-256-GCM is supported, which has a Tag
length of 16 bytes.

## Data Keys

Each Stream is encrypted and decrypted using a unique, one-time-use
Data Key. These Data Keys are derived from a long-term Parent Key
using a Key Derivation Function (KDF).

The Sequence Number limit implies:

* A Stream can contain at most `2^32` total Frames, including the End
  Frame.

* A Stream can contain at most `2^32 - 1` Body Frames.

* The maximum plaintext capacity of a Stream is `2^32 * (Frame Length -
  Frame Overhead)` bytes.

```
+------------+
| Parent Key |
+------------+
       |
       |     +-------------+    +--------+    +--------------+-----+
       +---->|  Data Key A |--->|  AEAD  |--->| Ciphertext A | TAG |
       |     +-------------+    +--------+    +--------------+-----+
       |                            ^
       |                            |
       |                      +-------------+
       |                      | Plaintext A |
       |                      +-------------+
       |
       |     +-------------+    +--------+    +--------------+-----+
       +---->|  Data Key B |--->|  AEAD  |--->| Ciphertext B | TAG |
       |     +-------------+    +--------+    +--------------+-----+
       |                            ^
       |                            |
       |                      +-------------+
       |                      | Plaintext B |
       |                      +-------------+
       v

```

## Header

The Header contains the necessary metadata to derive the Data Key for
a given Stream. Below is a binary specification of the Header. All
integers are unsigned and interpreted in little-endian format.

| Offset |    Field      |  Bytes |
|--------|---------------|--------|
|    0   | Magic Number  |      4 |
|    4   | Version       |      1 |
|    5   | Algorithm     |      2 |
|    7   | Frame Length  |      1 |
|    8   | Reserved      |      8 |
|   16   | Nonce         |     16 |
|   32   | Parent Key ID |     16 |
|   48   | MAC           |     32 |

### Magic Number
A file signature with the value `0x6d797a2e` (ASCII for ".zym"). This
identifies the file as conforming to the Zymic stream format.

### Version
Specifies the format version of the Header and Frame layout. Any
incompatible changes—such as reinterpretation of existing fields or
the addition of new fields—require incrementing this version number.
The Version field MUST be encoded as `2`. Version 2 is incompatible
with version 1.

### Algorithm
An unsigned integer specifying the combination of AEAD cipher and Data
Key derivation algorithm in use. The Algorithm field defines the
following value:

| Value | AEAD        | Data Key Derivation | Nonce Bytes | Tag Bytes |
|-------|-------------|---------------------|-------------|-----------|
|   0   | AES-256-GCM | HKDF-SHA-256        |     12      |     16    |

### Frame Length
Specifies the maximum Frame size as a power of two, encoded as an
exponent N, where:

```
Frame Length = 2^N (bytes)
```

Below is a table of supported Frame Length encodings:

| Encoded N | Byte Length |
|-----------|-------------|
|    12     |     4096    |
|    13     |     8192    |
|    14     |    16384    |
|    15     |    32768    |
|    16     |    65536    |

### Reserved
Unused bytes reserved for future protocol extensions. Encoders MUST
set all Reserved bytes to `0`. Decoders MUST include the Reserved
bytes when verifying the Header MAC but otherwise ignore their values.

### Nonce
A 16-byte value used to derive the Stream's Data Key. It MUST NOT be
reused for another Stream under the same Parent Key. The caller SHOULD
generate it using a CSPRNG. Another construction MAY be used if it
guarantees uniqueness.

### Parent Key ID
A 16-byte public identifier for the Parent Key used in Data Key
derivation. See [Parent Key](#parent-key) sub-section for more detail.

### MAC
A Message Authentication Code used to authenticate the Header and
confirm successful derivation under the supplied Parent Key.

## Parent Key

The Parent Key is an abstract cryptographic construct consisting of
two fields:

1. Public Identifier (ID) Field

    * The ID MUST identify exactly one Parent Key and MUST NOT be
    assigned to a different Parent Key.

    * It may be made public and is used to associate a specific
    Parent Key with a Stream.

    * The ID SHOULD be generated using a CSPRNG. Another construction
    MAY be used if it guarantees uniqueness.

2. Secret Field

    * This is 32 bytes of confidential key material.

    * It MUST be generated using a CSPRNG or derived using a KDF that
    produces pseudorandom cryptographic keys.

    * It MUST NOT be transmitted or persistently stored in plaintext.

The ID and Secret MUST be managed as an inseparable Parent Key. Zymic
cryptographically binds them during Data Key derivation. Both fields
MUST be provided by the Stream user or system. This specification does
not mandate how these fields are generated beyond the above
requirements.

Parent Keys may be derived, stored, and managed by any secure key
management system that fulfills the above criteria. This includes
software- or hardware-backed solutions, such as:

* Hardware Security Modules (HSMs)

* TPM-backed key stores

* Cloud-based Key Management Systems (KMS)

Note: This specification includes an example format for serializing
Parent Keys to disk, described in the section titled "Example Parent
Key Specification."

## Data Key Derivation

The Data Key is derived using a Key Derivation Function (KDF) that
takes as input:

* The Parent Key (secret and ID)

* The Stream metadata (contained in the Stream Header)

The KDF produces two outputs:

* Data Key -- a 32-byte symmetric encryption key used to encrypt all
  Frames in the Stream.

* Header MAC -- a 32-byte Message Authentication Code that
  authenticates the Stream Header.

The resulting Header MAC is appended to the Stream metadata to form
the complete, authenticated Stream Header.

```
      +-----------------------+           Stream Header
      |                       |           +----------+
      |          +-----+      +---------->| Metadata |
      |          |     |                  +----------+
  Metadata ----->|     |----------------->|   MAC    |
                 | KDF |                  +----------+
Parent Key ----->|     |-----> Data Key
                 |     |
                 +-----+

```

### HKDF Construction

Zymic uses HKDF
([RFC-5869](https://www.rfc-editor.org/rfc/rfc5869.html)) with SHA-256
as the underlying hash algorithm to derive the Data Key and Header
MAC.

The Header fields are encoded exactly as follows before key
derivation:

```
Header Metadata =
    Magic Number  (4 bytes, little-endian) ||
    Version       (1 byte)                 ||
    Algorithm     (2 bytes, little-endian) ||
    Frame Length  (1 byte)                 ||
    Reserved      (8 bytes)                ||
    Nonce         (16 bytes)               ||
    Parent Key ID (16 bytes)

Header =
    Header Metadata ||
    MAC             (32 bytes)
```

The MAC field is not included in any HKDF input. Only the 48-byte
Header Metadata block contributes to the derivation.

The MAC and Data Key are derived using HKDF-Expand with the Parent Key
Secret as the pseudorandom key (PRK). Each expansion prepends a
distinct ASCII domain label to the Header Metadata as the Info
parameter: "mac" for the Header MAC and "key" for the Data Key.

Since the Parent Key Secret is already suitable for direct use as a
PRK, the HKDF extract step is skipped. Skipping the extract step
requires the Parent Key Secret to be at least as long as the selected
hash algorithm's output. The 32-byte Parent Key Secret satisfies this
requirement for 256-bit hash algorithms.

HKDF is invoked as follows:

```
prk = Parent Key Secret
expand_length = 32

mac_info = "mac" || Header Metadata
key_info = "key" || Header Metadata

mac = hkdf_expand(prk, mac_info, expand_length)
data_key = hkdf_expand(prk, key_info, expand_length)
```

All Header fields used in the Info field MUST be in their raw binary
representation exactly as serialized in the Header. Multi-byte integer
fields MUST use little-endian encoding.

**Validation Requirement**

During decoding, the Header MAC MUST be recomputed by re-deriving it
from the header fields using the same HKDF inputs and compared in
constant time against the stored value in the MAC field of the Header.
Any mismatch is an authentication failure.

The derived Data Key MUST NOT be used to decrypt any Frame unless the
recomputed Header MAC matches the stored Header MAC.

Note: in this construction, "Header MAC" refers specifically to the
complete 32-byte output of the MAC-specific HKDF expansion.

**Parent Key Binding and Commitment**

The MAC construction is intended to provide key commitment at the
Parent Key level: it should be computationally infeasible to find two
distinct Parent Key Secrets that both successfully pass MAC validation
and decrypt the same encoded Stream.

This specification does not claim a formally proven key-commitment
security bound or conformance to a particular formal key-commitment
notion.

## Replay Attacks

This format authenticates integrity and key binding of a Stream, but
it does not by itself authenticate recency. In particular, it does not
prevent replay attacks in which an attacker replaces the current
stored Stream with an older, previously valid Stream derived from the
same Parent Key. Applications that require replay attack protection
MUST enforce an external, authenticated anti-replay policy appropriate
to their use

## Stream Encoding Algorithm

Plaintext data is encoded into a stream using the following steps.

Input Parameters:

* Frame Length -- Total serialized length of each Body Frame.
* Nonce -- 16-byte cryptographic nonce used in key derivation.
* Parent Key -- The Parent Key ID and secret key material.
* Plaintext -- The data to be encrypted and encoded into the Stream.

Steps:

1. Construct the Header Metadata using the field encodings, including
Reserved bytes set to `0`. Use the [Data Key
Derivation](#data-key-derivation) process to compute the Data Key and
Header MAC, append the MAC to the Header Metadata, and emit the
complete Header.

2. Chunk the Plaintext. Set Maximum Payload Length to `Frame Length -
Frame Overhead`, then divide nonempty Plaintext into chunks of that
size. All chunks except possibly the final chunk MUST have Maximum
Payload Length. If the Plaintext is empty, create one empty final chunk.

3. Encode each Plaintext chunk into a Frame. For each chunk:

    1. Assign the Frame sequence number.

        1. The first Frame MUST use `0`. Increment the Sequence Number by
           exactly `1` for each subsequent Frame.

        2. The value MUST be between `0` and `2^32 - 1`. The encoder MUST
           fail before another Frame would require `2^32`.

    2. Assign Frame type and End Length.

        1. If this is the final chunk, encode it as the End Frame and set
           End Length to the chunk's plaintext length.

        2. Otherwise, encode it as a Body Frame and set End Length to
           `0xffffffff`.

    3. Encrypt the payload.

        1. Encrypt the chunk using the Data Key and an AEAD cipher.

        2. Construct the AEAD nonce from the Sequence Number as
           specified in the [Sequence Number](#sequence-number) section.

        3. Include the four-byte little-endian End Length field as AAD.

    4. Attach the AEAD-generated Tag to the Frame.

### Stream Decoding

A Stream is decoded into plaintext using the following steps.

Input Parameters:

* Parent Key -- The Parent Key ID and secret key material.

* Stream -- A previously encoded and serialized Zymic Stream,
  including the Header and all Frames.

Steps:
1. Validate the Header and derive the Data Key.

    1. Validate the Magic Number, Version, Algorithm, Frame Length, and
       Parent Key ID. Process Reserved bytes as specified in the Header
       section. Reject any unsupported or invalid value.

    2. Use the [Data Key Derivation](#data-key-derivation) process to
       compute the expected Data Key and Header MAC.

    3. Compare the expected Header MAC with the stored Header MAC in
       constant time. If they differ, abort without using the derived
       Data Key to decrypt any Frame.

2. Process each Frame:

    1. Validate Sequence Number

        * Require the observed Sequence Number to equal the expected
        Sequence Number, beginning with `0`.

        * Reject a missing, duplicated, or reordered Frame.

    2. Validate the End Length and determine Frame type

        1. If End Length == `0xffffffff`, the Frame is a Body Frame. Its
           total serialized length MUST equal Frame Length, and its payload
           length must equal:
           ```
           Frame Length - Frame Overhead
           ```

        2. Otherwise, the Frame is an End Frame. The End Length value
           specifies the actual payload length and MUST be within:
           ```
           0 <= Payload Length <= Frame Length - Frame Overhead
           ```
           The total serialized length MUST equal:
           ```
           End Length + Frame Overhead
           ```

           Any bytes following the End Frame are not part of the current
           Stream, and their presence does not invalidate it.

    3. Decrypt the payload.

        1. Construct the AEAD nonce from the Sequence Number as
           specified in the [Sequence Number](#sequence-number) section.

        2. Include the four-byte serialized End Length field as AAD.

        3. Decrypt the Payload using the Data Key, the constructed
           AEAD nonce, and the attached Authentication Tag.

        4. If authentication fails, raise an integrity error and abort
           without releasing that Frame's plaintext.

        5. After a Body Frame is authenticated, increment the expected
           Sequence Number by exactly `1`. Reject the Stream if
           incrementing would overflow. Stop processing Frames after
           authenticating the End Frame.

3. Validate Stream termination.
    * Confirm that the Stream ends with a valid End Frame. An empty
       Stream with one End Frame and a payload length of `0` is valid.

    * If no End Frame is found, the Stream is considered truncated.

    * A decoder that is intended to validate the integrity of the
      entire stored Stream MUST continue processing until it has
      authenticated the End Frame.

    * A decoder that stops after only a prefix of plaintext, or that
      decrypts only a single Frame after seeking, authenticates only
      the data it actually processed. Such a decoder MUST NOT treat a
      successful partial decrypt as proof that the full Stream is
      present or unmodified beyond the authenticated prefix.

## Example Parent Key Specification

This section defines an example JSON-based format for serializing
Parent Keys to disk. The format uses a user-supplied password and the
Argon2id key derivation function (per
[RFC-9106](https://www.rfc-editor.org/rfc/rfc9106.html)) to protect
the key material via the AES Key Wrap algorithm
([RFC-3394](https://www.rfc-editor.org/rfc/rfc3394.html)).

The Key File is stored as JSON with the following fields:

```
{
  "id": "<Base64>",
  "date": <UNIX timestamp>,
  "argon": <argon setting>,
  "wrapped_secret": "<Base64>"
}
```

### id
The Parent Key ID, encoded using the standard Base64 alphabet with
padding. The decoded value MUST be exactly 16 bytes. This public
identifier associates Streams with the correct Parent Key.

### date
A UNIX timestamp (in seconds) indicating when the key file was
created. It is stored in JSON as a 64-bit unsigned integer. When used
in the Argon2id salt, it MUST be serialized as an eight-byte
little-endian unsigned integer.

### argon
An integer preset identifier representing the Argon2id
configuration. Argon2id Version 1.3 MUST be used with a 32-byte output.
The presets map to the memory in KiB (M), parallelism (P), and
iteration count (T) as follows:

| Setting Value |  M   | P | T |       Description       |
|---------------|------|---|---|-------------------------|
|   1           | 2^16 | 4 | 3 | CPU-intensive           |
|   2           | 2^18 | 4 | 1 | Memory-intensive        |
|   3           |  8   | 1 | 1 | Insecure (for testing)  |

Note: Setting 3 is for development or testing only and MUST NOT be
used in production environments.

### wrapped_secret

The wrapped Parent Key secret, encoded using the standard Base64
alphabet with padding. The decoded value MUST be exactly 40 bytes: the
32-byte Parent Key secret wrapped using AES Key Wrap. The wrapping key
is derived from the UTF-8 encoding of the user's password using
Argon2id with a salt composed of the decoded `id` and serialized `date`
fields.

To wrap the secret field:

```
# Construct the salt from the decoded ID and little-endian date.
salt = id_bytes || little_endian_u64(date)

# Derive a 32-byte wrapping key using the selected Argon2id preset.
key_wrap_key = argon2id(utf8(password), salt, output_length = 32)

# Generate 32 bytes for the secret using a CSPRNG.
secret = crypto_rand_32_bytes()
```

Wrap the secret using AES-256 Key Wrap
([RFC-3394](https://www.rfc-editor.org/rfc/rfc3394.html)):

```
wrapped_secret = aes256_wrap(key_wrap_key, secret)
```

To unwrap the secret field:

```
# Construct the salt from the decoded ID and little-endian date.
salt = id_bytes || little_endian_u64(date)

# Derive a 32-byte wrapping key using the selected Argon2id preset.
key_wrap_key = argon2id(utf8(password), salt, output_length = 32)
```

Unwrap the secret using AES-256 Key Wrap
([RFC-3394](https://www.rfc-editor.org/rfc/rfc3394.html)):

```
secret = aes256_unwrap(key_wrap_key, wrapped_secret)
```
