# Zymic AEAD Stream Format

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

Authentication Tag -- A checksum produced by an AEAD cipher and used
to provide authenticity of encrypted data.

Ciphertext -- The encrypted output of a plaintext message, produced by
an encryption algorithm.

KDF -- Key Derivation Function. A cryptographic algorithm used to
derive one or more encryption keys from a source key or secret.

KDK -- Key Deriving Key. An encryption key used for deriving other
encryption keys.

MAC -- Message Authentication Code. A checksum used to confirm the
authenticity of data.

Plaintext -- The original, unencrypted data input to an encryption
algorithm.

## Overview

Zymic is an Authenticated Encryption with Associated Data (AEAD)
stream protocol designed to secure sequentially transmitted plaintext
data. The protocol operates by dividing plaintext into discrete
segments, each of which is independently encrypted using an AEAD
cipher and a unique symmetric key.

Each encrypted segment produces a ciphertext and an accompanying
Authentication Tag. These are encapsulated into binary structures
known as Frames. A series of these Frames, in order, constitutes a
Stream.

Each Stream is encrypted using a unique Data Key -- a symmetric key
derived from a higher-level Parent Key using a key derivation
function. The Parent Key, also known as the Key Derivation Key (KDK),
is not directly used for encryption but serves as the root material
from which Data Keys are generated.

Streams are strictly ordered: Frames must appear in their original
sequence and any reordering or removal can be detected. Each Stream
begins with a Header, a block of metadata bound to the Frame sequence
via AEAD mechanisms. The Header and its associated Frames together
form a complete encrypted Stream.

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

Each Frame is assigned a monotonically increasing sequence
number. This number determines the correct ordering of Frames and is
included as AAD during encryption. Any modification or reordering of
sequence numbers results in an authenticity violation and will cause
decryption to fail.

```
<-------------------- Stream ----------------------->

+--------+--------------+--------------+------------+
| Header | Body Frame 1 | Body Frame 2 | End Frame  |
+--------+--------------+--------------+------------+
```

The table below is a binary specification of a Frame. All integers are
unsigned and interpreted in little-endian format.

|    Offset     |       Field      |      Bytes      | AAD  | Nonce |
|---------------|------------------|-----------------|------|-------|
|      0        | Sequence Number  |       4         |      |  ✅   |
|      4        | Invocation Count |       8         |      |  ✅   |
|     12        | End Length       |       4         |  ✅  |       |
|     16        | Payload          |  (conditional)  |      |       |
| (conditional) | Tag              |   (algorithm)   |      |       |

### Sequence Number
An unsigned integer used to specify the order of a Stream. The decoder
MUST verify that the observed Sequence Number is strictly increasing
with no gaps; any reordering or omission invalidates the stream.

### Invocation Count
An unsigned integer indicating how many times a Frame has been
re-encrypted with the same Data Key. This value defaults to 0.

The AEAD nonce for each frame is constructed by concatenating the
sequence number and the invocation count.

`AEAD Nonce = Sequence Number || Invocation`

This ensures nonce uniqueness even when the same Frame is encrypted
multiple times with the same key.

### End Length
Specifies the length of the payload only if the Frame is an End
Frame. For Body Frames, this field is always set to `0xffffffff` (a
reserved constant)

The payload length of a Body Frame is derived as:

Payload Lenght = Frame Length - 32

Where 32 is the sum of sequence number, Ivocation, End Length, and Tag
lengths.

This field is included as AAD input to the AEAD cipher.

### Payload
The ciphertext produced by AEAD encryption. Its length is determined
as described in the End Length section.

### Tag
The Authentication Tag generated by the AEAD cipher, authenticating
the Metadata and Payload. It is verified during decryption to ensure
integrity and authenticity.

The size of the Tag field is determined by the AEAD algorithm used by
the stream. Currnetly only AES-GCM is supported, which has a Tag
length of 16 bytes.

## Data Keys

Each Stream is encrypted and decrypted using a unique, one-time-use
Data Key. These Data Keys are derived from a long-term Parent Key
using a Key Derivation Function (KDF).

This design provides two primary security benefits:

* Key Isolation -- If a Data Key is compromised, the damage is
  contained to that specific Stream. Other Streams remain secure, as
  each is encrypted with a different derived key.

* Nonce Safety -- Frame sequence numbers can be safely used as
  deterministic nonce inputs for AEAD encryption. Since sequence
  numbers are unique and non-repeating within a Stream, this
  guarantees nonce uniqueness for a given Data Key. This property is
  essential for AEAD algorithms like AES-GCM, where nonce reuse under
  the same key breaks security.

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

### Algorithm
Unsigned integer specifing the AEAD cipher and Data Key derivation
algorithm in use. Currently only AES256-GCM and HMAC-SHA256 (RFC-5869)
are supported.

Zymic requires AEAD algorithms to support 12-byte nonces. AEAD
algorithms must be used with deterministic, non-repeating nonces
derived from Frame sequence number and invocation count.

### Frame Length
Specifies the maximum Frame size as a power of two, encoded as an
exponent N, where:

```
Frame Length = 2^N (bytes)
```

Below is a table of supported Frame Lengths:

| Frame Length | Byte Length |
|--------------|-------------|
|       12     |     4096    |
|       13     |     8192    |
|       14     |    16384    |
|       15     |    32768    |
|       16     |    65536    |

### Reserved
Unused section that should be set to 0. Reserved for future protocol
extensions.

### Nonce
A cryptographic nonce value used for data key derivation of thje
Stream's Data Key. This value must not be reused and should be derived
using a pseudo-random byte generator.

### Parent Key ID
An identifier for the Parent Key used in Data Key derivation. This
value must not be reused and should be derived using a pseudo-random
byte generator.

### MAC
A Message Authentication Code used to authenticate the Header and Data
Key. It ensures the integrity and authenticity of the Header.

## Parent Key

The Parent Key is an abstract cryptographic construct consisting of
two fields:

* A 16-byte public identifier (ID)

* A 32-byte secret key

Both fields must be provided by the Stream user or system. This
specification does not mandate how these fields are generated but
imposes the following requirements:

1. ID Field

    a. The ID must be globally unique and non-repeating.

    b. It may be made public and is used to associate a specific
    Parent Key with a Stream.

    c. It is strongly recommended that the ID be generated using a
    cryptographically secure pseudo-random number generator (CSPRNG).

    d. The ID must be cryptographically bound to the corresponding
    secret key to prevent substitution attacks.

2. Secret Field

    a. This is 32 bytes of confidential key material.

    b. It must be generated using a cryptographically secure process.

    c. It must never be transmitted or stored in plaintext.

Parent Keys may be derived, stored, and managed by any secure key
management system that fulfills the above criteria. This includes
software- or hardware-backed solutions, such as:

* Hardware Security Modules (HSMs)

* TPM-backed key stores

* Cloud-based Key Management Systems (KMS)

Note: This specification includes an optional format for serializing
Parent Keys to disk, described in the section titled "Optional Parent
Key Specification."

## Data Key Derivation

The Data Key is derived using a Key Derivation Function (KDF) that
takes as input:

* The Parent Key (secret and ID)

* The Stream metadata (contained in the Stream Header)

The KDF produces two outputs:

* Data Key -- a symmetric encryption key used to encrypt all Frames
  in the Stream.

* MAC -- a Message Authentication Code that authenticates the Stream
  Header.

The resulting MAC is appended to the Stream metadata to form the
complete, authenticated Stream Header.

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

### Data Key Derivation Function

Zymic uses HKDF (RFC-5869) with SHA-256 as the underlying hash
algorithm to derive two values:

1. Data Key -- used for AEAD encryption of Frames.

2. MAC -- used to authenticate the Stream Header.

The HDKF is invoked as follows:
```
ikm = Parent Key Secret
salt = Nonce || Parent Key ID
info = Magic Number || Version || Algorithm || Frame Length || Reserved

# Total length in bytes of the MAC + Data Key
length = 64

extract_output = hkdf_extract(ikm, salt)
expand_output = hkdf_expand(extract_output, info, length)

# The MAC is comprised of the first 32 bytes of the HKDF output.
mac = expand_output[0..32]

# The Data Key is comprised of the second 32 bytes of the HKDF output.
data_key = expand_output[32..64]:
```

All Header fields used in Salt and Info must be in their raw
binary (little-endian) representation when used in the HKDF input.

**Validation Requirement**

During decoding, the Header MAC must be recomputed by re-deriving it
from the header fields using the same HKDF inputs and compared
byte-for-byte against the stored value. Any mismatch indicates header
tampering.

**Parent Key Binding Enforcement**

The Parent Key ID is included in the HKDF Salt used to derive the
Stream's Data Key. As a result, the derived Data Key is
cryptographically bound to the specific Parent Key used.

Any attempt to substitute the Parent Key or its ID will result in a
different derived Data Key, causing subsequent Frame decryption or MAC
verification to fail.

This provides strong protection against key substitution attacks and
ensures that Streams cannot be processed with an incorrect or
malicious Parent Key.

## Stream Encoding Algorithm

Plaintext data is encoded into a stream using the following steps.

Input Parameters:

* Frame Length -- Maximum length of Body Frame payloads.
* Nonce -- 16-byte cryptographic nonce used in key derivation.
* Parent Key --  secret key material.
* Parent Key Id -- identifier for the Parent Key.
* Plaintext -- The data to be encrypted and encoded into the Stream.
* Payload Length -- Length of each Frame’s plaintext payload.

Steps:
1. Derive the Data Key. Use the [Data Key
Derivation](#Data-Key-Derivation) process to compute the Data Key and
Header MAC.

2. Chunk the Plaintext. Divide the Plaintext into Payload Length
chunks.

3. Encode each Plaintext chunk into a Frame. For each chunk:

    a. Assign the Frame sequence number.

        * The sequence number is increamented by 1 for each Frame.

        * The value must be between 0 and 2^32.

    b. Assign the invocation count.

        * Initialize to 0 for first-time encryption with the given
        Data Key.

        * Increment by 1 if the Frame is re-encrypted with the same Data Key.

        * The value must be between 0 and 2^64.

    c. Encrypt the payload.

        * Encrypt the chunk using the Data Key and an AEAD cipher.

        * Sequence Number and Invocation Count are encoded into the 12‑byte
          AEAD nonce (Sequence || Invocation).
        ```
        AEAD Nonce = Sequence Number || Invocation Count

        ```

        * Include End Length as AAD.

    d. Attach the AEAD-generated Tag to the Frame.

    e. Assign Frame type.

        * If this is the last frame, set the End Length to the payload length.

        * Otherwise, for a Body Frame, set the End Length to `0xffffffff`.

### Stream Decoding

A Stream is decoded into plaintext using the following steps.

Input Parameters:

* Parent Key -- secret key material.

* Stream -- A previously encoded and serialized Zymic Stream,
  including the Header and all Frames.

1. Derive the Data Key. Use the [Data Key
Derivation](#Data-Key-Derivation) process to compute the Data Key and
Header MAC.

2. Process each Frame:

    a. Validate Sequence Number

        * Ensure that Frames are in strictly increasing sequence order.

        * If a sequence number is missing, treat it as a missing Frame.

        * If a sequence number is out of order, treat it as a reordered Frame.

    b. Validate the End Length and determine Frame type

        * If End Length == `0xffffffff`, the Frame is a Body Frame. The
        payload length must equal:

        ```
        Frame Length - Frame Metadata Length (32 bytes)
        ```

        * Otherwise, the Frame is an End Frame. The End Length value
        specifies the actual payload length and must be within:

        ```
        0 ≤ Payload Length ≤ Frame Length - 32
        ```

    c. Decrypt the payload.

        * Construct the 12-byte AEAD nonce as
        ```
        AEAD Nonce = Sequence Number || Invocation Count

        ```

        * Include End Length as AAD.

        * Decrypt the Payload using the Data Key, the constructed AEAD
        nonce, and the attached the authentication tag.

        * If authentication fails, raise an integrity error and abort.

3. Validate Stream termination.

    * Confirm that the Stream ends with a valid End Frame. Note that
      an empty Stream with one End Frame and a payload length of 0 is
      valid.

    * If no End Frame is found, the Stream is considered truncated.

## Optional Parent Key Specification

This section defines an optional JSON-based format for serializing
Parent Keys to disk. The format uses a user-supplied password and the
Argon2id key derivation function (per RFC-9106) to protect the key
material via the AES Key Wrap algorithm (RFC-3394).

The Key File is stored in json with the following fields.
```
{
  "id": "<Base64>",
  "date": <UNIX timestamp>,
  "argon": <argon setting>,
  "wrapped_secret": "<Base64>"
}
```

### id
The Parent Key ID, base64-encoded. This is a 16-byte public identifier
used to associate Streams with the correct Parent Key.

### date
A UNIX timestamp (in seconds) indicating when the key file was
created. Stored as a 64-bit unsigned integer.

### argon
An integer preset identifier representing the Argon2id
configuration. The presets map to the memory (M), parallelism (P), and
iteration (T) parameters as follows:

| Setting Value |  M   | P | T |       Description       |
|---------------|------|---|---|-------------------------|
|   1           | 2^16 | 4 | 3 | CPU-intensive           |
|   2           | 2^18 | 4 | 1 | Memory-intensive        |
|   3           |  8   | 1 | 1 | Insecure (for testing)  |

Note: Setting 3 is for development or testing only and must not be
used in production environments.

### wrapped_secret

The wrapped Parent Key secret. This is a 40-byte value, encrypted
using the AES Key Wrap algorithm. The wrapping key is derived from the
user’s password using Argon2id with a salt composed of the id and date
fields.

To wrap the secret field:
```
# Construct the salt by appending the id and data fields.
salt = id || date

# Derive the key wrapping key from Argon2id with a user password.
key_wrap_key = argon2id(password, salt)

# Generate 32 bytes of cryptographicly secure random data for the Secret.
secret = crypto_rand_32_bytes()

# Wrap the secret using the aes keywrap algorithm.
wrapped_secret = aes256_wrap(key_wrap_key, secret)

```

To unwrap the secret field:

```
# Construct the salt by appending the id and data fields.
salt = id || date

# Derive the key wrapping key from Argon2id with a user password.
key_wrap_key = argon2id(password, salt)

# Unwrap the secret using the aes keywrap algorithm.
secret = aes256_unwrap(key_wrap_key, wrapped_secret)

```
