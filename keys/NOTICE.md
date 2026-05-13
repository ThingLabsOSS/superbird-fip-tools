# aml-user-key.sig

This file is the **production AES + RSA signing key bundle** that Spotify
used to sign and encrypt the FIP (Firmware Image Package) for the
Spotify Car Thing.

## Provenance

Spotify accidentally committed this file to their open-source u-boot
fork:

  - **Repo:** https://github.com/spsgsb/uboot
  - **Path:** `board/amlogic/superbird_production/aml-user-key.sig`
  - **Size:** 6976 bytes
  - **SHA-256:** `f48c731e064193c6584fe3785c193e6ec0ed51c892b5c20457641945cf906afc`

Spotify has not (as of this writing) removed it or rotated to a new key
on shipped devices. The repo has been public for years.

## Why it's here

This bundle is the input to `aml_encrypt_g12a --bootsig --amluserkey
<this-file> --aeskey enable`, which produces a FIP image that the BL2
on shipped Car Thing units accepts as legitimately signed. Without it,
we couldn't replace BL30/BL31/BL32/BL33 in the signed boot chain.

## Empirical proof this is the production key

Running `aml_encrypt_g12a --bootsig` against the same plaintext FIP HDR
with this key produces **byte-identical 48-byte ciphertext** at the FIP
HDR position of stock `bootloader.dump` and stock `fip_a.dump` taken
from real devices:

```
16 dc fd b7 7c 39 ac 15 99 8d db cf 8c 41 32 cc
0c 5b 07 e8 64 94 0c a2 ec 7e 19 83 15 9d b3 db
33 99 aa 6e 65 34 15 9d c5 4e a5 7e 4a 90 28 ce
```

Probability of independent AES keys producing identical 384-bit
ciphertexts on identical plaintext: 2^-384. Effectively zero. This is
the same key.

## Ethics + responsible disclosure

  - This key has been public, on Spotify's own GitHub, for years.
  - The Car Thing was discontinued in 2024; Spotify announced they
    would brick devices, then walked it back amid community outcry.
  - Anyone with this key can sign FIPs for any shipped Car Thing.
    Bricking is irrelevant — recovery via mask ROM USB always works.
  - This repo's purpose is to enable owners to run their own software
    on hardware they bought.

If Spotify ever rotates the key by pushing a vendor update that updates
the fused public-key hash on shipped devices — they can't. Fuses are
write-once and already burned with the current public key's hash. Any
re-key would brick all existing devices.
