# Secure boot status — Spotify Car Thing

## TL;DR

Fuses are blown. BL2 is immutable. **Everything after BL2** (BL30, BL31,
BL32, BL33) is replaceable because Spotify open-sourced the FIP signing
key in their own u-boot tree.

## Mutable vs immutable stages

| Stage | Where it lives | Verified by | Replaceable? |
|-------|---------------|-------------|--------------|
| Mask ROM | On-die SoC ROM | (verifier of BL2) | No, ever |
| BL2 (64 KiB) | boot0/boot1 LBA 1..127 | Mask ROM RSA, fused pubkey hash | **No** — fuses blown |
| BL30 (M3 firmware) | inside FIP body | BL2, via aml-user-key.sig | **Yes** |
| BL31 (TF-A) | inside FIP body | BL2, via aml-user-key.sig | **Yes** |
| BL32 (TEE, unused) | inside FIP body | BL2, via aml-user-key.sig | **Yes** |
| BL33 (u-boot) | inside FIP body | BL2, via aml-user-key.sig | **Yes** |
| Linux/userspace | Anywhere | None | Yes |

## Empirical results

### BL2 modification → CHK:21

Test: flipped one byte in `superbird.bl2.encrypted.bin` (offset 0x4000)
and sent the corrupted BL2 to mask ROM via `bl2_boot`.

Result: mask ROM printed `CHK:21` and dropped to USB Mode. No further
output. **Signature check failed.**

`CHK:21` is the AML mask ROM "BL2 integrity/signature failed" code.

### Re-signing FIP HDR with leaked key → byte-identical to stock

Running:
```
aml_encrypt_g12a --bootsig \
    --input dev-keyed-fip.bin \
    --amluserkey aml-user-key.sig \
    --aeskey enable \
    --output resigned.bin
```

produces output where bytes `[0x10000:0x10030]` (the FIP HDR ciphertext)
are **byte-identical** to:

  - `bootloader.dump[0x10000:0x10030]` (stock device's bootloader partition)
  - `fip_a.dump[0:0x30]` (stock device's fip_a partition)

The matching bytes:
```
16 dc fd b7 7c 39 ac 15 99 8d db cf 8c 41 32 cc
0c 5b 07 e8 64 94 0c a2 ec 7e 19 83 15 9d b3 db
33 99 aa 6e 65 34 15 9d c5 4e a5 7e 4a 90 28 ce
```

This is the same plaintext FIP HDR encrypted with the same AES key and
IV, producing the same ciphertext. The probability of independent keys
producing identical 384-bit ciphertexts on identical plaintext is
2⁻³⁸⁴. Effectively zero.

The key in `aml-user-key.sig` IS Spotify's production FIP signing key.

### Boot at power-on with empty user area → success

After:
1. Wiping the user area (3.6 GiB) to zeros (except a hardware-guarded
   emmckey enclave at LBA 73760-74271)
2. Writing the standard `flash_boot_partition.py ours` image to both
   boot0 and boot1

The device boots our upstream u-boot at power-on in ~5 seconds. No
vendor BL33 ever runs. Panel splash appears, then u-boot prompt.

## Why fuses being blown is not a blocker

Mask ROM verifies BL2's RSA signature against a public-key hash burned
into eFUSE. We can't substitute a BL2 with a different public key
because the eFUSE hash wouldn't match.

But mask ROM does NOT verify what BL2 loads next. It hands control to
BL2 and BL2 is responsible for verifying its own children. BL2's
verification is done with keys baked into the BL2 binary itself —
which were derived from `aml-user-key.sig` at Spotify's build time.

So as long as we have `aml-user-key.sig`, we can sign anything BL2
expects to verify.

## Mask ROM error codes observed

| Code | Meaning | When seen |
|------|---------|-----------|
| `CHK:21` | RSA signature mismatch | Corrupted BL2 |
| `CHK:1F` | AES/hash check failed at this sector | Reading info_sector at LBA 0 as BL2 (expected once per boot — mask ROM retries at LBA 1 and succeeds) |
| `READ:0` | sector read OK | Normal |
| `SD?:20000;USB:8` | falling back to SD/USB after eMMC fails | Three consecutive CHK fails |

A single `CHK:1F` followed by `READ:0;0.0;0.0` in the boot tag is
**normal and expected**. Three CHK:1F in a row means mask ROM gave up
on eMMC.

## Related

- `docs/boot-chain.md` — BL2's 4-path FIP fallback chain
- `docs/emmc-layout.md` — physical layout, info_sector struct
- `keys/NOTICE.md` — provenance of `aml-user-key.sig`
