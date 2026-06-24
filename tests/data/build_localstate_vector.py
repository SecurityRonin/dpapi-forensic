import os, struct
from impacket.dpapi import DPAPI_BLOB, ALGORITHMS_DATA
from Crypto.Hash import SHA1, SHA512, HMAC
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MK = bytes.fromhex("9828d9873735439e823dbd216205ff88266d28ad685a413970c640d5ee943154bbade31fada673d542c72d707a163bb3d1bceb0c50465b359ae06998481b0ce3")

# --- The 32-byte Chrome cookie AES key we want this Local State blob to protect ---
# deterministic, recognizable
COOKIE_KEY = bytes(range(0x20, 0x40))  # 32 bytes 0x20..0x3f
assert len(COOKIE_KEY)==32

# GUIDs from the existing tier-1 vector (so master-key GUID is consistent)
GUID_CRED = bytes.fromhex("d08c9ddf0115d1118c7a00c04fc297eb")
GUID_MK   = bytes.fromhex("33f19f5ee340be4a8a2e2b4e62bd0cc6")
CALG_AES_256 = 0x6610
CALG_SHA_512 = 0x800e
HashMod = SHA512
hash_block = HashMod.block_size  # 128
key_len, mode, iv_len = ALGORITHMS_DATA[CALG_AES_256][0], ALGORITHMS_DATA[CALG_AES_256][2], ALGORITHMS_DATA[CALG_AES_256][3]

salt = bytes.fromhex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")  # 32-byte salt (SHA512)

# session key + derived key, replicating impacket deriveKey (HMAC-SHA512 expansion)
keyHash = SHA1.new(MK).digest()
sessionKey = HMAC.new(keyHash, salt, HashMod).digest()

# replicate DPAPI_BLOB.deriveKey
def deriveKey(sessionKey, hashMod, key_iv_len):
    # impacket: if len(digest) >= keyLen return; else ipad/opad expansion
    digest = sessionKey
    if len(digest) >= key_iv_len:
        return digest
    blk = hashMod.block_size
    ipad = bytearray([i ^ 0x36 for i in bytearray(digest)] + [0x36]*(blk-len(digest)))
    opad = bytearray([i ^ 0x5c for i in bytearray(digest)] + [0x5c]*(blk-len(digest)))
    a = hashMod.new(ipad).digest()
    b = hashMod.new(opad).digest()
    return a + b

# We need key (32) + iv (16) = 48 bytes. SHA512 digest = 64 >= 48, so derivedKey = sessionKey.
derivedKey = deriveKey(sessionKey, HashMod, key_len+iv_len)
encKey = derivedKey[:key_len]
iv = b'\x00'*iv_len
ct = AES.new(encKey, mode=mode, iv=iv).encrypt(pad(COOKIE_KEY, AES.block_size))

# Now build the blob bytes. Layout per DPAPI_BLOB structure:
# Version(4) GuidCredential(16) MasterKeyVersion(4) GuidMasterKey(16) Flags(4)
# DescriptionLen(4) Description(var) CryptAlgo(4) CryptAlgoLen(4) Salt(4-len-prefixed)
# HMacKeyLen(4) HMacKey(var) HashAlgo(4) HashAlgoLen(4) HMac(4-len-prefixed)
# DataLen(4) Data(var) SignLen(4) Sign(var)
def lp(b):  # 4-byte len prefix + bytes
    return struct.pack("<L", len(b)) + b

description = "\x00\x00".encode("latin-1")  # 2 bytes like tier-1 (DescriptionLen=2)
HMacKey = b''
HMac = bytes(64)  # zero HMac salt for Sign path (64 bytes, SHA512)

pre = b''
pre += struct.pack("<L",1)            # Version
pre += GUID_CRED
pre += struct.pack("<L",1)            # MasterKeyVersion
pre += GUID_MK
pre += struct.pack("<L",0)            # Flags
pre += lp(description)                # DescriptionLen + Description
pre += struct.pack("<L",CALG_AES_256) # CryptAlgo
pre += struct.pack("<L", key_len*8)   # CryptAlgoLen (bits) -- cosmetic
pre += lp(salt)                       # Salt
pre += lp(HMacKey)                    # HMacKey
pre += struct.pack("<L",CALG_SHA_512) # HashAlgo
pre += struct.pack("<L",512)          # HashAlgoLen
pre += lp(HMac)                       # HMac
pre += lp(ct)                         # Data

# toSign = rawData[20: len-len(Sign)-4]; rawData starts at Version.
# So toSign covers bytes from offset 20 to just before SignLen. offset 20 = after Version(4)+GuidCred(16).
# Compute Sign over the assembled 'pre' (which is everything up to Data, no Sign yet).
toSign = pre[20:]   # from offset 20 to end of Data
# Sign path 3 (HMAC keyHash over HMac then toSign):
h3 = HMAC.new(keyHash, HMac, HashMod)
h3.update(toSign)
Sign = h3.digest()

blob_bytes = pre + lp(Sign)

# Verify impacket decrypts back to COOKIE_KEY
blob = DPAPI_BLOB(blob_bytes)
pt = blob.decrypt(MK)
print("impacket roundtrip key match:", pt == COOKIE_KEY, "len", len(pt) if pt else None)
print("COOKIE_KEY hex:", COOKIE_KEY.hex())
print("LOCAL_STATE_BLOB_HEX (raw DPAPI blob, no DPAPI prefix):")
print(blob_bytes.hex())

# Chrome Local State stores: base64( b"DPAPI" + blob_bytes )
import base64
encrypted_key_b64 = base64.b64encode(b"DPAPI"+blob_bytes).decode()
print("ENCRYPTED_KEY_B64 (Local State os_crypt.encrypted_key):")
print(encrypted_key_b64)

# --- Build a v10 cookie using COOKIE_KEY ---
COOKIE_PLAINTEXT = b"forensic-session-token-42"
nonce = bytes.fromhex("0102030405060708090a0b0c")  # 12 bytes
gcm = AESGCM(COOKIE_KEY)
ct_tag = gcm.encrypt(nonce, COOKIE_PLAINTEXT, None)  # ciphertext||tag
v10_value = b"v10" + nonce + ct_tag
print("COOKIE_PLAINTEXT:", COOKIE_PLAINTEXT.decode())
print("V10_COOKIE_HEX (encrypted_value as stored in Cookies DB):")
print(v10_value.hex())

# Sanity: decrypt back
dec = AESGCM(COOKIE_KEY).decrypt(nonce, v10_value[15:], None)
print("v10 roundtrip:", dec == COOKIE_PLAINTEXT)
