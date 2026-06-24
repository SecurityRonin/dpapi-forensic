import struct
from impacket.dpapi import DPAPI_BLOB, CredentialFile, CREDENTIAL_BLOB, ALGORITHMS_DATA
from Crypto.Hash import SHA1, SHA512, HMAC
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

MK = bytes.fromhex("9828d9873735439e823dbd216205ff88266d28ad685a413970c640d5ee943154bbade31fada673d542c72d707a163bb3d1bceb0c50465b359ae06998481b0ce3")
GUID_CRED = bytes.fromhex("d08c9ddf0115d1118c7a00c04fc297eb")
GUID_MK   = bytes.fromhex("33f19f5ee340be4a8a2e2b4e62bd0cc6")
CALG_AES_256 = 0x6610
CALG_SHA_512 = 0x800e
HashMod = SHA512

# --- Build the inner CREDENTIAL_BLOB (the cleartext the DPAPI blob protects) ---
def u16(s): return s.encode("utf-16le")
target = u16("Domain:target=TERMSRV/fileserver01")
username = u16("CORP\\jdoe")
secret = u16("S3cr3t-P@ssw0rd!")   # stored in the "Unknown" field (the password)
cb = CREDENTIAL_BLOB()
cb['Flags']=0; cb['Size']=0; cb['Unknown0']=0; cb['Type']=1; cb['Flags2']=0
cb['LastWritten']=0x01d8000000000000; cb['Unknown2']=0; cb['Persist']=2; cb['AttrCount']=0
cb['Unknown3']=0
cb['TargetSize']=len(target); cb['Target']=target
cb['TargetAliasSize']=0; cb['TargetAlias']=b''
cb['DescriptionSize']=0; cb['Description']=b''
cb['UnknownSize']=len(secret); cb['Unknown']=secret
cb['UsernameSize']=len(username); cb['Username']=username
cb['Unknown3Size']=0; cb['Unknown3']=b''
cb['Remaining']=b''
cleartext = cb.getData()
# Fix Size field (impacket dump uses fields; Size not strictly needed for our decode test)
print("cleartext len:", len(cleartext))

# --- Encrypt cleartext into a DPAPI blob (inverse of DPAPI_BLOB.decrypt, AES256/SHA512) ---
salt = bytes.fromhex("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899")
key_len, mode, iv_len = ALGORITHMS_DATA[CALG_AES_256][0], ALGORITHMS_DATA[CALG_AES_256][2], ALGORITHMS_DATA[CALG_AES_256][3]
keyHash = SHA1.new(MK).digest()
sessionKey = HMAC.new(keyHash, salt, HashMod).digest()
# derivedKey: SHA512 digest (64) >= key+iv (48), so derivedKey = sessionKey
derivedKey = sessionKey
encKey = derivedKey[:key_len]
iv = b'\x00'*iv_len
ct = AES.new(encKey, mode=mode, iv=iv).encrypt(pad(cleartext, AES.block_size))

def lp(b): return struct.pack("<L", len(b)) + b
description = "\x00\x00".encode("latin-1")
HMac = bytes(64)
pre  = struct.pack("<L",1) + GUID_CRED + struct.pack("<L",1) + GUID_MK + struct.pack("<L",0)
pre += lp(description) + struct.pack("<L",CALG_AES_256) + struct.pack("<L",key_len*8) + lp(salt)
pre += lp(b'') + struct.pack("<L",CALG_SHA_512) + struct.pack("<L",512) + lp(HMac) + lp(ct)
toSign = pre[20:]
Sign = HMAC.new(keyHash, HMac, HashMod); Sign.update(toSign); Sign = Sign.digest()
blob_bytes = pre + lp(Sign)

# --- Verify impacket DPAPI_BLOB.decrypt(blob) == cleartext, then CREDENTIAL_BLOB parses ---
dec = DPAPI_BLOB(blob_bytes).decrypt(MK)
assert dec == cleartext, "DPAPI roundtrip mismatch"
cb2 = CREDENTIAL_BLOB(dec)
print("impacket Target  :", cb2['Target'].decode('utf-16le'))
print("impacket Username:", cb2['Username'].decode('utf-16le'))
print("impacket Secret  :", cb2['Unknown'].decode('utf-16le'))

# --- Wrap in the on-disk CredentialFile (Version/Size/Unknown + Data=blob) ---
cf = CredentialFile()
cf['Version']=1; cf['Size']=len(blob_bytes); cf['Unknown']=0; cf['Data']=blob_bytes
cred_file_bytes = cf.getData()
# Verify impacket re-reads CredentialFile and its Data decrypts back
cf2 = CredentialFile(cred_file_bytes)
assert cf2['Data']==blob_bytes
dec2 = DPAPI_BLOB(cf2['Data']).decrypt(MK)
assert dec2==cleartext
print("CredentialFile roundtrip OK")
print("CRED_FILE_HEX:", cred_file_bytes.hex())
print("CRED_BLOB_HEX (inner DPAPI blob):", blob_bytes.hex())
print("EXPECT_TARGET:", "Domain:target=TERMSRV/fileserver01")
print("EXPECT_USERNAME:", "CORP\\jdoe")
print("EXPECT_SECRET:", "S3cr3t-P@ssw0rd!")
print("MASTER_KEY_HEX:", MK.hex())
