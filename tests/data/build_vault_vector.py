import struct
from impacket.dpapi import (DPAPI_BLOB, VAULT_VPOL, VAULT_VPOL_KEYS, VAULT_VCRD,
                            VAULT_ATTRIBUTE, VAULT_ATTRIBUTE_MAP_ENTRY, VAULT_KNOWN_SCHEMAS,
                            VAULT_INTERNET_EXPLORER)
from Crypto.Hash import SHA1, SHA512, HMAC
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

MK = bytes.fromhex("9828d9873735439e823dbd216205ff88266d28ad685a413970c640d5ee943154bbade31fada673d542c72d707a163bb3d1bceb0c50465b359ae06998481b0ce3")
GUID_CRED = bytes.fromhex("d08c9ddf0115d1118c7a00c04fc297eb")
GUID_MK   = bytes.fromhex("33f19f5ee340be4a8a2e2b4e62bd0cc6")
CALG_AES_256, CALG_SHA_512 = 0x6610, 0x800e

# ---- The two VPOL AES keys (cleartext that the VPOL DPAPI blob protects) ----
AESKEY1 = bytes(range(0x10,0x30)); AESKEY2 = bytes(range(0x40,0x60))
def make_bcrypt(aes_key):
    header = struct.pack('<LLL', 0x4d42444b, 1, len(aes_key)) + aes_key
    size = len(header) + 8
    return struct.pack('<LLL', size, 1, 0) + header
VPOL_KEYS_CLEARTEXT = make_bcrypt(AESKEY1) + make_bcrypt(AESKEY2)
# sanity: impacket extracts them back
k = VAULT_VPOL_KEYS(VPOL_KEYS_CLEARTEXT)
assert k['Key1']['bKeyBlob']['bKey']==AESKEY1 and k['Key2']['bKeyBlob']['bKey']==AESKEY2

# ---- DPAPI-encrypt VPOL_KEYS_CLEARTEXT into a DPAPI blob (AES256/SHA512, no entropy) ----
def mint_dpapi_blob(cleartext, salt):
    keyHash = SHA1.new(MK).digest()
    sessionKey = HMAC.new(keyHash, salt, SHA512).digest()
    derivedKey = sessionKey  # 64 >= 48
    encKey = derivedKey[:32]; iv = b'\x00'*16
    ct = AES.new(encKey, AES.MODE_CBC, iv=iv).encrypt(pad(cleartext, 16))
    def lp(b): return struct.pack("<L", len(b)) + b
    desc="\x00\x00".encode("latin-1"); HMac=bytes(64)
    pre  = struct.pack("<L",1)+GUID_CRED+struct.pack("<L",1)+GUID_MK+struct.pack("<L",0)
    pre += lp(desc)+struct.pack("<L",CALG_AES_256)+struct.pack("<L",256)+lp(salt)
    pre += lp(b'')+struct.pack("<L",CALG_SHA_512)+struct.pack("<L",512)+lp(HMac)+lp(ct)
    Sign = HMAC.new(keyHash, HMac, SHA512); Sign.update(pre[20:]); Sign=Sign.digest()
    return pre + lp(Sign)
vpol_blob = mint_dpapi_blob(VPOL_KEYS_CLEARTEXT, bytes.fromhex("1122334455667788112233445566778811223344556677881122334455667788"))
assert DPAPI_BLOB(vpol_blob).decrypt(MK) == VPOL_KEYS_CLEARTEXT

# ---- Build the VAULT_VPOL file around that blob ----
def build_vpol_file(blob):
    desc = "vpol\x00".encode("utf-16le")
    out  = struct.pack("<L",1)              # Version
    out += bytes(16)                        # Guid
    out += struct.pack("<L",len(desc)) + desc
    out += bytes(12)                        # Unknown
    out += struct.pack("<L", 0)             # Size (cosmetic for our parse)
    out += bytes(16) + bytes(16)            # Guid2, Guid3
    out += struct.pack("<L", len(blob)) + blob   # KeySize + Blob
    return out
vpol_file = build_vpol_file(vpol_blob)
vp = VAULT_VPOL(vpol_file)
assert vp['Blob'].decrypt(MK) == VPOL_KEYS_CLEARTEXT
print("VPOL roundtrip OK; vpol decrypts to VAULT_VPOL_KEYS, key1 =", AESKEY1.hex())

# ---- Build a VCRD whose attribute decrypts (AES-CBC, key1) to a VAULT_INTERNET_EXPLORER ----
# Inner cleartext schema:
def build_ie_cleartext(user, resource, password):
    u=user.encode("utf-16le"); r=resource.encode("utf-16le"); p=password.encode("utf-16le")
    out = struct.pack("<LLL", 1, 3, 0)      # Version, Count, Unknown
    out += struct.pack("<L", 1) + struct.pack("<L", len(u)) + u   # Id1, UsernameLen, Username
    out += struct.pack("<L", 2) + struct.pack("<L", len(r)) + r   # Id2, ResourceLen, Resource
    out += struct.pack("<L", 3) + struct.pack("<L", len(p)) + p   # Id3, PasswordLen, Password
    return out
IE_USER="alice@example.com"; IE_RES="https://portal.example.com"; IE_PWD="V@ultP4ss!"
ie_clear = build_ie_cleartext(IE_USER, IE_RES, IE_PWD)
# AES-CBC encrypt with key1, IV present (16 random bytes). impacket: attribute['Data'] is ciphertext.
IV = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
attr_ct = AES.new(AESKEY1, AES.MODE_CBC, iv=IV).encrypt(pad(ie_clear, 16))
# decryption in example does NOT unpad -> cleartext may carry PKCS7 padding; schema parse ignores trailing.

# Build a single VAULT_ATTRIBUTE (id >= 100, extended w/ IV) so attributesLen>28 triggers decrypt.
def build_attribute(attr_id, iv, data):
    # Id(4) Unknown1(4) Unknown2(4) Unknown3(4) [pad 6 if bytes16..22==0] [id100: Unknown5(4) if Id>=100]
    #   Size(4) IVPresent(1) IVSize(4) IV(IVSize) Data(Size - IVSize - 5)
    body = struct.pack("<LLLL", attr_id, 0, 0, 0)
    body += b'\x00'*6                # padding (bytes 16..22 == 0 -> impacket adds 'padding')
    body += struct.pack("<L", 0)     # id100 Unknown5 (Id>=100)
    size = len(iv) + len(data) + 5   # Size = IVSize + len(Data) + 5 (IVPresent path)
    body += struct.pack("<L", size)
    body += struct.pack("<B", 1)     # IVPresent
    body += struct.pack("<L", len(iv))
    body += iv
    body += data
    return body
attr = build_attribute(100, IV, attr_ct)

def build_vcrd(friendly, attributes):
    # SchemaGuid(16) Unknown0(4) LastWritten(8) Unknown1(4) Unknown2(4)
    # FriendlyNameLen(4) FriendlyName Var  AttributesMapsSize(4) AttributeMaps  Data
    fn = (friendly+"\x00").encode("utf-16le")
    head = bytes(16) + struct.pack("<L",0) + struct.pack("<Q",0x01d8000000000000) + struct.pack("<LL",0,0)
    head += struct.pack("<L", len(fn)) + fn
    # one map entry: Id(4) Offset(4) Unknown1(4) = 12 bytes
    map_size = 12*len(attributes)
    # Offset is absolute into rawData. Compute after we know header length.
    prefix_len = len(head) + 4 + map_size  # +4 for AttributesMapsSize field
    maps=b''; cur=prefix_len; payload=b''
    for i,a in enumerate(attributes):
        maps += struct.pack("<LLL", 100+i, cur, 0)
        payload += a; cur += len(a)
    out = head + struct.pack("<L", map_size) + maps + payload
    return out
vcrd_file = build_vcrd("Windows Web Password Credential", [attr])

# ---- Confirm via impacket: VCRD parses, attribute AES-CBC-decrypts with key1 to IE schema ----
blob = VAULT_VCRD(vcrd_file)
cleartext=None
for i, entry in enumerate(blob.attributesLen):
    if entry > 28:
        attribute = blob.attributes[i]
        if 'IV' in attribute.fields and len(attribute['IV'])==16:
            cipher = AES.new(AESKEY1, AES.MODE_CBC, iv=attribute['IV'])
        else:
            cipher = AES.new(AESKEY1, AES.MODE_CBC)
        cleartext = cipher.decrypt(attribute['Data'])
assert cleartext is not None, "no attribute decrypted"
fn = blob['FriendlyName'].decode('utf-16le')[:-1]
print("VCRD FriendlyName:", fn, "| known schema:", fn in VAULT_KNOWN_SCHEMAS)
ie = VAULT_INTERNET_EXPLORER(cleartext)
print("impacket IE Username:", ie['Username'].decode('utf-16le'))
print("impacket IE Resource:", ie['Resource'].decode('utf-16le'))
print("impacket IE Password:", ie['Password'].decode('utf-16le'))
print()
print("MASTER_KEY_HEX:", MK.hex())
print("VPOL_FILE_HEX:", vpol_file.hex())
print("VPOL_KEYS_CLEARTEXT_HEX:", VPOL_KEYS_CLEARTEXT.hex())
print("AESKEY1_HEX:", AESKEY1.hex())
print("VCRD_FILE_HEX:", vcrd_file.hex())
print("ATTR_IV_HEX:", IV.hex())
print("EXPECT_USER:", IE_USER); print("EXPECT_RES:", IE_RES); print("EXPECT_PWD:", IE_PWD)
