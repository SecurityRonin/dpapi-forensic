import struct
from impacket.dpapi import DPAPI_BLOB
from Crypto.Hash import SHA1, SHA512, HMAC
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

MK = bytes.fromhex("9828d9873735439e823dbd216205ff88266d28ad685a413970c640d5ee943154bbade31fada673d542c72d707a163bb3d1bceb0c50465b359ae06998481b0ce3")
GUID_CRED = bytes.fromhex("d08c9ddf0115d1118c7a00c04fc297eb")
GUID_MK   = bytes.fromhex("33f19f5ee340be4a8a2e2b4e62bd0cc6")
CALG_AES_256, CALG_SHA_512 = 0x6610, 0x800e

# Real Wlansvc keyMaterial: the WPA2 PSK is stored as a DPAPI blob over the
# UTF-8 PSK bytes terminated with a NUL (observed format). Model that.
PSK = "CorrectHorseBatteryStaple"
cleartext = PSK.encode("utf-8") + b"\x00"   # trailing NUL as Windows stores it

def mint_dpapi_blob(cleartext, salt, entropy=None):
    keyHash = SHA1.new(MK).digest()
    sk = HMAC.new(keyHash, salt, SHA512)
    if entropy is not None: sk.update(entropy)
    sessionKey = sk.digest()
    derivedKey = sessionKey  # 64 >= 48
    encKey = derivedKey[:32]; iv = b'\x00'*16
    ct = AES.new(encKey, AES.MODE_CBC, iv=iv).encrypt(pad(cleartext, 16))
    def lp(b): return struct.pack("<L", len(b)) + b
    desc="\x00\x00".encode("latin-1"); HMac=bytes(64)
    pre  = struct.pack("<L",1)+GUID_CRED+struct.pack("<L",1)+GUID_MK+struct.pack("<L",0)
    pre += lp(desc)+struct.pack("<L",CALG_AES_256)+struct.pack("<L",256)+lp(salt)
    pre += lp(b'')+struct.pack("<L",CALG_SHA_512)+struct.pack("<L",512)+lp(HMac)+lp(ct)
    Sign = HMAC.new(keyHash, HMac, SHA512)
    if entropy is not None: Sign.update(entropy)
    Sign.update(pre[20:]); Sign=Sign.digest()
    return pre + lp(Sign)

salt = bytes.fromhex("deadbeefcafebabe0011223344556677deadbeefcafebabe0011223344556677")
blob = mint_dpapi_blob(cleartext, salt)
dec = DPAPI_BLOB(blob).decrypt(MK)
print("impacket decrypt raw:", repr(dec))
psk = dec.rstrip(b"\x00").decode("utf-8")
print("impacket PSK:", psk)
assert psk == PSK

# WLAN keyMaterial is the blob hex-encoded (uppercase in the XML, but case-insensitive)
key_material_hex = blob.hex().upper()
print("KEY_MATERIAL_HEX:", key_material_hex)
print("MASTER_KEY_HEX:", MK.hex())
print("EXPECT_PSK:", PSK)

# A minimal WLAN profile XML embedding the keyMaterial (for the thin XML helper test)
xml = f'''<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>HomeNet</name>
  <MSM><security><sharedKey>
    <keyType>passPhrase</keyType>
    <protected>true</protected>
    <keyMaterial>{key_material_hex}</keyMaterial>
  </sharedKey></security></MSM>
</WLANProfile>'''
print("---XML---")
print(xml)
