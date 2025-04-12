#mcdouglasx
import hashlib
import base58
import bip32utils
import ecdsa
from ecdsa.util import string_to_number
from ecdsa.curves import SECP256k1
import addr

def sha256(d):
    return hashlib.sha256(d).digest()

def ripemd160(d):
    h = hashlib.new('ripemd160')
    h.update(d)
    return h.digest()

def bech32_polymod(vals):
    gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in vals:
        b = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk

def bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def bech32_chksum(hrp, data, bech32m=False):
    vals = bech32_hrp_expand(hrp) + data
    const = 0x2bc830a3 if bech32m else 1
    poly = bech32_polymod(vals + [0,0,0,0,0,0]) ^ const
    return [(poly >> 5 * (5 - i)) & 31 for i in range(6)]

def bech32_encode(hrp, data, bech32m=False):
    comb = data + bech32_chksum(hrp, data, bech32m)
    charset = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
    return hrp + '1' + ''.join([charset[d] for d in comb])

def conv_bits(d, f_bits, t_bits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << t_bits) - 1
    for v in d:
        if v < 0 or v >> f_bits:
            raise ValueError("Invalid value")
        acc = (acc << f_bits) | v
        bits += f_bits
        while bits >= t_bits:
            bits -= t_bits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (t_bits - bits)) & maxv)
    elif bits >= f_bits or ((acc << (t_bits - bits)) & maxv):
        raise ValueError("Invalid bits")
    return ret

def bch_addr(pubk):
    s256 = sha256(pubk)
    rmd = ripemd160(s256)
    data = conv_bits(rmd, 8, 5)
    data = [0] + data
    hrp = "bc"
    return bech32_encode(hrp, data)

def p2sh_p2wpkh(pubk):
    s256 = sha256(pubk)
    rmd = ripemd160(s256)
    scr = b'\x00\x14' + rmd
    scr_hash = ripemd160(sha256(scr))
    return base58.b58encode_check(b'\x05' + scr_hash).decode()

def tag_hash(tag, data):
    t_hash = sha256(tag.encode("utf-8"))
    return sha256(t_hash + t_hash + data)

def tap_tweak(pubk, m_root=None):
    if m_root is None:
        return tag_hash("TapTweak", pubk)
    else:
        return tag_hash("TapTweak", pubk + m_root)

def xonly_pubk(privk):
    sk = ecdsa.SigningKey.from_string(privk, curve=SECP256k1)
    vk = sk.get_verifying_key()
    return vk.to_string("compressed")[1:]

def tweak_pubk(pubk, m_root=None):
    if len(pubk) != 32:
        raise ValueError("X-only pubkey must be 32 bytes")
    t = tap_tweak(pubk, m_root)
    t_int = string_to_number(t)
    pubk_pt = ecdsa.VerifyingKey.from_string(b'\x02' + pubk, curve=SECP256k1).pubkey.point
    tweaked_pt = pubk_pt + (SECP256k1.generator * t_int)
    tweaked = ecdsa.VerifyingKey.from_public_point(tweaked_pt, curve=SECP256k1).to_string("compressed")[1:]
    return tweaked

def taproot_addr(pubk, m_root=None):
    tweaked = tweak_pubk(pubk, m_root)
    prog = [0x01] + list(conv_bits(tweaked, 8, 5))
    return bech32_encode("bc", prog, bech32m=True)

def derive_addrs(xprv, drv):
    root_key = bip32utils.BIP32Key.fromExtendedKey(xprv)
    drv = int(drv)
    res = "Extended Privkey Generation:\n"
    for standard, coin, label, func in [
          ("BIP84", 84, "p2wpkh", lambda k: bch_addr(bytes.fromhex(k.PublicKey().hex()))),
          ("BIP44", 44, "p2pkh", lambda k: k.Address()),
          ("BIP49", 49, "p2wpkh-p2sh", lambda k: p2sh_p2wpkh(bytes.fromhex(k.PublicKey().hex()))),
          ("BIP86", 86, "p2tr", lambda k: taproot_addr(xonly_pubk(k.PrivateKey())))]:
        for branch, branch_name in [(0, "Receiving"), (1, "Change")]:
            for i in range(drv):
                key = root_key.ChildKey(coin+0x80000000)\
                              .ChildKey(0+0x80000000)\
                              .ChildKey(0+0x80000000)\
                              .ChildKey(branch)\
                              .ChildKey(i)
                wif = key.WalletImportFormat()
                derived_addr = func(key)
                res += f"{standard} {branch_name} Address {i}:\n {label}:{wif}\nAddress: {derived_addr}\n\n"
    return res

def dump_descriptor(xprv, wallet_file):

    wallet_addrs = set(addr.extract_addrs(wallet_file))
    res = "Dump Descriptor Matches:\n"
    found = set()
    root_key = bip32utils.BIP32Key.fromExtendedKey(xprv)
    max_iterations = 5000
    progress_threshold = 200
    standards = [
        ("BIP84", 84, "p2wpkh", lambda k: bch_addr(bytes.fromhex(k.PublicKey().hex()))),
        ("BIP44", 44, "p2pkh", lambda k: k.Address()),
        ("BIP49", 49, "p2wpkh-p2sh", lambda k: p2sh_p2wpkh(bytes.fromhex(k.PublicKey().hex()))),
        ("BIP86", 86, "p2tr", lambda k: taproot_addr(xonly_pubk(k.PrivateKey())))
    ]
    for standard, coin, label, func in standards:
        for branch in [0, 1]:
            i = 0
            no_progress = 0
            while i < max_iterations and no_progress < progress_threshold:
                key = root_key.ChildKey(coin+0x80000000)\
                              .ChildKey(0+0x80000000)\
                              .ChildKey(0+0x80000000)\
                              .ChildKey(branch)\
                              .ChildKey(i)
                wif = key.WalletImportFormat()
                derived_addr = func(key)
                if derived_addr in wallet_addrs and derived_addr not in found:
                    res += f"{standard} ({'Receiving' if branch==0 else 'Change'}) ({i}):\nPrivate Key: {wif}\nAddress: {derived_addr}\n\n"
                    found.add(derived_addr)
                    no_progress = 0
                else:
                    no_progress += 1
                i += 1
    res += f"\nTotal addresses in wallet file: {len(wallet_addrs)}. Exported: {len(found)}.\n"
    return res

def export_to_electrum(xprv, wallet_file="", drv=None):

    res = ""
    if wallet_file and wallet_file.strip() != "":
        wallet_addrs = set(addr.extract_addrs(wallet_file))
        found = set()
        root_key = bip32utils.BIP32Key.fromExtendedKey(xprv)
        max_iterations = 5000
        progress_threshold = 200
        for standard, coin, label, func in [
              ("p2wpkh", 84, "p2wpkh", lambda k: bch_addr(bytes.fromhex(k.PublicKey().hex()))),
              ("p2pkh", 44, "p2pkh", lambda k: k.Address()),
              ("p2wpkh-p2sh", 49, "p2wpkh-p2sh", lambda k: p2sh_p2wpkh(bytes.fromhex(k.PublicKey().hex())))]:
            for branch in [0, 1]:
                i = 0
                no_progress = 0
                while i < max_iterations and no_progress < progress_threshold:
                    key = root_key.ChildKey(coin+0x80000000)\
                                  .ChildKey(0+0x80000000)\
                                  .ChildKey(0+0x80000000)\
                                  .ChildKey(branch)\
                                  .ChildKey(i)
                    derived_addr = func(key)
                    if derived_addr in wallet_addrs and derived_addr not in found:
                        res += f"{label}:{key.WalletImportFormat()}\n"
                        found.add(derived_addr)
                        no_progress = 0
                    else:
                        no_progress += 1
                    i += 1
        return res
    else:
        if drv is None:
            raise ValueError("No wallet file provided and no derivation count specified.")
        root_key = bip32utils.BIP32Key.fromExtendedKey(xprv)
        for standard, coin, label, func in [
              ("p2wpkh", 84, "p2wpkh", lambda k: bch_addr(bytes.fromhex(k.PublicKey().hex()))),
              ("p2pkh", 44, "p2pkh", lambda k: k.Address()),
              ("p2wpkh-p2sh", 49, "p2wpkh-p2sh", lambda k: p2sh_p2wpkh(bytes.fromhex(k.PublicKey().hex())))]:
            for branch in [0, 1]:
                for i in range(drv):
                    key = root_key.ChildKey(coin+0x80000000)\
                                  .ChildKey(0+0x80000000)\
                                  .ChildKey(0+0x80000000)\
                                  .ChildKey(branch)\
                                  .ChildKey(i)
                    res += f"{label}:{key.WalletImportFormat()}\n"
        return res

if __name__ == "__main__":
    xpriv_input = input("Introduce xprv: ")
    wallet_file = input("Path to wallet file (.dat) [or leave empty for extended privkey mode]: ")
    if wallet_file.strip() == "":
        drv_input = int(input("Number of derivations: "))
        print("Export to Electrum (Extended privkey mode):\n")
        print(export_to_electrum(xpriv_input, "", drv_input))
    else:
        print("Dump Descriptor:\n")
        print(dump_descriptor(xpriv_input, wallet_file))
        print("\nExport to Electrum (Dump Descriptor mode):\n")
        print(export_to_electrum(xpriv_input, wallet_file))
