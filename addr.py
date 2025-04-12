import sqlite3
import re

def is_xpub(text):
    patterns = [
        r'\b(xpub|ypub|zpub)[a-km-zA-HJ-NP-Z1-9]{100,}\b',
        r'\b[0-9A-Za-z]{100,}\b'
    ]
    return any(re.search(p, text) for p in patterns)

def is_valid_addr(addr):
    if is_xpub(addr):
        return False
    if addr.startswith('1'):
        return (26 <= len(addr) <= 35 and 
                all(c in '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz' for c in addr))
    elif addr.startswith('3'):
        return (26 <= len(addr) <= 35 and 
                all(c in '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz' for c in addr))
    elif addr.startswith('bc1q'):
        return (len(addr) == 42 and re.match(r'^bc1q[02-9ac-hj-np-z]{39}$', addr))
    elif addr.startswith('bc1p'):
        return (len(addr) == 62 and re.match(r'^bc1p[02-9ac-hj-np-z]{58}$', addr))
    return False

def extract_addrs(wallet_file):
    patterns = [
        r'\b(1[1-9A-HJ-NP-Za-km-z]{25,34})\b',
        r'\b(3[1-9A-HJ-NP-Za-km-z]{25,34})\b',
        r'\b(bc1q[02-9ac-hj-np-z]{39})\b',
        r'\b(bc1p[02-9ac-hj-np-z]{58})\b'
    ]
    addrs = set()
    try:
        conn = sqlite3.connect(wallet_file)
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [t[0] for t in cur.fetchall()]
        for table in tables:
            try:
                cur.execute(f'SELECT * FROM "{table}";')
                for row in cur:
                    for field in row:
                        if isinstance(field, (str, bytes)):
                            text = field.decode('latin-1', errors='ignore') if isinstance(field, bytes) else field
                            if is_xpub(text):
                                continue
                            for p in patterns:
                                matches = re.finditer(p, text)
                                for m in matches:
                                    addr = m.group(1)
                                    if is_valid_addr(addr):
                                        addrs.add(addr)
            except sqlite3.Error:
                continue
    finally:
        conn.close()
    return sorted(addrs)

if __name__ == "__main__":
    wallet = 'wallet.dat'
    found_addrs = extract_addrs(wallet)
    print(f"Valid addresses found ({len(found_addrs)}):")
    for addr in found_addrs:
        print(addr)
