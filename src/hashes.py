"""
Hashing functions and pseudo-random generators (tweakables)
"""

from src.utils import *
from src.parameters import *
from src.ADRS import *
import math
import hashlib
import random

def hash(seed, adrs: ADRS, value, n=None):
    if n is None:
        params = get_parameters()
        n = params["n"]
    m = hashlib.sha256()

    m.update(seed)
    m.update(adrs.to_bin())
    m.update(value)

    hashed = m.digest()[:n]
    return hashed

def prf(secret_seed, adrs, params=None):
    if params is None:
        params = get_parameters()
    n = params["n"]
    
    random.seed(int.from_bytes(secret_seed + adrs.to_bin(), "big"))
    return random.randint(0, 256 ** n).to_bytes(n, byteorder='big')

def hash_msg(r, public_seed, public_root, value, digest_size=None, params=None):
    if params is None:
        params = get_parameters()
    if digest_size is None:
        digest_size = params["n"]
    
    m = hashlib.sha256()

    m.update(r)
    m.update(public_seed)
    m.update(public_root)
    m.update(value)

    hashed = m.digest()[:digest_size]

    i = 0
    while len(hashed) < digest_size:
        i += 1
        m = hashlib.sha256()

        m.update(r)
        m.update(public_seed)
        m.update(public_root)
        m.update(value)
        m.update(bytes([i]))

        hashed += m.digest()[:digest_size - len(hashed)]

    return hashed

def prf_msg(secret_seed, opt, m, params=None):
    if params is None:
        params = get_parameters()
    n = params["n"]
    
    random.seed(int.from_bytes(secret_seed + opt + hash_msg(b'0', b'0', b'0', m, n*2, params=params), "big"))
    return random.randint(0, 256 ** n).to_bytes(n, byteorder='big')

def base_w(x, w, out_len):
    vin = 0
    vout = 0
    total = 0
    bits = 0
    basew = []

    for consumed in range(0, out_len):
        if bits == 0:
            total = x[vin]
            vin += 1
            bits += 8
        bits -= math.floor(math.log(w, 2))
        basew.append((total >> bits) % w)
        vout += 1

    return basew

def sig_wots_from_sig_xmss(sig, params=None):
    if params is None:
        params = get_parameters()
    n = params["n"]
    w = params["w"]
    len_1 = math.ceil(8 * n / math.log(w, 2))
    len_2 = math.floor(math.log(len_1 * (w - 1), 2) / math.log(w, 2)) + 1
    len_0 = len_1 + len_2
    
    return sig[0:len_0]

def auth_from_sig_xmss(sig, params=None):
    if params is None:
        params = get_parameters()
    n = params["n"]
    w = params["w"]
    len_1 = math.ceil(8 * n / math.log(w, 2))
    len_2 = math.floor(math.log(len_1 * (w - 1), 2) / math.log(w, 2)) + 1
    len_0 = len_1 + len_2
    
    return sig[len_0:]

def sigs_xmss_from_sig_ht(sig, params=None):
    if params is None:
        params = get_parameters()
    d = params["d"]
    h = params["h"]
    h_prime = h // d
    n = params["n"]
    w = params["w"]
    len_1 = math.ceil(8 * n / math.log(w, 2))
    len_2 = math.floor(math.log(len_1 * (w - 1), 2) / math.log(w, 2)) + 1
    len_0 = len_1 + len_2
    
    expected_length = d * (h_prime + len_0)
    if len(sig) != expected_length:
        print(f"sigs_xmss_from_sig_ht: sig length = {len(sig)}, expected = {expected_length}")
    
    sigs = []
    for i in range(0, d):
        start = i * (h_prime + len_0)
        end = (i + 1) * (h_prime + len_0)
        sigs.append(sig[start:end])
    return sigs

def auths_from_sig_fors(sig, params=None):
    if params is None:
        params = get_parameters()
    k = params["k"]
    a = params["a"]

    expected_length = k * (a + 1)
    if len(sig) != expected_length:
        print(f"auths_from_sig_fors: sig length = {len(sig)}, expected = {expected_length}")
        return []

    sigs = []
    step = a + 1
    for i in range(0, k):
        start = i * step
        sk = sig[start]
        auth = sig[start + 1:start + step]
        sigs.append([sk, auth])
    return sigs