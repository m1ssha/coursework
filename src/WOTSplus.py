from src.parameters import *
from src.hashes import *
from src.ADRS import *
import math

def chain(x, i, s, public_seed, adrs: ADRS, params=None):
    if params is None:
        params = get_parameters()
    w = params["w"]

    if s == 0:
        return bytes(x)

    if (i + s) > (w - 1):
        return -1

    tmp = chain(x, i, s - 1, public_seed, adrs, params=params)

    adrs.set_hash_address(i + s - 1)
    tmp = hash(public_seed, adrs, tmp, params["n"])

    return tmp

def wots_sk_gen(secret_seed, adrs: ADRS, params=None):
    if params is None:
        params = get_parameters()
    n = params["n"]
    w = params["w"]
    len_1 = math.ceil(8 * n / math.log(w, 2))
    len_2 = math.floor(math.log(len_1 * (w - 1), 2) / math.log(w, 2)) + 1
    len_0 = len_1 + len_2

    sk = []
    for i in range(0, len_0):
        adrs.set_chain_address(i)
        adrs.set_hash_address(0)
        sk.append(prf(secret_seed, adrs.copy(), params=params))
    return sk

def wots_pk_gen(secret_seed, public_seed, adrs: ADRS, params=None):
    if params is None:
        params = get_parameters()
    n = params["n"]
    w = params["w"]
    len_1 = math.ceil(8 * n / math.log(w, 2))
    len_2 = math.floor(math.log(len_1 * (w - 1), 2) / math.log(w, 2)) + 1
    len_0 = len_1 + len_2

    wots_pk_adrs = adrs.copy()
    tmp = bytes()
    for i in range(0, len_0):
        adrs.set_chain_address(i)
        adrs.set_hash_address(0)
        sk = prf(secret_seed, adrs.copy(), params=params)
        tmp += bytes(chain(sk, 0, w - 1, public_seed, adrs.copy(), params=params))

    wots_pk_adrs.set_type(ADRS.WOTS_PK)
    wots_pk_adrs.set_key_pair_address(adrs.get_key_pair_address())

    pk = hash(public_seed, wots_pk_adrs, tmp, n)
    return pk

def wots_sign(m, secret_seed, public_seed, adrs, params=None):
    if params is None:
        params = get_parameters()
    n = params["n"]
    w = params["w"]
    len_1 = math.ceil(8 * n / math.log(w, 2))
    len_2 = math.floor(math.log(len_1 * (w - 1), 2) / math.log(w, 2)) + 1
    len_0 = len_1 + len_2

    csum = 0

    msg = base_w(m, w, len_1)

    for i in range(0, len_1):
        csum += w - 1 - msg[i]

    padding = (len_2 * math.floor(math.log(w, 2))) % 8 if (len_2 * math.floor(math.log(w, 2))) % 8 != 0 else 8
    csum = csum << (8 - padding)
    csumb = csum.to_bytes(math.ceil((len_2 * math.floor(math.log(w, 2))) / 8), byteorder='big')
    csumw = base_w(csumb, w, len_2)
    msg += csumw

    sig = []
    for i in range(0, len_0):
        adrs.set_chain_address(i)
        adrs.set_hash_address(0)
        sk = prf(secret_seed, adrs.copy(), params=params)
        sig += [chain(sk, 0, msg[i], public_seed, adrs.copy(), params=params)]

    if len(sig) != len_0:
        print(f"wots_sign: sig length = {len(sig)}, expected = {len_0}")
    return sig

def wots_pk_from_sig(sig, m, public_seed, adrs: ADRS, params=None):
    if params is None:
        params = get_parameters()
    n = params["n"]
    w = params["w"]
    len_1 = math.ceil(8 * n / math.log(w, 2))
    len_2 = math.floor(math.log(len_1 * (w - 1), 2) / math.log(w, 2)) + 1
    len_0 = len_1 + len_2

    if len(sig) != len_0:
        print(f"wots_pk_from_sig: sig length = {len(sig)}, expected = {len_0}")
        return None

    csum = 0
    wots_pk_adrs = adrs.copy()

    msg = base_w(m, w, len_1)

    for i in range(0, len_1):
        csum += w - 1 - msg[i]

    padding = (len_2 * math.floor(math.log(w, 2))) % 8 if (len_2 * math.floor(math.log(w, 2))) % 8 != 0 else 8
    csum = csum << (8 - padding)
    csumb = csum.to_bytes(math.ceil((len_2 * math.floor(math.log(w, 2))) / 8), byteorder='big')
    csumw = base_w(csumb, w, len_2)
    msg += csumw

    tmp = bytes()
    for i in range(0, len_0):
        adrs.set_chain_address(i)
        tmp += chain(sig[i], msg[i], w - 1 - msg[i], public_seed, adrs.copy(), params=params)

    wots_pk_adrs.set_type(ADRS.WOTS_PK)
    wots_pk_adrs.set_key_pair_address(adrs.get_key_pair_address())
    pk_sig = hash(public_seed, wots_pk_adrs, tmp, n)
    return pk_sig