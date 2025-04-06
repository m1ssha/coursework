"""
FORS Function
"""

from src.parameters import *
from src.hashes import *
from src.ADRS import *
import math

def fors_sk_gen(secret_seed, adrs: ADRS, idx, params=None):
    if params is None:
        params = get_parameters()

    adrs.set_tree_height(0)
    adrs.set_tree_index(idx)
    sk = prf(secret_seed, adrs.copy(), params=params)

    return sk

def fors_treehash(secret_seed, s, z, public_seed, adrs, params=None):
    if params is None:
        params = get_parameters()
    n = params["n"]

    if s % (1 << z) != 0:
        return -1

    stack = []

    for i in range(0, 2**z):
        adrs.set_tree_height(0)
        adrs.set_tree_index(s + i)
        sk = prf(secret_seed, adrs.copy(), params=params)
        node = hash(public_seed, adrs.copy(), sk, n)

        adrs.set_tree_height(1)
        adrs.set_tree_index(s + i)
        if len(stack) > 0:
            while stack[len(stack) - 1]['height'] == adrs.get_tree_height():
                adrs.set_tree_index((adrs.get_tree_index() - 1) // 2)
                node = hash(public_seed, adrs.copy(), stack.pop()['node'] + node, n)

                adrs.set_tree_height(adrs.get_tree_height() + 1)

                if len(stack) <= 0:
                    break
        stack.append({'node': node, 'height': adrs.get_tree_height()})

    return stack.pop()['node']

def fors_pk_gen(secret_seed, public_seed, adrs: ADRS, params=None):
    if params is None:
        params = get_parameters()
    k = params["k"]
    a = params["a"]
    t = 2 ** a

    fors_pk_adrs = adrs.copy()

    root = bytes()
    for i in range(0, k):
        root += fors_treehash(secret_seed, i * t, a, public_seed, adrs, params=params)

    fors_pk_adrs.set_type(ADRS.FORS_ROOTS)
    fors_pk_adrs.set_key_pair_address(adrs.get_key_pair_address())
    pk = hash(public_seed, fors_pk_adrs, root, params["n"])
    return pk

def fors_sign(m, secret_seed, public_seed, adrs, params=None):
    if params is None:
        params = get_parameters()
    k = params["k"]
    a = params["a"]
    t = 2 ** a

    m_int = int.from_bytes(m, 'big')
    sig_fors = []

    for i in range(0, k):
        idx = (m_int >> (k - 1 - i) * a) % t

        adrs.set_tree_height(0)
        adrs.set_tree_index(i * t + idx)
        sig_fors += [prf(secret_seed, adrs.copy(), params=params)]

        auth = []
        for j in range(0, a):
            s = math.floor(idx // 2 ** j)
            if s % 2 == 1:
                s -= 1
            else:
                s += 1
            auth += [fors_treehash(secret_seed, i * t + s * 2**j, j, public_seed, adrs.copy(), params=params)]

        sig_fors += auth

    expected_length = k * (a + 1)
    if len(sig_fors) != expected_length:
        print(f"fors_sign: sig_fors length = {len(sig_fors)}, expected = {expected_length}")
    return sig_fors

def fors_pk_from_sig(sig_fors, m, public_seed, adrs: ADRS, params=None):
    if params is None:
        params = get_parameters()
    k = params["k"]
    a = params["a"]
    t = 2 ** a
    n = params["n"]

    expected_length = k * (a + 1)
    if len(sig_fors) != expected_length:
        print(f"fors_pk_from_sig: sig_fors length = {len(sig_fors)}, expected = {expected_length}")
        return None

    m_int = int.from_bytes(m, 'big')
    sigs = auths_from_sig_fors(sig_fors, params=params)
    root = bytes()

    for i in range(0, k):
        idx = (m_int >> (k - 1 - i) * a) % t

        sk = sigs[i][0]
        adrs.set_tree_height(0)
        adrs.set_tree_index(i * t + idx)
        node_0 = hash(public_seed, adrs.copy(), sk, n)
        node_1 = 0

        auth = sigs[i][1]
        if len(auth) != a:
            print(f"fors_pk_from_sig: auth[{i}] length = {len(auth)}, expected = {a}")
            return None

        adrs.set_tree_index(i * t + idx)
        for j in range(0, a):
            adrs.set_tree_height(j + 1)

            if math.floor(idx / 2**j) % 2 == 0:
                adrs.set_tree_index(adrs.get_tree_index() // 2)
                node_1 = hash(public_seed, adrs.copy(), node_0 + auth[j], n)
            else:
                adrs.set_tree_index((adrs.get_tree_index() - 1) // 2)
                node_1 = hash(public_seed, adrs.copy(), auth[j] + node_0, n)

            node_0 = node_1

        root += node_0

    fors_pk_adrs = adrs.copy()
    fors_pk_adrs.set_type(ADRS.FORS_ROOTS)
    fors_pk_adrs.set_key_pair_address(adrs.get_key_pair_address())

    pk = hash(public_seed, fors_pk_adrs, root, n)
    return pk

def auths_from_sig_fors(sig, params=None):
    if params is None:
        params = get_parameters()
    k = params["k"]
    a = params["a"]

    sigs = []
    step = a + 1
    for i in range(0, k):
        start = i * step
        sk = sig[start]
        auth = sig[start + 1:start + step]
        sigs.append([sk, auth])
    return sigs