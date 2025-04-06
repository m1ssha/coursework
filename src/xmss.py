from src.parameters import *
from src.hashes import *
from src.ADRS import *
from src.WOTSplus import *
import math

def treehash(secret_seed, s, z, public_seed, adrs: ADRS, params=None):
    if params is None:
        params = get_parameters()
    n = params["n"]

    if s % (1 << z) != 0:
        return -1

    stack = []

    for i in range(0, 2**z):
        adrs.set_type(ADRS.WOTS_HASH)
        adrs.set_key_pair_address(s + i)
        node = wots_pk_gen(secret_seed, public_seed, adrs.copy(), params=params)

        adrs.set_type(ADRS.TREE)
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

def xmss_pk_gen(secret_seed, public_seed, adrs: ADRS, params=None):
    if params is None:
        params = get_parameters()
    h = params["h"]
    d = params["d"]
    h_prime = h // d

    pk = treehash(secret_seed, 0, h_prime, public_seed, adrs.copy(), params=params)
    return pk

def xmss_sign(m, secret_seed, idx, public_seed, adrs, params=None):
    if params is None:
        params = get_parameters()
    h = params["h"]
    d = params["d"]
    h_prime = h // d
    n = params["n"]
    w = params["w"]
    len_1 = math.ceil(8 * n / math.log(w, 2))
    len_2 = math.floor(math.log(len_1 * (w - 1), 2) / math.log(w, 2)) + 1
    len_0 = len_1 + len_2

    auth = []
    for j in range(0, h_prime):
        ki = math.floor(idx // 2**j)
        if ki % 2 == 1:
            ki -= 1
        else:
            ki += 1
        auth += [treehash(secret_seed, ki * 2**j, j, public_seed, adrs.copy(), params=params)]

    adrs.set_type(ADRS.WOTS_HASH)
    adrs.set_key_pair_address(idx)

    sig = wots_sign(m, secret_seed, public_seed, adrs.copy(), params=params)
    sig_xmss = sig + auth
    
    expected_length = (len_0 + h_prime) * n 
    total_length = sum(len(x) for x in sig_xmss) 
    if total_length != expected_length:
        print(f"xmss_sign: sig_xmss length = {total_length}, expected = {expected_length}")
    return sig_xmss

def xmss_pk_from_sig(idx, sig_xmss, m, public_seed, adrs, params=None):
    if params is None:
        params = get_parameters()
    n = params["n"]
    h = params["h"]
    d = params["d"]
    h_prime = h // d
    w = params["w"]
    len_1 = math.ceil(8 * n / math.log(w, 2))
    len_2 = math.floor(math.log(len_1 * (w - 1), 2) / math.log(w, 2)) + 1
    len_0 = len_1 + len_2

    expected_length = (len_0 + h_prime) * n
    total_length = sum(len(x) for x in sig_xmss)
    if total_length != expected_length:
        print(f"xmss_pk_from_sig: sig_xmss length = {total_length}, expected = {expected_length}")
        return None

    adrs.set_type(ADRS.WOTS_HASH)
    adrs.set_key_pair_address(idx)
    sig = sig_wots_from_sig_xmss(sig_xmss, params=params)  
    auth = auth_from_sig_xmss(sig_xmss, params=params)

    if len(auth) != h_prime:
        print(f"xmss_pk_from_sig: auth length = {len(auth)}, expected = {h_prime}")
        return None

    node_0 = wots_pk_from_sig(sig, m, public_seed, adrs.copy(), params=params)
    node_1 = 0

    adrs.set_type(ADRS.TREE)
    adrs.set_tree_index(idx)
    for i in range(0, h_prime):
        adrs.set_tree_height(i + 1)

        if math.floor(idx / 2**i) % 2 == 0:
            adrs.set_tree_index(adrs.get_tree_index() // 2)
            node_1 = hash(public_seed, adrs.copy(), node_0 + auth[i], n)
        else:
            adrs.set_tree_index((adrs.get_tree_index() - 1) // 2)
            node_1 = hash(public_seed, adrs.copy(), auth[i] + node_0, n)

        node_0 = node_1

    return node_0