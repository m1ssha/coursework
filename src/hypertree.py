"""
Hypertree function based on XMSS Subs-Trees
"""

from src.parameters import *
from src.hashes import *
from src.ADRS import *
from src.xmss import *

def ht_pk_gen(secret_seed, public_seed, params=None):
    if params is None:
        params = get_parameters()
    d = params["d"]

    adrs = ADRS()
    adrs.set_layer_address(d - 1)
    adrs.set_tree_address(0)
    root = xmss_pk_gen(secret_seed, public_seed, adrs.copy(), params=params)
    return root

def ht_sign(m, secret_seed, public_seed, idx_tree, idx_leaf, params=None):
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

    adrs = ADRS()
    adrs.set_layer_address(0)
    adrs.set_tree_address(idx_tree)

    sig_tmp = xmss_sign(m, secret_seed, idx_leaf, public_seed, adrs.copy(), params=params)
    sig_ht = sig_tmp
    root = xmss_pk_from_sig(idx_leaf, sig_tmp, m, public_seed, adrs.copy(), params=params)

    for j in range(1, d):
        idx_leaf = idx_tree % (2 ** h_prime)
        idx_tree = idx_tree >> h_prime

        adrs.set_layer_address(j)
        adrs.set_tree_address(idx_tree)

        sig_tmp = xmss_sign(root, secret_seed, idx_leaf, public_seed, adrs.copy(), params=params)
        sig_ht = sig_ht + sig_tmp

        if j < d - 1:
            root = xmss_pk_from_sig(idx_leaf, sig_tmp, root, public_seed, adrs.copy(), params=params)

    expected_length = d * (h_prime + len_0)
    print(f"ht_sign: sig_ht length = {len(sig_ht)}, expected = {expected_length}")
    if len(sig_ht) != expected_length:
        raise ValueError(f"ht_sign: Invalid sig_ht length: {len(sig_ht)} != {expected_length}")
    return sig_ht

def ht_verify(m, sig_ht, public_seed, idx_tree, idx_leaf, public_key_ht, params=None):
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

    adrs = ADRS()

    sigs_xmss = sigs_xmss_from_sig_ht(sig_ht, params=params)
    expected_length = d * (h_prime + len_0)
    print(f"ht_verify: sig_ht length = {len(sig_ht)}, expected = {expected_length}")
    print(f"ht_verify: sigs_xmss length = {len(sigs_xmss)}, expected = {d}")
    if len(sigs_xmss) != d:
        print(f"ht_verify: Invalid sigs_xmss length: {len(sigs_xmss)} != {d}")
        return False

    sig_tmp = sigs_xmss[0]
    adrs.set_layer_address(0)
    adrs.set_tree_address(idx_tree)
    node = xmss_pk_from_sig(idx_leaf, sig_tmp, m, public_seed, adrs, params=params)
    if node is None:
        print("ht_verify: Failed to compute node for layer 0")
        return False

    for j in range(1, d):
        idx_leaf = idx_tree % (2 ** h_prime)
        idx_tree = idx_tree >> h_prime

        sig_tmp = sigs_xmss[j]
        adrs.set_layer_address(j)
        adrs.set_tree_address(idx_tree)
        node = xmss_pk_from_sig(idx_leaf, sig_tmp, node, public_seed, adrs, params=params)
        if node is None:
            print(f"ht_verify: Failed to compute node for layer {j}")
            return False

    return node == public_key_ht