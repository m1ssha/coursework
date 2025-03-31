import math

RANDOMIZE = True

def get_parameters(instance="128s"):
    params = {
        "128s": {"n": 16, "w": 16, "h": 63, "d": 7, "k": 10, "a": 14},
        "128f": {"n": 16, "w": 16, "h": 66, "d": 22, "k": 33, "a": 9},
        "192s": {"n": 24, "w": 16, "h": 63, "d": 7, "k": 14, "a": 15},
        "192f": {"n": 24, "w": 16, "h": 66, "d": 22, "k": 31, "a": 11},
        "256s": {"n": 32, "w": 16, "h": 64, "d": 8, "k": 17, "a": 15},
        "256f": {"n": 32, "w": 16, "h": 68, "d": 17, "k": 35, "a": 12}
    }
    return params.get(instance, params["128s"])

params = get_parameters()
n = params["n"]
w = params["w"]
h = params["h"]
d = params["d"]
k = params["k"]
a = params["a"]


# Message Lengt for WOTS
len_1 = math.ceil(8 * n / math.log(w, 2))
len_2 = math.floor(math.log(len_1 * (w - 1), 2) / math.log(w, 2)) + 1
len_0 = len_1 + len_2

# XMSS Sub-Trees height
h_prime = h // d

# FORS trees leaves number
t = 2**a