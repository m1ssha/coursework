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