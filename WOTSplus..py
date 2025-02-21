import math
import functions

class WOTSplus(object):

    def __init__(self, n, w, F, Gl):
        self.n = n
        self.w = w
        self.len1 = math.ceil(n / math.log2(w))
        self.len2 = math.floor(math.log2(self.len1 * (w - 1)) / math.log2(w)) + 1
        self.len = self.len1 + self.len2
        self.F = F
        self.Gl = lambda seed: Gl(seed = seed, n = self.len * self.n // 8)

    
    def chain(self, x, masks, chainrange):
        x = list(x)
        for i in range(self.len):
            for j in chainrange[i]:
                x[i] = self.F(functions.xor(x[i], masks[j]))
        
        return x
    

    def int_to_basew(self, x, base):
        for _ in range(self.len1):
            yield x % base
            x //= base


    def chainlenghts(self, m):
        M = int.from_bytes(m, byteorder="little")
        M = list(self.int_to_basew(M, self.w))
        C = sum(self.w - 1 - M[i] for i in range(self.len1))
        C = list(self.int_to_basew(C, self.w))

        return M + C
    

    def keygen(self, seed, masks):
        sk = self.Gl(seed)
        sk = function.chunkbytes(sk, self.n // 8)

        return self.chains(sk, masks, [range(0, self.w - 1)] * self.len)
    
    
    def sign(self, m, seed, masks):
        sk = self.Gl(seed)
        sk = function.chunkbytes(sk, self.n // 8)
        B = self.chainlenghts(m)

        return self.chains(sk, masks, [range(0, b) for b in B])
    

    def verify(self, m, sig, masks):
        B = self.chainlenghts(m)

        return self.chains(sig, masks, [range(b, self.w - 1) for b in B])