# LITCTF 2025 — Crypto: lcgcg

**Category:** Crypto  
**Author:** hihitherethere  
**If first solved:** 

---

## Challenge Description

The challenge introduced the concept of an **LCGCG** (Linear Congruential Generator Congruential Generator). The description hinted:

> The LCGCG is the evolved version of the LCG. But every LCGCG has its origin LCG... could you find its roots?

We were given:
- `main.py` (generator script)
- `out.txt` (three numbers, IV, and ciphertext)

---

## Understanding the Challenge

Reading the provided `main.py` made it clear:
- The challenge builds an LCG repeatedly, nesting it 100 times. This created what they called an **LCGCG**.
- After 100 iterations, the final LCG was used to generate outputs.
- The outputs were then used to derive an AES key, which encrypted the flag.

Key observations:
1. Any **LCG** is defined as:
   ```
   x_{i+1} = (a*x_i + b) mod p
   ```
   where `(a, b, x0)` are parameters.
2. If we know three consecutive outputs `(x1, x2, x3)`, we can solve equations to recover `a` and `b`.
3. In this challenge, the final given numbers were **three consecutive outputs of the last LCG**.

So, we could:
- Recover the last LCG parameters `(a, b, x0)`.
- Treat those `(a, b, x0)` as outputs of the previous LCG.
- Step backwards **100 times** until we recover the original LCG.

Once we had the original seed, we could derive the AES key and decrypt the ciphertext.

---

## Exploit Strategy

1. **Parse out.txt** to extract:
   - `p` (prime modulus)
   - the three outputs of the final LCG
   - IV and ciphertext.
2. **Recover the last LCG parameters** using the formula:
   ```
   a = (x3 - x2) * inverse(x2 - x1, p) mod p
   b = (x2 - a*x1) mod p
   ```
3. Use the recovered `(a, b, x0)` as the *outputs* of the previous LCG.
4. Repeat step 2 **100 times** to go back to the original LCG.
5. With the recovered original LCG seed, compute the next output `r`.
6. Build the AES key as `pad(long_to_bytes(r**2), 16)`.
7. Decrypt the ciphertext with AES-CBC using the given IV.

---

## Exploit Script (solve.py)
```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import long_to_bytes, inverse

p = ...  # extracted from out.txt
out1, out2, out3 = ...  # three final outputs
iv = ...  # from out.txt
ct = ...  # from out.txt

# function to recover LCG params from 3 outputs
def recover(x1, x2, x3, p):
    a = ((x3 - x2) * inverse(x2 - x1, p)) % p
    b = (x2 - a * x1) % p
    return a, b, x1

# walk backwards 100 times
triple = (out1, out2, out3)
for _ in range(100):
    triple = recover(*triple, p)

# the recovered seed is in triple
_, _, x0 = triple

# next output of original LCG
a, b, x = triple
r = (a*x + b) % p

key = pad(long_to_bytes(r*r), 16)
cipher = AES.new(key, AES.MODE_CBC, iv)
flag = unpad(cipher.decrypt(ct), 16)
print(flag.decode())
```

---

## Running the Script
On Kali Linux:
```bash
python3 solve.py
```

Output:
```
LITCTF{wh47_1s_4n_lcgcg?_4_qu4dr4t1c_c0ngru3nt14l_g3nr4t0r?}
```

---

## Conclusion

This challenge was about recognizing that even if an LCG is nested multiple times (LCGCG), its structure leaks enough information to recover the original. By reversing the process step by step, we could peel back 100 layers and finally decrypt the ciphertext.

**Final Flag:**  
`LITCTF{wh47_1s_4n_lcgcg?_4_qu4dr4t1c_c0ngru3nt14l_g3nr4t0r?}`

