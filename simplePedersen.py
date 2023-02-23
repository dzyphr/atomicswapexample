import collections
import hashlib
import random
import binascii
import sys
import libnum
from ECC import *
p1SecretKey, p1PublicKey = gen_keypair()
p2SecretKey, p2PublicKey = gen_keypair()
r1 = random.randrange(0, pow(2, 256)-1)
r2 = random.randrange(0, pow(2, 256)-1)
v1 = random.randrange(0, pow(2, 256)-1)
v2 = random.randrange(0, pow(2, 256)-1)
r3= r1 + r2
v3= v1 + v2

va = add_points(scalar_mult(r1*p2SecretKey, curve.g), scalar_mult(v1*p2SecretKey, curve.g))
vb = add_points(scalar_mult(r2*p2SecretKey, curve.g), scalar_mult(v2*p2SecretKey, curve.g))
vr1 = add_points(va, vb)

print ("Transaction (r1*G + v1*G) + (r2*G +v2*G): ",vr1)

vr2 = add_points(scalar_mult(r3*p2SecretKey, curve.g), scalar_mult(v3 * p2SecretKey, curve.g))
print ("Transaction (r3*G + v3*G): ",vr2)
print ("\nNow let's compare...")
if (vr1[0]==vr2[0]):
    print(vr1[0], "==", vr2[0])
    print ("Success! This proves that the sum of the fully known value+blinding combinations multiplied by the generator is equal to the sum  of the zero knowlege blinded values multiplied the generator")
else:
	print ("Failure!")

