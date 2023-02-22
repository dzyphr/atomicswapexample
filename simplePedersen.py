import collections
import hashlib
import random
import binascii
import sys
import libnum

EllipticCurve = collections.namedtuple('EllipticCurve', 'name p a b g n h')

curve = EllipticCurve(
    'secp256k1',
    # Field characteristic.
    p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
    # Curve coefficients.
    a=0,
    b=7,
    # Base point.
    g=(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
       0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8),
    # Subgroup order.
    n=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,
    # Subgroup cofactor.
#    h=1,
)

def is_curve_point(point):
    if point is None:
        return True
    x, y = point
    return (y * y - x * x * x - curve.a * x - curve.b) % curve.p == 0

def add_points(point1, point2):
    assert is_curve_point(point1)
    assert is_curve_point(point2)

    if point1 is None:
        return point2
    if point2 is None:
        return point1
    
    x1, y1 = point1
    x2, y2 = point2

    if x1 == x2 and y1 != y2:
        return None

    if x1 == x2:
        m = (3 * x1 * x1 + curve.a) * libnum.invmod(2 * y1, curve.p)
    else:
        m = (y1 - y2) * libnum.invmod(x1 - x2, curve.p)

    x3 = m * m - x1 - x2
    y3 = y1 + m * (x3 - x1)
    result = (x3 % curve.p, -y3 % curve.p)
    assert is_curve_point(result)
    return result


def invmod(a, n):
    """
    Return 1 / a (mod n).
    @a and @n must be co-primes.
    """
    if n < 2:
        raise ValueError("modulus must be greater than 1")

    x, y, g = xgcd(a, n)

    if g != 1:
        raise ValueError("no invmod for given @a and @n")
    else:
        return x % n

def scalar_mult(k, point):
    assert is_curve_point(point)

    if k % curve.n == 0 or point is None:
        return None

    if k < 0:
        return scalar_mult(-k, point_neg(point))

    result = None
    addend = point

    while k:
        if k & 1:
            result = add_points(result, addend)
        addend = add_points(addend, addend)    
        k >>= 1
            
    assert is_curve_point(result)
    return result

def point_neg(point):
    """Returns -point."""
    assert is_on_curve(point)

    if point is None:
        # -0 = 0
        return None

    x, y = point
    result = (x, -y % curve.p)

    assert is_on_curve(result)

    return result


def gen_keypair():
    private_key = random.randrange(1, curve.n) #should use a HD wallet BIP32 model in practice for generation
    public_key = scalar_mult(private_key, curve.g)
    return private_key, public_key

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
    print ("Success! This proves that the sum of the fully known value+blinding combinations raised to the generator is equal to the sum  of the zero knowlege blinded values raised to the generator")
else:
	print ("Failure!")

