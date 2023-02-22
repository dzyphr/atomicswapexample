import secrets
import hashlib
from ECC import *
#p1 on erg p2 on evm
sha256 = hashlib.sha256()
message = "1000000000" #some public change output value in mimblewimble
print("\nmessage:", message)
p1SecretKey, p1PublicKey = gen_keypair()
print("\np1 pubkey:", p1PublicKey)
p2SecretKey, p2PublicKey = gen_keypair()
print("\np2 pubkey:", p2PublicKey)
#start p1 activity
rs = random.randrange(0, curve.n)#BOTH rs AND ks SHOULD NOT BE REUSED BY ONE SIGNER
ks = random.randrange(0, curve.n)
rsG = scalar_mult(rs, curve.g)
ksG = scalar_mult(ks, curve.g)
print("\np1 picks secret randoms rs and ks and multiplies them by the curve generator and sends to p2")
print("\nrs:", rs, "rsG:", rsG)
print("\nks:", ks, "ksG:", ksG)
#p1 send rsG and ksG to p2
#end p1 activity
#start p2 activity
rr = random.randrange(0, curve.n)
kr = random.randrange(0, curve.n)
krG = scalar_mult(kr, curve.g)
rrG = scalar_mult(rr, curve.g)
print("\np2 picks secret randoms rr and kr and multiplies them by the curve generator and sends to p1")
print("\nrr:", rr, "rrG:", rrG)
print("\nkr:", kr, "krG:", krG)
print("p2 also computes hashed message e = hash( M | ksG + krG )")
hashContent = message.encode() + str(ksG + krG).encode()
sha256.update(hashContent)
e = int(sha256.digest().hex(), 16)
print("e:", e)
sr = kr + (e * rr)
print("\np2 creates their multisig value sr:", sr)
x = secrets.randbits(256)
print("\np2 creates a 256bit secret preimage x:", x)
srG = scalar_mult(sr, curve.g)
xG = scalar_mult(x, curve.g)
print("srG:", srG)
print("\np2 multiplies the preimage by secp256k1 generator G to get xG:", xG)
sr_ = sr + x
print("\np2 computes a partial equation for p1 sr_ = sr - x. \n\nsr:", sr_)
print("\np2 sends sr_ and xG along with srG to p1")
#end p2 activity
#start p1 activity
check = add_points(srG, xG)
sr_G = scalar_mult(sr_, curve.g)
print("\np1 checks that srG + xG == sr_G", check, "==", sr_G, "and that xG are locking funds in contract")
assert(check == sr_G)
#p1 also check that xG is locking up funds
#if so p1 locks their coins into a box that requires (sr + ss, krG + ksG) to spend or can redeem after lockheight
print("\np1 locks funds to contract that checks that the inputed sr and ss are == to srG and ssG as well as include krG and ksG in the second half of the conditions")
ss = ks + e * rs
print("\np1 computes their part of the signature ss = ks + e * rs:", ss, "and sends result to p2" )
ssG = scalar_mult(ss, curve.g)
print("ss:", ss, "ssG", ssG)
#p1 sends e and ss to p2
#end p1 activity
#start p2 activity
sr = kr + e * rr
print("\np2 computes their part of the signature sr = kr + e *rr:", sr)
Q = sr + ss
print("\nthe contract can check for the combined sig:", Q, "obtained by doing assert([input]ss*G + sr*G == [spending condition]ssG + srG)")
#p2 claims with Q which implicitly broadcasts the value of Q on chain, they also use krG and ksG as 2nd half of the sig
#end p2 activity
#start p1 activity
print("\np1 sees that p2 broadcasted Q on chain and can then use it to compute sr")
p1sr = Q - ss
print("\nsr:", sr,"==", "p1sr:", p1sr)
assert(sr == p1sr)
p1x = sr_ - sr #p1 discovers x this way
print("\np1 discovers sr_ - sr = x", p1x)
assert(p1x == x)
print("p1 can now spend value locked to hash/public pair xG with x and their signature")
#p1 can now spend value locked to hash xG with x and their signature
#end atomic swap




