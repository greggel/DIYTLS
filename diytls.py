import os, binascii, hashlib, random
from Crypto.Util.number import *
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

#
#  Elliptic Curve Diffie-Hellman exchange to establish a shared secret.  Use a NIST approved curve. (Module 5)
#

p=8948962207650232551656602815159153422162609644098354511344597187200057010413552439917934304191956942765446530386427345937963894309923928536070534607816947
A=8948962207650232551656602815159153422162609644098354511344597187200057010413552439917934304191956942765446530386427345937963894309923928536070534607816944
B=6532815740455945129522030162820444801309011444717674409730083343052139800841847092116476221316466234404847931899409316558007222582458822004777353814164030
n=8948962207650232551656602815159153422162609644098354511344597187200057010413418528378981730643524959857451398370029280583094215613882043973354392115544169

def parseparams():
    f=file('parameters','r')
    lines=f.readlines()
    f.close()
    params = {}
    currentHex=''
    currentParam=''

    def h2i(hexLines):
        if (hexLines == ''):
            return 0
        return int(hexLines.replace(' ','').replace(':',''), 16)

    def splitPoint(hexLines):
        gen=hexLines.replace(' ','').replace(':','')[2:]
        gl=len(gen)
        return (int(gen[:gl/2],16), int(gen[gl/2:], 16))

    ecpoints=["Gener", "pub"]

    for line in lines:
        if line[0].isalpha():
            if (currentHex != '' and currentParam != ''):
                #print "key:",currentParam
                if not currentParam in ecpoints:
                    params[currentParam]=h2i(currentHex)
                else:
                    params[currentParam]=splitPoint(currentHex)
            currentParam = line.strip().replace(':','')[:5]
            currentHex=''
        else:
            currentHex+=line.strip()
    return params

def modinv(a,n=p):
    lm, hm = 1,0
    low, high = a%n,n
    while low > 1:
        ratio = high/low
        nm, new = hm-lm*ratio, high-low*ratio
        lm, low, hm, high = nm, new, lm, low
    return lm % n

def ECadd(a,b):
    LamAdd = ((b[1]-a[1]) * modinv(b[0]-a[0],p)) % p
    x = (LamAdd*LamAdd-a[0]-b[0]) % p
    y = (LamAdd*(a[0]-x)-a[1]) % p
    return (x,y)

def ECdouble(a): 
    Lam = ((3*a[0]*a[0]+A) * modinv((2*a[1]),p)) % p
    x = (Lam*Lam-2*a[0]) % p
    y = (Lam*(a[0]-x)-a[1]) % p
    return (x,y)

def EccMultiply(GenPoint,ScalarHex): 
    if ScalarHex == 0 or ScalarHex >= n: raise Exception("Invalid Scalar/Private Key")
    ScalarBin = str(bin(ScalarHex))[2:]
    Q=GenPoint
    for i in range (1, len(ScalarBin)): # This is invented EC multiplication.
        Q=ECdouble(Q); # print "DUB", Q[0]; print
        if ScalarBin[i] == "1":
            Q=ECadd(Q,GenPoint); # print "ADD", Q[0]; print
    return (Q)

aliceKey=random.randint(2,n)
bobKey=random.randint(2,n)
Gx=48466123833030262803392336100238219153583507208568692916997676040710914433206166277619603205883195141089972554984933622779063262747856716603107303447973
Gy=593158065101447629241595919519712532017995867890045892424306607937025640989671604809456400578418899034838514443503685160460030024361157233512098217636658
GPoint = (Gx,Gy)

print ' '
PublicKey = EccMultiply(GPoint,aliceKey)
print "alice private key:"
print aliceKey
print ' '
print "Bob private key:"
print bobKey
print ' '
print "ECDH Public Key Exchange"; 
print PublicKey
print ' '
# print "the official Public Key - compressed:"; 
# if PublicKey[1] % 2 == 1: # If the Y value for the Public Key is odd.
#     print "03"+str(hex(PublicKey[0])[2:-1]).zfill(64)
# else: # Or else, if the Y value is even.
#     print "02"+str(hex(PublicKey[0])[2:-1]).zfill(64)

n = int('00b561c3d144b8aab6c4ee7fa6e60c6ab330adf7222f8cdff8ef0919',16)
e = 65537

p = int('0dce1dd4aa0fc356cb9399c16a83',16)
q = int('0d23831b2f5a163e2de1be391b33',16)

d = int("21c8199e6a3c329f63c23fc827df777b2cd3e9947225aea057a9f9",16)

#CipherTextExample = 12899310797509517336639735239544711450365375209315317886614608139
#m = int(binascii.hexlify("alsdkajldjaksdjajdjsaldjaklsdja"),16)

#
# For each chunk of public information sent generate an RSA Digital Signature. (Module 6) 
# 

m = int(str(PublicKey).encode("hex"),16)
C = pow(m,d,n)

print 'RSA Digital Signature'
print C
print ' '

#
# Attempting to verify my RSA signature but because I included both key's in my Public Key variable I am not sure I can verify by decryption.
# Verification done by sharing signature.
#

print 'RSA Public Key for sharing'
print n,e
print ' '
print 'Verification Signature of RSA number'
print pow(C,e,n)
print ' '

#
# Once you have a shared key encrypt a message using AES in GCM mode (not in our notes but not too different). (Module 3)
# 

#key = str(PublicKey[0])[0:32]
#
# wasn't sure if it was just supposed to be my ecdh x key or C from the RSA containing both keys
key = str(C)[0:32]

def encrypt(key, plaintext, associated_data):
    # Generate a random 96-bit IV.
    iv = os.urandom(12)

    # Construct an AES-GCM Cipher object with the given key and a
    # randomly generated IV.
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    # associated_data will be authenticated but not encrypted,
    # it must also be passed in on decryption.
    encryptor.authenticate_additional_data(associated_data)

    # Encrypt the plaintext and get the associated ciphertext.
    # GCM does not require padding.
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return (iv, ciphertext, encryptor.tag)

def decrypt(key, associated_data, iv, ciphertext, tag):
    # Construct a Cipher object, with the key, iv, and additionally the
    # GCM tag used for authenticating the message.
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()

    # We put associated_data back in or the tag will fail to verify
    # when we finalize the decryptor.
    decryptor.authenticate_additional_data(associated_data)

    # Decryption gets us the authenticated plaintext.
    # If the tag does not match an InvalidTag exception will be raised.
    return decryptor.update(ciphertext) + decryptor.finalize()

iv, ciphertext, tag = encrypt(
    key,
    b"I, the undersigned, do solemnly swear to pick boogers, eat them, and wipe any excess on my shirt.",
    b"authenticated but not encrypted payload"
)
#
#Uncomment to Decrypt Message
print 'Decrypted Message Encrypted in AES-GCM:'
print(decrypt(
    key,
    b"authenticated but not encrypted payload",
    iv,
    ciphertext,
    tag
))
#
#
#-----------------------------------------------------
#
#
#   SAGE Work for ECDH Key Share
#
#
#p=8948962207650232551656602815159153422162609644098354511344597187200057010413552439917934304191956942765446530386427345937963894309923928536070534607816947
# A=8948962207650232551656602815159153422162609644098354511344597187200057010413552439917934304191956942765446530386427345937963894309923928536070534607816944
# B=6532815740455945129522030162820444801309011444717674409730083343052139800841847092116476221316466234404847931899409316558007222582458822004777353814164030
# q=8948962207650232551656602815159153422162609644098354511344597187200057010413418528378981730643524959857451398370029280583094215613882043973354392115544169
# Gx=5240454105373391383446315535930423532243726242869439206480578543706358506399554673205583372921814351137736817888782671966171301927338369930113338349467098
# Gy=4783098043208509222858478731459039446855297686825168822962919559100076900387655035060042118755576220187973470126780576052258118403094460341772613532037938
# E=EllipticCurve(Zmod(p), [A, B])
# #E.cardinality()

# P=E(Gx,Gy)

# #alpha=randint(1, q-1)
# alpha=183024977326024200693322429950612741087600132528014801490192196292622572929328315220629867564065254828373319078205050691638978587113225901223873889808887
# beta=6481507176889157465962085692105249658599191313153396051372226642499574600498868991370746955895951209517007544339440929430865812078941637992575580254399949


# POINTA = alpha * P

# Bx = 3494441914271847790983374251781936464147267392038082341015931122449764902986138265222400541988852803091322221255850017635809046930150136225467063996839569
# By = 2082056036095882579216117546655738203999270659614749346131719276164894373244114904614385847498939968752145263370903605819189807803484296972616860630936377

# P = E(Bx,By)

# print POINTA
# print ' '
# C = alpha * P
# print C

# #print ' '
# #print P
# #print EllipticCurve(Zmod(p),a,Gx,Gy)
