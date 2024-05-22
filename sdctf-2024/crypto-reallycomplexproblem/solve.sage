from CRSA import GaussianRational, decrypt
from fractions import Fraction
from Crypto.Util.number import long_to_bytes

ciphertext = 49273345737246996726590603353583355178086800698760969592130868354337851978351471620667942269644899697191123465795949428583500297970396171368191380368221413824213319974264518589870025675552877945771766939806196622646891697942424667182133501533291103995066016684839583945343041150542055544031158418413191646229 - 258624816670939796343917171898007336047104253546023541021805133600172647188279270782668737543819875707355397458629869509819636079018227591566061982865881273727207354775997401017597055968919568730868113094991808052722711447543117755613371129719806669399182197476597667418343491111520020195254569779326204447367 * I
N = -117299665605343495500066013555546076891571528636736883265983243281045565874069282036132569271343532425435403925990694272204217691971976685920273893973797616802516331406709922157786766589075886459162920695874603236839806916925542657466542953678792969287219257233403203242858179791740250326198622797423733569670 + 617172569155876114160249979318183957086418478036314203819815011219450427773053947820677575617572314219592171759604357329173777288097332855501264419608220917546700717670558690359302077360008042395300149918398522094125315589513372914540059665197629643888216132356902179279651187843326175381385350379751159740993*I
a = 1671911043329305519973004484847472037065973037107329742284724545409541682312778072234 * 10^70 + 193097758392744599866999513352336709963617764800771451559221624428090414152709219472155 * 10^68 * I


# This function takes in our polynomial and returns two rows
# The first row is the coefficient vector, scaled by the uppper bounds, of the regular polynomial 
# The second row is the coefficient vector, scaled by the upper bounds, of its imaginary multiple
def get_coefficients(f, R_r, R_i):
     regular = []
     imag_multiple = []
     coeffs = f.list()

     for i, c in enumerate(coeffs):
         regular.extend([c.real() * R_r^i, c.imag() * R_i^i])

     for i, c in enumerate(coeffs):
         imag_multiple.extend([-1 * c.imag() * R_r^i, c.real() * R_i^i])

     return [regular, imag_multiple]

# since our row vectors have different lengths, we need to pad them with zeros
# Note that the solve script reverses the columns. The leftmost column is the constant while
# the rightmost column is the coefficient of the highest degree of x
def rpad(lst, length):
    result = []
    for l in lst:
        result.append(l + [0 for i in range(length - len(l))])
    return result


def coppersmith(f, R_r, R_i, N,  k):
    # This was the maximum number of columns/entries a row vector has.
    max_cols = 4 * k
    # polynomial row vectors
    polynomial_rows = []
    x = f.parent().gen(0) # apparently helps sage do its thing

    # Add polynomials from our first technique
    for i in range(k):
        poly_rows = get_coefficients(f^i * N^(k-i), R_r, R_i)
        poly_rows = rpad(poly_rows, max_cols)
        polynomial_rows.extend(poly_rows)

    # Add polynomials from our second technique
    for i in range(k):
        poly_rows = get_coefficients(f^k * x^i, R_r, R_i) 
        poly_rows = rpad(poly_rows, max_cols)
        polynomial_rows.extend(poly_rows)
    
    # We perform LLL on our lattice
    M = matrix(polynomial_rows)
    B = M.LLL()

    # v is the first polynomial from our reduced lattice
    v = B[0] 
    
    # This section was lifted from the official solve, but just cleans up our polynomial
    Q = 0
    for (s, i) in enumerate(list(range(0, len(v), 2))):
        z = v[i] / (R_r^s) + v[i+1] / (R_i^s) * I
        Q += z * x^s

    return Q

R.<x> = PolynomialRing(I.parent(), "x") # sage once again doing its thing
f = x + a # our beloved polynomial
Q = coppersmith(f, 10^70, 10^68, N, k=10)

# r = x_0 = Q.roots()[0][0]
p = a + Q.roots()[0][0]


# Now we cast the values we calculated to GaussianRationals and find q
p = GaussianRational(Fraction(int(p.real())), Fraction(int(p.imag())))
N = GaussianRational(Fraction(int(N.real())), Fraction(int(N.imag())))
ciphertext = GaussianRational(Fraction(int(ciphertext.real())), Fraction(int(ciphertext.imag())))
q = N / p

# calculate the value of d from p and q
p_norm = int(p.real*p.real + p.imag*p.imag)
q_norm = int(q.real*q.real + q.imag*q.imag)
tot = (p_norm - 1) * (q_norm - 1)
e = 65537
d = pow(e, -1, tot)

# decrypt our ciphertext 
m = decrypt(ciphertext, (N, d))

# decode the message
print(long_to_bytes(int(m.real)) + long_to_bytes(int((m.imag))))
