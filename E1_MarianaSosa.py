import random
import hashlib

# generar un número primo aleatorio
def generate_prime():
    while True:
        num = random.randint(100, 500)
        if is_prime(num):
            return num

# comprobar si un número es primo
def is_prime(n):
    if n <= 1:
        return False
    elif n <= 3:
        return True
    elif n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True

# calcular el máximo común divisor
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

# calcular el inverso modular
def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

# generar las claves pública y privada
def generate_keypair():
    p = generate_prime()
    q = generate_prime()
    n = p * q
    phi = (p - 1) * (q - 1)

    # elegir un número aleatorio e relativamente primo a phi
    e = random.randint(1, phi)
    while gcd(e, phi) != 1:
        e = random.randint(1, phi)

    # calcular el inverso modular de e
    d = mod_inverse(e, phi)

    return ((e, n), (d, n))

# función para cifrar un mensaje
def encrypt(public_key, message):
    e, n = public_key
    encrypted_msg = [pow(ord(char), e, n) for char in message]
    return encrypted_msg

# función para descifrar un mensaje
def decrypt(private_key, encrypted_msg):
    d, n = private_key
    decrypted_msg = [chr(pow(char, d, n)) for char in encrypted_msg]
    return ''.join(decrypted_msg)

# función para dividir el mensaje en partes de 128 caracteres
def split_message(message):
    return [message[i:i+128] for i in range(0, len(message), 128)]

# función para generar el hash de un mensaje
def generate_hash(message):
    return hashlib.sha256(message.encode()).hexdigest()

# generar claves pública y privada
public_key, private_key = generate_keypair()

# mensaje original de Alice
message = "Mensaje de prueba de 1050 caracteres. " * 21

# dividir el mensaje en partes de 128 caracteres
message_parts = split_message(message)

# cifrar y enviar cada parte del mensaje
encrypted_parts = [encrypt(public_key, part) for part in message_parts]

# Bob recibe y descifra cada parte del mensaje
decrypted_parts = [decrypt(private_key, part) for part in encrypted_parts]

# reconstruir el mensaje original
received_message = ''.join(decrypted_parts)

# generar el hash del mensaje original de Bob
received_hash = generate_hash(received_message)

# generar el hash del mensaje original de Alice
original_hash = generate_hash(message)

# comprobar si los hashes son iguales
if received_hash == original_hash:
    print("Autenticidad del mensaje verificada. Los hashes coinciden!")
else:
    print("Error: Autenticidad del mensaje no verificada. Los hashes no coinciden.")
