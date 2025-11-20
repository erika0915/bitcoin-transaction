from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def generate_dsa_key_pair(key_size=2048):

    # DSA 매개변수 생성 
    parameters = dsa.generate_parameters(key_size=key_size, backend=default_backend())

    # 개인 키 생성 
    private_key = parameters.generate_private_key()

    # 공개 키 추출 
    public_key = private_key.public_key()

    # 키를 PEM 형식으로 직렬화 
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    # 사용할 객체와 PEM 출력을 반환 
    return private_key, public_key, private_pem, public_pem

# Key Pair 1 (Task 2: P2PK에 사용될 예정)
private_key_1, public_key_1, private_pem_1, public_pem_1 = generate_dsa_key_pair(2048)

# Key Pair 2 (Task 3: P2PKH에 사용될 예정)
private_key_2, public_key_2, private_pem_2, public_pem_2 = generate_dsa_key_pair(2048)

print("=" * 60)
print("              ✅ Task 1: DSA 키 쌍 2개 생성 완료              ")
print("=" * 60)

# Key Pair 1 출력 (P2PK 용)
print("\n[ Key Pair 1 (P2PK) ]")
print("-" * 30)
print("1. Private Key Object:", private_key_1)
print("2. Public Key Object: ", public_key_1)

# PEM 출력
print("\n--- 개인 키 (Private Key PEM) ---")
print(private_pem_1)
print("--- 공개 키 (Public Key PEM) ---")
print(public_pem_1)
print("-" * 60)

# Key Pair 2 출력 (P2PKH 용)
print("\n[ Key Pair 2 (P2PKH) ]")
print("-" * 30)
print("1. Private Key Object:", private_key_2)
print("2. Public Key Object: ", public_key_2)

# PEM 출력
print("\n--- 개인 키 (Private Key PEM) ---")
print(private_pem_2)
print("--- 공개 키 (Public Key PEM) ---")
print(public_pem_2)
print("=" * 60)

P2PK_PRIVATE_KEY = private_key_1
P2PK_PUBLIC_KEY = public_key_1
P2PKH_PRIVATE_KEY = private_key_2
P2PKH_PUBLIC_KEY = public_key_2