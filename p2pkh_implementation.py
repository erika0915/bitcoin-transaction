from dsa_key_generation import P2PKH_PRIVATE_KEY, P2PKH_PUBLIC_KEY
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import hashlib

def sha1_hash(data):
    # 과제 요구사항: OP_HASH160 연산에 SHA-1 사용 
    return hashlib.sha1(data).digest()

def implement_p2pkh(private_key, public_key, message):
    # Pay-to-PubKey-Hash (P2PKH) 스크립트 실행 시뮬레이션

    print("\n" + "=" * 70)
    print(f"              🏆 Task 3: P2PKH 구현 및 실행              ")
    print("=" * 70)

    # Task 3 메시지: "Blockchain Application Q2" 
    message_bytes = message.encode('utf-8')
    
    # ScriptSig (Signature) 생성 : SHA-256 사용 
    try:
        signature = private_key.sign(
            message_bytes,
            hashes.SHA256()
        )
        print("✅ 1. ScriptSig (Signature) 생성 완료 (SHA-256 사용).")

    except Exception as e:
        print(f"❌ 서명 생성 오류: {e}")
        return False

    # Public Key (bytes) 추출 
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # ScriptPubKey를 위한 Public Key Hash 생성 (OP_HASH160 시뮬레이션)
    public_key_hash = sha1_hash(public_key_bytes)
    print("✅ 2. ScriptPubKey를 위한 Public Key Hash (SHA-1) 생성 완료.")
    
    # ScriptSig: [Signature] [Public Key], ScriptPubKey: OP_DUP OP_HASH160 [PK_Hash] OP_EQUALVERIFY OP_CHECKSIG [cite: 13]

    # 스크립트 실행 시뮬레이션 (스택 기반) 
    # ScriptSig 실행: 스택에 [Signature]와 [Public Key] PUSH
    execution_stack = [signature, public_key_bytes]

    # ScriptPubKey 실행 (검증)
    print("\n[실행] ScriptPubKey 시작 (OP_DUP -> OP_HASH160 -> OP_EQUALVERIFY -> OP_CHECKSIG)...")

    # OP_DUP: Public Key 복제
    pk_dup = execution_stack[-1]
    execution_stack.append(pk_dup) # 스택: [Sig, PK, PK]
    
    # OP_HASH160: 복제된 PK를 SHA-1 해시
    pk_to_hash = execution_stack.pop()
    hashed_pk = sha1_hash(pk_to_hash)
    execution_stack.append(hashed_pk) # 스택: [Sig, PK, Hash(PK)]
    
    # ScriptPubKey의 [PK_Hash] PUSH 및 OP_EQUALVERIFY 비교
    execution_stack.append(public_key_hash) # 스택: [Sig, PK, Hash(PK), Expected_Hash]
    
    expected_hash = execution_stack.pop()
    actual_hash = execution_stack.pop()
    
    if expected_hash != actual_hash:
        print("❌ OP_EQUALVERIFY 실패: 해시 불일치.")
        return False
        
    print("✅ OP_EQUALVERIFY 성공: Public Key Hash 일치 확인.")
    
    # OP_CHECKSIG: 서명 검증
    # 스택에서 Public Key와 Signature 추출 (스택: [Sig, PK] 상태)
    pk_for_check = execution_stack.pop() 
    sig_for_check = execution_stack.pop() 
    
    try:
        # 검증: (Signature, Message)를 Public Key로 검증
        public_key.verify(
            sig_for_check,
            message_bytes,
            hashes.SHA256()
        )
        
        final_result = True
        print("✅ OP_CHECKSIG 결과: TRUE (거래 성공!)")
        
    except Exception as e:
        final_result = False
        print(f"❌ OP_CHECKSIG 결과: FALSE (거래 실패! 오류: {e})")

    print(f"\n--- 최종 스크립트 실행 결과: {final_result} ---")
    return final_result

TASK3_MESSAGE = "Blockchain Application Q2"
implement_p2pkh(P2PKH_PRIVATE_KEY, P2PKH_PUBLIC_KEY, TASK3_MESSAGE)