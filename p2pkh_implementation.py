from dsa_key_generation import P2PKH_PRIVATE_KEY, P2PKH_PUBLIC_KEY
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import hashlib

def sha1_hash(data):
    # OP_HASH160 연산에서 SHA-1만 사용하라는 요구 사항을 처리합니다. 
    return hashlib.sha1(data).digest()

def implement_p2pkh(private_key, public_key, message):
    # P2PKH 스크립트의 서명 및 검증을 시뮬레이션

    print("\n" + "=" * 70)
    print(f"              🏆 Task 3: P2PKH 구현 및 실행              ")
    print("=" * 70)

    # Task 3 메시지: "Blockchain Application Q2" 
    message_bytes = message.encode('utf-8')
    
    # ScriptSig 생성: 서명 (Signature)
    # 개인 키를 사용하여 메시지(SHA-256 해시)에 서명 
    try:
        signature = private_key.sign(
            message_bytes,
            hashes.SHA256()
        )
        print("✅ 1. ScriptSig (Signature) 생성 완료 (SHA-256 사용).")

    except Exception as e:
        print(f"❌ 서명 생성 오류: {e}")
        return False

    # Script 구성 요소 준비
    
    # Public Key (bytes)를 DER 형식으로 추출
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # ScriptPubKey를 위한 공개 키 해시 (OP_HASH160 시뮬레이션)
    # OP_HASH160은 SHA-1 알고리즘을 사용함 
    public_key_hash = sha1_hash(public_key_bytes)
    print("✅ 2. ScriptPubKey를 위한 Public Key Hash (SHA-1) 생성 완료.")
    
    # ScriptSig: [Signature] [Public Key] [cite: 13]
    # ScriptPubKey: OP_DUP OP_HASH160 [PK_Hash] OP_EQUALVERIFY OP_CHECKSIG [cite: 13]

    # 스크립트 실행 시뮬레이션 (스택 기반) 
    # P2PKH 스크립트는 두 단계를 거쳐 실행됩니다:
    # ScriptSig 실행 (잠금 해제)
    # 스택에 [Signature]와 [Public Key]가 PUSH됩니다.
    execution_stack = [signature, public_key_bytes]

    # ScriptPubKey 실행 (검증)
    print("\n[실행] ScriptPubKey 시작 (OP_DUP -> OP_HASH160 -> OP_EQUALVERIFY -> OP_CHECKSIG)...")

    # OP_DUP: 스택 최상위 항목 (Public Key)을 복제
    pk_dup = execution_stack[-1] # Public Key
    execution_stack.append(pk_dup) # 스택: [Sig, PK, PK]
    
    # OP_HASH160: 스택 최상위 항목 (Public Key)을 SHA-1 해시 
    pk_to_hash = execution_stack.pop()
    hashed_pk = sha1_hash(pk_to_hash)
    execution_stack.append(hashed_pk) # 스택: [Sig, PK, Hash(PK)]
    
    # OP_EQUALVERIFY: 스택 최상위 두 항목을 비교 (Hash(PK)와 PK_Hash)
    # P2PKH의 ScriptPubKey는 미리 정의된 [PK_Hash]를 가지고 있어야 합니다.
    # 스택에 정의된 [PK_Hash]를 PUSH (실제 스크립트에서는 바이트로 인코딩되어 있음)
    execution_stack.append(public_key_hash) # 스택: [Sig, PK, Hash(PK), Expected_Hash]
    
    expected_hash = execution_stack.pop()
    actual_hash = execution_stack.pop()
    
    if expected_hash != actual_hash:
        print("❌ OP_EQUALVERIFY 실패: 해시 불일치.")
        return False
        
    print("✅ OP_EQUALVERIFY 성공: Public Key Hash 일치 확인.")
    
    # OP_CHECKSIG: 서명 검증 (스택 최상위 두 항목 [PK]와 [Sig] 사용)
    # OP_EQUALVERIFY를 통과하면 스택은 [Sig, PK] 상태로 돌아갑니다.
    pk_for_check = execution_stack.pop() # Public Key
    sig_for_check = execution_stack.pop() # Signature
    
    try:
        # 검증: (Signature, Message)를 Public Key로 검증
        public_key.verify(
            sig_for_check,
            message_bytes,
            hashes.SHA256()
        )
        
        # 검증 성공 시 스택의 결과는 True (거래 성공)
        final_result = True
        print("✅ OP_CHECKSIG 결과: TRUE (거래 성공!)")
        
    except Exception as e:
        final_result = False
        print(f"❌ OP_CHECKSIG 결과: FALSE (거래 실패! 오류: {e})")

    print(f"\n--- 최종 스크립트 실행 결과: {final_result} ---")
    return final_result

TASK3_MESSAGE = "Blockchain Application Q2"
implement_p2pkh(P2PKH_PRIVATE_KEY, P2PKH_PUBLIC_KEY, TASK3_MESSAGE)