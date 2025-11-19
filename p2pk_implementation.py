from dsa_key_generation import P2PK_PRIVATE_KEY, P2PK_PUBLIC_KEY
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import serialization

def implement_p2pk(private_key, public_key, message):
    # P2PK 스크립트의 서명 생성 및 검증을 시뮬레이션

    print("\n" + "=" * 60)
    print("              🚀 Task 2: P2PK 구현 및 실행              ")
    print("=" * 60)

    # Task 2 메시지: "Blockchain Application Q1" [cite: 10]
    message_bytes = message.encode('utf-8')

    # ScriptSig 생성: 서명 (Signature)
    # SHA-256 알고리즘 사용 [cite: 10]
    try:
        signature = private_key.sign(
            message_bytes,
            hashes.SHA256()
        )
        print("✅ 1. ScriptSig (Signature) 생성 완료 (SHA-256 사용).")

    except Exception as e:
        print(f"❌ 서명 생성 오류: {e}")
        return False

    # Public Key (bytes)를 DER 형식으로 추출 (스크립트 스택 사용을 위해)
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # 스크립트 구성
    # ScriptSig: [Signature] [Public Key] [cite: 9]
    # ScriptPubKey: [Public Key] OP_CHECKSIG [cite: 9]
    print("✅ 2. ScriptSig 및 ScriptPubKey 구성 완료.")


    # 스크립트 실행 시뮬레이션
    # ScriptSig (증거)와 ScriptPubKey (잠금)을 합쳐 실행합니다. 
    print("\n[실행] 완전한 스크립트 구성 및 실행 시작...") # [cite: 11]
    
    # OP_CHECKSIG는 Python의 public_key.verify()를 통해 시뮬레이션됩니다.
    try:
        # 검증: (Signature, Message)를 Public Key로 검증
        public_key.verify(
            signature,
            message_bytes,
            hashes.SHA256()
        )
        
        # 검증 성공 시 스택의 결과는 True (거래 성공)
        final_result = True
        print("✅ OP_CHECKSIG 결과: TRUE (거래 성공!)")
        
    except Exception as e:
        # 검증 실패 시 결과는 False
        final_result = False
        print(f"❌ OP_CHECKSIG 결과: FALSE (거래 실패! 오류: {e})")

    print(f"\n--- 최종 스크립트 실행 결과: {final_result} ---")
    return final_result

TASK2_MESSAGE = "Blockchain Application Q1"
implement_p2pk(P2PK_PRIVATE_KEY, P2PK_PUBLIC_KEY, TASK2_MESSAGE)