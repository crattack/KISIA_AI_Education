import yara
import os
from typing import Optional

# 1. LLM API 호출 시뮬레이션 함수 (YARA 룰 정의)
def get_yara_rule_from_ai(malware_features: str) -> Optional[str]:
    """LLM이 요청을 기반으로 YARA 룰을 생성한다고 가정한 함수입니다."""
    print(f"\n[AI 요청]: 다음 특징을 기반으로 YARA 룰을 생성해줘: {malware_features}")
    
    # 수정: $s2 정의 제거 (condition에서 사용하지 않으므로)
    ai_generated_rule = """
rule AI_Generated_Malware_Hunter
{
    meta:
        author = "Generative AI Co-pilot"
        description = "Detects file with multiple VirtualAlloc signatures."
    
    strings:
        $s1 = "VirtualAlloc" ascii nocase
    
    condition:
        // 파일 크기가 1MB 미만이고,
        // $s1 ("VirtualAlloc")이 파일 내에 최소 3번 이상 출현할 때 탐지
        filesize < 1MB and
        #s1 >= 3
}
"""
    return ai_generated_rule

# 2. YARA 룰 검증 함수
def verify_yara_rule(rule_source: str, target_file: str):
    """생성된 YARA 룰을 컴파일하고 타겟 파일에 적용하여 탐지 여부를 확인합니다."""
    print(f"\n[>] YARA 룰 컴파일 및 검증 시작...")
    
    try:
        # 룰 컴파일
        rules = yara.compile(source=rule_source)
        
        # 파일 스캔
        matches = rules.match(target_file)
        
        if matches:
            print("[!!!] 탐지 성공! ✅")
            for match in matches:
                print(f"[!] 탐지된 룰: {match.rule}")
        else:
            print("[+] 탐지 실패. 룰이 파일을 포착하지 못했습니다.")
            
    except yara.Error as e:
        print(f"[-] YARA 룰 컴파일 오류: {e}")
    except Exception as e:
        print(f"[-] 스캔 중 오류 발생: {e}")

# 3. 실습 실행
if __name__ == "__main__":
    TARGET_FILE = "dummy_malware.bin"
    MALWARE_FEATURES = "PE 파일이며, 동적 메모리 할당 함수인 'VirtualAlloc' 문자열이 세 번 이상 출현합니다."
    
    # A. 테스트 파일 생성 (YARA 룰에 걸리도록 시그니처를 3회 포함)
    try:
        with open(TARGET_FILE, "w") as f:
            f.write("Header.\n")
            f.write("VirtualAlloc, VirtualAlloc, VirtualAlloc\n")  # $s1 3회 출현
            f.write("End of file.")
        print(f"[>] 테스트 파일 '{TARGET_FILE}'이 생성되었습니다.")
    except Exception as e:
        print(f"파일 생성 중 오류 발생: {e}")
        exit()
    
    # B. LLM에게 YARA 룰 생성 요청
    ai_rule = get_yara_rule_from_ai(MALWARE_FEATURES)
    
    if ai_rule:
        print("\n--- LLM이 생성한 룰 ---")
        print(ai_rule)
        print("-----------------------")
        
        # C. YARA 룰 검증
        verify_yara_rule(ai_rule, TARGET_FILE)
    
    # D. 정리
    if os.path.exists(TARGET_FILE):
        os.remove(TARGET_FILE)
        print(f"\n[>] 테스트 파일 '{TARGET_FILE}'이 삭제되었습니다.")