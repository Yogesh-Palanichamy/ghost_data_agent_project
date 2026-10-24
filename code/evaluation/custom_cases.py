"""Additional synthetic unit cases for core policy/intent behavior.

These are participant-authored tests, not expected labels for any challenge case.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import main

CASES = [
    {
        "name": "correction_without_deletion",
        "purpose": "A phone correction while retaining an active account is not a deletion request.",
        "check": lambda: main.is_authorized_deletion("My phone number is out of date. Please replace it and leave my account active."),
        "expected": False,
    },
    {
        "name": "explicit_not_to_erase_is_not_deletion",
        "purpose": "A data-access question that explicitly says it is not a request to erase is not deletion-authorized.",
        "check": lambda: main.is_authorized_deletion("Can you tell me what personal information you hold about me? This is an information request, not a request to erase it."),
        "expected": False,
    },
    {
        "name": "multilingual_portuguese_deletion",
        "purpose": "Recognize a Portuguese permanent account-deletion request.",
        "check": lambda: main.is_authorized_deletion("Solicito a exclusão permanente da conta associada a este e-mail."),
        "expected": True,
    },
    {
        "name": "multilingual_korean_deletion",
        "purpose": "Recognize a Korean account-deletion request.",
        "check": lambda: main.is_authorized_deletion("이 이메일 주소에 연결된 계정의 영구 삭제를 요청합니다."),
        "expected": True,
    },
    {
        "name": "anonymized_tombstone_retained",
        "purpose": "A tombstone retaining only a stable user reference is compliant under the REDACT rule.",
        "check": lambda: not main.is_violation({"category":"ACCOUNT_TOMBSTONE","state":"REDACTED","flat":{"user_id":["user_123"],"email":[None],"phone":[None],"name":[None],"email_hash":[None]}}),
        "expected": True,
    },
    {
        "name": "identifiable_analytics_requires_anonymization",
        "purpose": "An analytics profile retaining an email hash is still attributable and must be anonymized.",
        "check": lambda: main.is_violation({"category":"ANALYTICS_PROFILE","state":"PRESENT","flat":{"email_hash":["a"*64],"user_id":[None],"email":[None]}}),
        "expected": True,
    },
]

if __name__ == "__main__":
    failed=[]
    for case in CASES:
        actual=bool(case["check"]())
        ok=actual==case["expected"]
        print(("PASS" if ok else "FAIL"),case["name"],"expected=",case["expected"],"actual=",actual)
        if not ok: failed.append(case["name"])
    if failed: raise SystemExit("Failed custom tests: "+", ".join(failed))
