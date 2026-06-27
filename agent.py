from openai import OpenAI

import config
from models import ScanResult, Severity

client = OpenAI(api_key=config.REGOLO_API_KEY, base_url=config.REGOLO_BASE_URL)

SYSTEM_PROMPT = (
    "You are a senior security engineer writing an executive security assessment. "
    "Be specific. Quote evidence. Prioritize by real-world exploitability, not just CVSS. "
    "Identify attack chains where multiple findings combine. "
    "Prefer concrete remediation steps, exact commands, and code/config changes. "
    "Treat auto-fixable findings as ready-to-merge candidates and call out the exact fix."
)

REPORT_STRUCTURE = """Produce a markdown report with EXACTLY these sections and headings:

## Executive Summary
## Overall Risk Score
(format: X.X/10 — one sentence justification)
## Critical & High Findings
(for each: ### [ID] Title, then Impact, Evidence quoted, and the exact fix command or code)
## Fix-Ready Findings
(for each auto-fixable finding: ### [ID] Title, then the exact patch summary and the remediation outcome)
## Attack Chains
(how findings combine, e.g. exposed secret + debug mode = full system compromise)
## Remediation Roadmap
### Immediate (today)
### This Week
### This Month
## Quick Wins
(fixes under 30 minutes, ordered by impact)
"""


def get_available_models() -> list[str]:
    try:
        resp = client.models.list()
        models = [m.id for m in resp.data]
        return models or ["gpt-4o", "gpt-4o-mini", "gpt-3.5-turbo"]
    except Exception:
        return ["gpt-4o", "gpt-4o-mini", "gpt-3.5-turbo"]


def _format_findings(scan_result: ScanResult) -> str:
    blocks = []
    for f in scan_result.findings:
        loc = f"{f.file_path}:{f.line_number}" if f.file_path else "n/a"
        blocks.append(
            f"[{f.id}] {f.severity.value} | {f.category} | {f.title}\n"
            f"File: {loc}\n"
            f"Evidence: {f.evidence}\n"
            f"Fix: {f.fix_suggestion}\n"
            "---"
        )
    return "\n".join(blocks) if blocks else "No findings."


def analyze(repo_url: str, scan_result: ScanResult, model: str = None) -> str:
    counts = {s: len(scan_result.by_severity(s)) for s in Severity}
    stats = ", ".join(f"{s.value}: {counts[s]}" for s in Severity)
    auto_fixable = [f for f in scan_result.findings if f.auto_fixable]

    user_prompt = (
        f"Repository: {repo_url}\n"
        f"Total findings: {len(scan_result.findings)} ({stats})\n"
        f"Auto-fixable findings: {len(auto_fixable)}\n\n"
        f"FINDINGS:\n{_format_findings(scan_result)}\n\n"
        f"{REPORT_STRUCTURE}"
    )

    resp = client.chat.completions.create(
        model=model or config.REGOLO_MODEL,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        temperature=0.2,
        max_tokens=4000,
    )
    return resp.choices[0].message.content


if __name__ == "__main__":
    print(get_available_models())
