import json
from typing import Any, Optional

from fastapi import Body, FastAPI, HTTPException, Request
from pydantic import BaseModel

from security.core.demo import DemoComparison, run_guidance_demo
from security.core.impact import CodeChangeImpact, run_code_change_impact
from security.core.scanner import Scanner
from security.models.finding import Severity

MAX_CODE_SIZE = 50_000

app = FastAPI(title="VibeCodeGuide", version="0.1.0")


class FindingModel(BaseModel):
    rule_id: str
    title: str
    message: str
    severity: str
    file: str
    line: Optional[int] = None
    category: Optional[str] = None
    col: Optional[int] = None
    suggestion: Optional[str] = None
    snippet: Optional[str] = None
    confidence: Optional[str] = None
    risk_score: Optional[int] = None
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    impact: Optional[str] = None
    privacy_strategy: Optional[str] = None


class ParseErrorModel(BaseModel):
    file: str
    message: str


class SummaryModel(BaseModel):
    by_severity: dict[str, int]
    by_category: dict[str, int]
    risk: Optional[dict[str, Any]] = None


class AnalyzeResponse(BaseModel):
    ok: bool
    error_type: Optional[str]
    error_message: Optional[str]
    scanned_files: int
    findings: list[FindingModel]
    parse_errors: list[ParseErrorModel]
    summary: SummaryModel
    guidance_enabled: bool = True


class DemoDeltaModel(BaseModel):
    additional_findings_count: int
    guidance_only_rule_ids: list[str]
    privacy_strategies_surfaced: list[str]
    baseline_finding_count: int
    guided_finding_count: int
    baseline_security_count: int
    guided_security_count: int
    guided_privacy_count: int


class DemoAnalyzeResponse(BaseModel):
    ok: bool
    sample_label: str
    baseline: AnalyzeResponse
    with_guidance: AnalyzeResponse
    delta: DemoDeltaModel


class ChangedLineModel(BaseModel):
    line_number: int
    before_text: str
    after_text: str


class CodeChangeImpactResponse(BaseModel):
    ok: bool
    sample_label: str
    changed_lines: list[ChangedLineModel]
    before: AnalyzeResponse
    after: AnalyzeResponse
    resolved_findings: list[FindingModel]
    introduced_findings: list[FindingModel]
    before_privacy_count: int
    after_privacy_count: int
    before_security_count: int
    after_security_count: int
    before_total_count: int
    after_total_count: int
    resolved_privacy_count: int
    resolved_security_count: int


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


def _parse_enable_guidance(request: Request) -> bool:
    header = request.headers.get("x-enable-guidance", "").strip().lower()
    if header in ("0", "false", "no", "off"):
        return False
    if header in ("1", "true", "yes", "on"):
        return True
    return True


def _extract_code(body: bytes, content_type: str) -> str:
    if not body:
        raise HTTPException(status_code=422, detail="Request body is required.")

    if "application/json" in content_type:
        try:
            parsed = json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise HTTPException(status_code=422, detail="Invalid JSON body.") from exc
        code = parsed.get("code") if isinstance(parsed, dict) else (parsed if isinstance(parsed, str) else None)
    else:
        try:
            code = body.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise HTTPException(status_code=422, detail="Body must be UTF-8 text.") from exc

    if not isinstance(code, str):
        raise HTTPException(status_code=422, detail="Provide code as JSON {'code': '...'} or raw text body.")
    if not code.strip():
        raise HTTPException(status_code=422, detail="Code cannot be empty.")
    if len(code) > MAX_CODE_SIZE:
        raise HTTPException(status_code=422, detail=f"Code length exceeds {MAX_CODE_SIZE} characters.")
    return code


def _scan_result_to_response(result, *, guidance_enabled: bool) -> dict[str, Any]:
    d = result.to_dict()
    return {
        "ok": True,
        "error_type": None,
        "error_message": None,
        "scanned_files": d["scanned_files"],
        "findings": d["findings"],
        "parse_errors": d["parse_errors"],
        "summary": SummaryModel.model_validate(d["summary"]),
        "guidance_enabled": guidance_enabled,
    }


def _comparison_to_demo_response(comparison: DemoComparison) -> dict[str, Any]:
    return {
        "ok": True,
        "sample_label": comparison.sample_label,
        "baseline": _scan_result_to_response(comparison.baseline, guidance_enabled=False),
        "with_guidance": _scan_result_to_response(comparison.with_guidance, guidance_enabled=True),
        "delta": DemoDeltaModel.model_validate(comparison.delta.to_dict()),
    }


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_python_code(
    request: Request,
    payload: Any = Body(
        ...,
        media_type="text/plain",
        example='import random\ntoken = random.random()\neval(input())',
    ),
) -> Any:
    _ = payload
    body = await request.body()
    content_type = request.headers.get("content-type", "").lower()
    code = _extract_code(body=body, content_type=content_type)

    min_severity_header = request.headers.get("x-min-severity", "").upper()
    min_severity = Severity[min_severity_header] if min_severity_header in Severity.__members__ else None
    enable_guidance = _parse_enable_guidance(request)

    scanner = Scanner(min_severity=min_severity, enable_guidance=enable_guidance)
    try:
        result = scanner.scan_source(code)
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail={
                "ok": False,
                "error_type": type(exc).__name__,
                "error_message": str(exc),
                "scanned_files": 0,
                "findings": [],
                "parse_errors": [],
                "summary": {"by_severity": {}, "by_category": {}},
                "guidance_enabled": enable_guidance,
            },
        ) from exc

    return _scan_result_to_response(result, guidance_enabled=enable_guidance)


@app.post("/analyze/demo", response_model=DemoAnalyzeResponse)
async def analyze_demo_comparison(
    request: Request,
    payload: Any = Body(
        ...,
        media_type="text/plain",
        example='print(email)\npassword = "secret"',
    ),
) -> Any:
    _ = payload
    body = await request.body()
    content_type = request.headers.get("content-type", "").lower()
    code = _extract_code(body=body, content_type=content_type)

    min_severity_header = request.headers.get("x-min-severity", "").upper()
    min_severity = Severity[min_severity_header] if min_severity_header in Severity.__members__ else None

    try:
        comparison = run_guidance_demo(code, filename="<code>")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return _comparison_to_demo_response(comparison)


def _extract_impact_payload(body: bytes, content_type: str) -> tuple[str, str, str]:
    if "application/json" not in content_type:
        raise HTTPException(
            status_code=422,
            detail="Provide JSON {'before': '...', 'after': '...', 'filename': 'optional.py'}.",
        )
    try:
        parsed = json.loads(body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=422, detail="Invalid JSON body.") from exc
    if not isinstance(parsed, dict):
        raise HTTPException(status_code=422, detail="Impact payload must be a JSON object.")
    before = parsed.get("before")
    after = parsed.get("after")
    filename = parsed.get("filename") or "<code>"
    if not isinstance(before, str) or not isinstance(after, str):
        raise HTTPException(status_code=422, detail="Fields 'before' and 'after' must be strings.")
    if not before.strip() or not after.strip():
        raise HTTPException(status_code=422, detail="Fields 'before' and 'after' cannot be empty.")
    if len(before) > MAX_CODE_SIZE or len(after) > MAX_CODE_SIZE:
        raise HTTPException(status_code=422, detail=f"Code length exceeds {MAX_CODE_SIZE} characters.")
    return before, after, filename


def _impact_to_response(impact: CodeChangeImpact) -> dict[str, Any]:
    payload = impact.to_dict()
    return {
        "ok": True,
        "sample_label": payload["sample_label"],
        "changed_lines": payload["changed_lines"],
        "before": _scan_result_to_response(impact.before, guidance_enabled=True),
        "after": _scan_result_to_response(impact.after, guidance_enabled=True),
        "resolved_findings": payload["resolved_findings"],
        "introduced_findings": payload["introduced_findings"],
        "before_privacy_count": payload["before_privacy_count"],
        "after_privacy_count": payload["after_privacy_count"],
        "before_security_count": payload["before_security_count"],
        "after_security_count": payload["after_security_count"],
        "before_total_count": payload["before_total_count"],
        "after_total_count": payload["after_total_count"],
        "resolved_privacy_count": payload["resolved_privacy_count"],
        "resolved_security_count": payload["resolved_security_count"],
    }


@app.post("/analyze/impact", response_model=CodeChangeImpactResponse)
async def analyze_code_change_impact(request: Request) -> Any:
    body = await request.body()
    content_type = request.headers.get("content-type", "").lower()
    before, after, filename = _extract_impact_payload(body=body, content_type=content_type)

    min_severity_header = request.headers.get("x-min-severity", "").upper()
    min_severity = Severity[min_severity_header] if min_severity_header in Severity.__members__ else None

    try:
        impact = run_code_change_impact(
            before,
            after,
            filename=filename,
            min_severity=min_severity,
            sample_label=filename,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return _impact_to_response(impact)
