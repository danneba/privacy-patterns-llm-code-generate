import ast
from typing import Iterator, Optional

_PII_SUBSTRINGS = (
    "email",
    "e_mail",
    "phone",
    "mobile",
    "ssn",
    "social_security",
    "date_of_birth",
    "dob",
    "birthdate",
    "address",
    "postal",
    "zip_code",
    "firstname",
    "first_name",
    "lastname",
    "last_name",
    "full_name",
    "password",
    "passwd",
    "national_id",
    "passport",
    "health",
    "medical",
    "biometric",
    "latitude",
    "longitude",
    "location",
    "gps",
    "ip_address",
)

_SENSITIVE_STORAGE = frozenset({"password", "passwd", "ssn", "social_security", "national_id"})

_LOG_CALLS = frozenset({
    "print",
    "info",
    "debug",
    "warning",
    "error",
    "exception",
    "critical",
})

_ANALYTICS_CALLS = frozenset({
    "track",
    "identify",
    "capture",
    "log_event",
    "record_event",
})

_AUTH_GUARDS = frozenset({
    "is_authenticated",
    "is_authorized",
    "has_permission",
    "require_auth",
    "login_required",
    "check_auth",
    "verify_token",
})

_CONSENT_MARKERS = frozenset({
    "consent",
    "opt_in",
    "opt_out",
    "permission",
    "agreed",
    "accepted_terms",
})

_AUDIT_MARKERS = frozenset({
    "audit",
    "audit_log",
    "log_audit",
    "record_audit",
    "security_log",
})


def is_pii_name(name: str) -> bool:
    lowered = name.lower()
    return any(marker in lowered for marker in _PII_SUBSTRINGS)


def is_sensitive_storage_name(name: str) -> bool:
    lowered = name.lower()
    return any(marker in lowered for marker in _SENSITIVE_STORAGE)


def node_name(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def call_target(node: ast.Call) -> Optional[str]:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def iter_calls(tree: ast.AST) -> Iterator[ast.Call]:
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            yield node


def expression_mentions_pii(node: ast.AST) -> bool:
    for child in ast.walk(node):
        name = node_name(child)
        if name and is_pii_name(name):
            return True
    return False


def function_has_auth_guard(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for node in ast.walk(func):
        if isinstance(node, ast.Call):
            target = call_target(node)
            if target and target.lower() in _AUTH_GUARDS:
                return True
        if isinstance(node, ast.Attribute):
            if node.attr.lower() in _AUTH_GUARDS:
                return True
        if isinstance(node, ast.Name):
            if node.id.lower() in _AUTH_GUARDS:
                return True
    return False


def function_mentions_consent(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for arg in func.args.args + func.args.kwonlyargs:
        if any(marker in arg.arg.lower() for marker in _CONSENT_MARKERS):
            return True
    for node in ast.walk(func):
        name = node_name(node)
        if name and any(marker in name.lower() for marker in _CONSENT_MARKERS):
            return True
    return False


def function_mentions_audit(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for node in ast.walk(func):
        if isinstance(node, ast.Call):
            target = call_target(node)
            if target and any(marker in target.lower() for marker in _AUDIT_MARKERS):
                return True
        name = node_name(node)
        if name and any(marker in name.lower() for marker in _AUDIT_MARKERS):
            return True
    return False
