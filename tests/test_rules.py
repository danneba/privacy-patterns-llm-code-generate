import ast
import pytest

from security.rules.security.vg001_eval import EvalUsageRule
from security.rules.security.vg002_exec import ExecUsageRule
from security.rules.security.vg003_hardcoded_secrets import HardcodedSecretsRule
from security.rules.security.vg004_insecure_random import InsecureRandomRule
from security.rules.security.vg005_subprocess import SubprocessShellRule
from security.rules.security.vg006_pickle import PickleRule
from security.rules.security.vg007_assert import SecurityAssertRule
from security.rules.security.vg008_weak_hash import WeakHashRule
from security.rules.security.vg010_yaml_load import UnsafeYamlLoadRule
from security.rules.security.vg011_tls_verify import DisabledTlsVerificationRule
from security.rules.security.vg012_debug_mode import DebugModeRule
from security.rules.security.vg013_sql_injection import SqlInjectionRule


def _parse(code: str):
    return ast.parse(code), code.splitlines()


class TestVG001Eval:
    def test_detects_eval(self):
        tree, lines = _parse("eval(user_input)")
        findings = EvalUsageRule().check(tree, "test.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "eval_exec_usage"
        assert findings[0].line == 1

    def test_snippet_captured(self):
        tree, lines = _parse("result = eval(expr)")
        findings = EvalUsageRule().check(tree, "test.py", lines)
        assert findings[0].snippet == "result = eval(expr)"

    def test_no_false_positive(self):
        tree, lines = _parse("x = 1 + 2\nprint('eval me not')")
        assert EvalUsageRule().check(tree, "test.py", lines) == []

    def test_multiple_evals(self):
        code = "eval(a)\neval(b)"
        tree, lines = _parse(code)
        assert len(EvalUsageRule().check(tree, "test.py", lines)) == 2


class TestVG002Exec:
    def test_detects_exec(self):
        tree, lines = _parse('exec("import os")')
        findings = ExecUsageRule().check(tree, "test.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "eval_exec_usage"

    def test_no_false_positive_string(self):
        tree, lines = _parse("x = 'executor string'")
        assert ExecUsageRule().check(tree, "test.py", lines) == []


class TestVG003HardcodedSecrets:
    def test_detects_password(self):
        tree, lines = _parse('password = "super_secret"')
        findings = HardcodedSecretsRule().check(tree, "test.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "hardcoded_secret"

    def test_detects_api_key(self):
        tree, lines = _parse('api_key = "sk-abc123"')
        findings = HardcodedSecretsRule().check(tree, "test.py", lines)
        assert len(findings) == 1

    def test_detects_token(self):
        tree, lines = _parse('auth_token = "tok_xyz"')
        findings = HardcodedSecretsRule().check(tree, "test.py", lines)
        assert len(findings) == 1

    def test_no_flag_empty_string(self):
        tree, lines = _parse('password = ""')
        assert HardcodedSecretsRule().check(tree, "test.py", lines) == []

    def test_no_flag_non_string_value(self):
        tree, lines = _parse("password = None")
        assert HardcodedSecretsRule().check(tree, "test.py", lines) == []

    def test_no_flag_unrelated_variable(self):
        tree, lines = _parse('greeting = "hello world"')
        assert HardcodedSecretsRule().check(tree, "test.py", lines) == []

    def test_detects_flask_secret_key_attribute(self):
        tree, lines = _parse('app.secret_key = "not-secret"')
        findings = HardcodedSecretsRule().check(tree, "test.py", lines)
        assert len(findings) == 1

    def test_detects_bytes_key_assignment(self):
        tree, lines = _parse("KEY = b'12345678910111212345678910111212'")
        findings = HardcodedSecretsRule().check(tree, "test.py", lines)
        assert len(findings) == 1

    def test_skips_test_support_paths(self):
        tree, lines = _parse('password = "12345"')
        assert HardcodedSecretsRule().check(tree, "app/tests/test_login.py", lines) == []


class TestVG004InsecureRandom:
    def test_detects_random_randint(self):
        code = "import random\ntoken = random.randint(0, 100)"
        tree, lines = _parse(code)
        findings = InsecureRandomRule().check(tree, "test.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "insecure_random"

    def test_detects_random_choice(self):
        code = "import random\nx = random.choice(['a', 'b'])"
        tree, lines = _parse(code)
        assert len(InsecureRandomRule().check(tree, "test.py", lines)) == 1

    def test_detects_from_random_import(self):
        code = "from random import choice\nx = choice(['a', 'b'])"
        tree, lines = _parse(code)
        findings = InsecureRandomRule().check(tree, "test.py", lines)
        assert len(findings) == 1

    def test_no_flag_secrets_module(self):
        code = "import secrets\nx = secrets.token_hex()"
        tree, lines = _parse(code)
        assert InsecureRandomRule().check(tree, "test.py", lines) == []

    def test_no_flag_random_import_without_call(self):
        code = "import random"
        tree, lines = _parse(code)
        assert InsecureRandomRule().check(tree, "test.py", lines) == []

    def test_detects_normalvariate(self):
        code = "import random\nx = random.normalvariate(0, 1)"
        tree, lines = _parse(code)
        assert len(InsecureRandomRule().check(tree, "test.py", lines)) == 1

    def test_detects_randbytes(self):
        code = "import random\nx = random.randbytes(16)"
        tree, lines = _parse(code)
        assert len(InsecureRandomRule().check(tree, "test.py", lines)) == 1


class TestVG008WeakHash:
    def test_detects_hashlib_new_md5(self):
        code = "import hashlib\nh = hashlib.new('md5')"
        tree, lines = _parse(code)
        findings = WeakHashRule().check(tree, "test.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "weak_hash_algorithm"


class TestVG005Subprocess:
    def test_detects_subprocess_run_shell_true(self):
        code = "import subprocess\nsubprocess.run(['ls'], shell=True)"
        tree, lines = _parse(code)
        findings = SubprocessShellRule().check(tree, "test.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "subprocess_shell_true"

    def test_detects_subprocess_popen_shell_true(self):
        code = "import subprocess\nsubprocess.Popen('ls', shell=True)"
        tree, lines = _parse(code)
        assert len(SubprocessShellRule().check(tree, "test.py", lines)) == 1

    def test_detects_from_subprocess_import(self):
        code = "from subprocess import run\nrun('ls', shell=True)"
        tree, lines = _parse(code)
        assert len(SubprocessShellRule().check(tree, "test.py", lines)) == 1

    def test_no_flag_shell_false(self):
        code = "import subprocess\nsubprocess.run(['ls'], shell=False)"
        tree, lines = _parse(code)
        assert SubprocessShellRule().check(tree, "test.py", lines) == []

    def test_no_flag_no_shell_kwarg(self):
        code = "import subprocess\nsubprocess.run(['ls'])"
        tree, lines = _parse(code)
        assert SubprocessShellRule().check(tree, "test.py", lines) == []


class TestVG006Pickle:
    def test_detects_pickle_load(self):
        code = "import pickle\ndata = pickle.load(f)"
        tree, lines = _parse(code)
        findings = PickleRule().check(tree, "test.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "unsafe_deserialization"

    def test_detects_pickle_loads(self):
        code = "import pickle\ndata = pickle.loads(raw)"
        tree, lines = _parse(code)
        assert len(PickleRule().check(tree, "test.py", lines)) == 1

    def test_detects_from_pickle_import_load(self):
        code = "from pickle import load\ndata = load(f)"
        tree, lines = _parse(code)
        assert len(PickleRule().check(tree, "test.py", lines)) == 1

    def test_detects_cpickle(self):
        code = "import cPickle\ndata = cPickle.loads(raw)"
        tree, lines = _parse(code)
        assert len(PickleRule().check(tree, "test.py", lines)) == 1


class TestVG007Assert:
    def test_detects_auth_assert(self):
        tree, lines = _parse("assert user.is_authenticated")
        findings = SecurityAssertRule().check(tree, "test.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "assert_used_for_validation"

    def test_detects_admin_assert(self):
        tree, lines = _parse("assert is_admin(user)")
        findings = SecurityAssertRule().check(tree, "test.py", lines)
        assert len(findings) == 1

    def test_detects_permission_assert(self):
        tree, lines = _parse("assert user.has_permission('edit')")
        findings = SecurityAssertRule().check(tree, "test.py", lines)
        assert len(findings) == 1

    def test_flags_all_asserts(self):
        # Rule now flags every assert regardless of context
        tree, lines = _parse("assert len(items) > 0")
        assert len(SecurityAssertRule().check(tree, "test.py", lines)) == 1

    def test_flags_math_assert(self):
        tree, lines = _parse("assert result == expected_value")
        assert len(SecurityAssertRule().check(tree, "test.py", lines)) == 1


class TestVG010YamlLoad:
    def test_detects_yaml_load_without_loader(self):
        code = "import yaml\ndata = yaml.load(raw)"
        tree, lines = _parse(code)
        findings = UnsafeYamlLoadRule().check(tree, "test.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "unsafe_yaml_load"

    def test_detects_direct_yaml_load_import(self):
        code = "from yaml import load\ndata = load(raw)"
        tree, lines = _parse(code)
        assert len(UnsafeYamlLoadRule().check(tree, "test.py", lines)) == 1

    def test_no_flag_safe_load(self):
        code = "import yaml\ndata = yaml.safe_load(raw)"
        tree, lines = _parse(code)
        assert UnsafeYamlLoadRule().check(tree, "test.py", lines) == []

    def test_no_flag_safe_loader(self):
        code = "import yaml\ndata = yaml.load(raw, Loader=yaml.SafeLoader)"
        tree, lines = _parse(code)
        assert UnsafeYamlLoadRule().check(tree, "test.py", lines) == []


class TestVG011TlsVerify:
    def test_detects_requests_verify_false(self):
        code = "import requests\nrequests.get('https://example.com', verify=False)"
        tree, lines = _parse(code)
        findings = DisabledTlsVerificationRule().check(tree, "test.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "tls_verification_disabled"

    def test_detects_direct_requests_import(self):
        code = "from requests import post\npost('https://example.com', verify=False)"
        tree, lines = _parse(code)
        assert len(DisabledTlsVerificationRule().check(tree, "test.py", lines)) == 1

    def test_no_flag_verify_true(self):
        code = "import requests\nrequests.get('https://example.com', verify=True)"
        tree, lines = _parse(code)
        assert DisabledTlsVerificationRule().check(tree, "test.py", lines) == []


class TestVG012DebugMode:
    def test_detects_app_run_debug_true(self):
        tree, lines = _parse("app.run(debug=True)")
        findings = DebugModeRule().check(tree, "test.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "debug_mode_enabled"

    def test_detects_fastapi_debug_true(self):
        tree, lines = _parse("app = FastAPI(debug=True)")
        assert len(DebugModeRule().check(tree, "test.py", lines)) == 1

    def test_detects_app_debug_assignment(self):
        tree, lines = _parse("app.debug = True")
        assert len(DebugModeRule().check(tree, "test.py", lines)) == 1

    def test_detects_settings_debug_constant(self):
        tree, lines = _parse("DEBUG = True")
        assert len(DebugModeRule().check(tree, "test.py", lines)) == 1

    def test_no_flag_debug_false(self):
        tree, lines = _parse("app.run(debug=False)")
        assert DebugModeRule().check(tree, "test.py", lines) == []


class TestVG013SqlInjection:
    def test_detects_f_string_sql_execute(self):
        code = "cursor.execute(f\"SELECT * FROM users WHERE name = '{name}'\")"
        tree, lines = _parse(code)
        findings = SqlInjectionRule().check(tree, "test.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "sql_query_construction"

    def test_detects_percent_formatted_sql(self):
        code = "cursor.execute(\"SELECT * FROM users WHERE id = %s\" % user_id)"
        tree, lines = _parse(code)
        assert len(SqlInjectionRule().check(tree, "test.py", lines)) == 1

    def test_detects_format_sql(self):
        code = "cursor.execute(\"DELETE FROM users WHERE id = {}\".format(user_id))"
        tree, lines = _parse(code)
        assert len(SqlInjectionRule().check(tree, "test.py", lines)) == 1

    def test_no_flag_parameterized_sql(self):
        code = "cursor.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,))"
        tree, lines = _parse(code)
        assert SqlInjectionRule().check(tree, "test.py", lines) == []

    def test_detects_sql_variable_execute(self):
        code = """
sql = f"SELECT * FROM users WHERE name = '{name}'"
cursor.execute(sql)
"""
        tree, lines = _parse(code)
        findings = SqlInjectionRule().check(tree, "test.py", lines)
        assert len(findings) >= 1
        assert all(f.rule_id == "sql_query_construction" for f in findings)

    def test_no_flag_static_fstring_sql_with_params(self):
        code = """
sql = f"SELECT * FROM users WHERE id = ?"
cursor.execute(sql, (user_id,))
"""
        tree, lines = _parse(code)
        assert SqlInjectionRule().check(tree, "test.py", lines) == []


class TestVG013SqlalchemyText:
    def test_detects_text_percent_format(self):
        code = 'result.filter(text("title = \'%s\'" % (name, name)))'
        tree, lines = _parse(code)
        assert len(SqlInjectionRule().check(tree, "test.py", lines)) == 1


class TestVG013DjangoRaw:
    def test_detects_objects_raw_percent_format(self):
        code = """
users = User.objects.raw(
    "SELECT * FROM %s WHERE user_id='%s' ORDER BY is_admin='0'"
    % (table_name, user_id_form))
"""
        tree, lines = _parse(code)
        assert len(SqlInjectionRule().check(tree, "views.py", lines)) == 1


class TestVG014ShellWrapper:
    def test_detects_wrapper_call_with_dynamic_arg(self):
        from security.rules.security.vg014_shell_wrapper import (
            ShellWrapperCallRule,
            set_repo_shell_wrappers,
        )

        set_repo_shell_wrappers(frozenset({"run_cmd"}))
        try:
            tree, lines = _parse("run_cmd(user_input)")
            findings = ShellWrapperCallRule().check(tree, "test.py", lines)
            assert len(findings) == 1
            assert findings[0].rule_id == "shell_wrapper_call"
        finally:
            set_repo_shell_wrappers(frozenset())


class TestVG015Ssti:
    def test_detects_render_template_string_variable(self):
        from security.rules.security.vg015_ssti import ServerSideTemplateInjectionRule

        code = "return render_template_string(template)"
        tree, lines = _parse(code)
        findings = ServerSideTemplateInjectionRule().check(tree, "test.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "server_side_template_injection"


class TestVG009OsImportAlias:
    def test_detects_from_os_import_popen(self):
        from security.rules.security.vg009_os_shell import OsShellRule

        code = "from os import popen\npopen('ls')"
        tree, lines = _parse(code)
        assert len(OsShellRule().check(tree, "test.py", lines)) == 1


class TestVG003DictSecrets:
    def test_detects_password_in_dict_literal(self):
        code = 'users = [{"username": "admin", "password": "secret123"}]'
        tree, lines = _parse(code)
        findings = HardcodedSecretsRule().check(tree, "seed.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "hardcoded_secret"


class TestVG002Compile:
    def test_detects_compile(self):
        tree, lines = _parse("compile(user_code, '<string>', 'exec')")
        findings = ExecUsageRule().check(tree, "test.py", lines)
        assert len(findings) == 1


class TestVG013SqlDedupe:
    def test_single_finding_for_assign_then_execute(self):
        code = """
query = f"SELECT * FROM users WHERE id={user_id}"
cursor.execute(query)
"""
        tree, lines = _parse(code)
        findings = SqlInjectionRule().check(tree, "views.py", lines)
        assert len(findings) == 1

    def test_single_finding_for_assign_then_raw(self):
        code = """
sql_query = "SELECT * FROM t WHERE user='" + name + "'"
login.objects.raw(sql_query)
"""
        tree, lines = _parse(code)
        findings = SqlInjectionRule().check(tree, "views.py", lines)
        assert len(findings) == 1


class TestVG003HashSkip:
    def test_skips_hex_password_hashes(self):
        code = 'USER = {"username": "User1", "password": "491a2800b80719ea9e3c89ca5472a8bda1bdd1533d4574ea5bd85b70a8e93be0"}'
        tree, lines = _parse(code)
        assert HardcodedSecretsRule().check(tree, "views.py", lines) == []


class TestVG016StaticPath:
    def test_skips_open_on_static_join_path(self):
        from security.rules.security.vg016_path_traversal import PathTraversalRule

        code = """
dirname = os.path.dirname(__file__)
log_filename = os.path.join(dirname, "playground/A9/main.py")
f = open(log_filename, "w")
"""
        tree, lines = _parse(code)
        assert PathTraversalRule().check(tree, "apis.py", lines) == []


class TestVG016PathJoin:
    def test_detects_os_path_join_with_untrusted_name(self):
        from security.rules.security.vg016_path_traversal import PathTraversalRule

        code = "path = os.path.join(data_path, uploaded_file.name)"
        tree, lines = _parse(code)
        findings = PathTraversalRule().check(tree, "benefits.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "path_traversal"


class TestVG019CleartextCredentials:
    def test_detects_password_from_request(self):
        from security.rules.security.vg019_cleartext_credentials import (
            CleartextCredentialHandlingRule,
        )

        code = "User(username=request.form['username'], password=request.form['password'])"
        tree, lines = _parse(code)
        findings = CleartextCredentialHandlingRule().check(tree, "app.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "cleartext_credential_handling"


class TestVG020ErrorDisclosure:
    def test_detects_traceback_format_exc(self):
        from security.rules.security.vg020_error_disclosure import VerboseErrorDisclosureRule

        code = "return traceback.format_exc()"
        tree, lines = _parse(code)
        findings = VerboseErrorDisclosureRule().check(tree, "views.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "verbose_error_disclosure"


class TestVG021UnsafeFileWrite:
    def test_detects_write_of_request_data(self):
        from security.rules.security.vg021_unsafe_file_write import UnsafeFileWriteRule

        code = """
def handler(request):
    log_code = request.POST.get('log_code')
    f = open("main.py", "w")
    f.write(log_code)
"""
        tree, lines = _parse(code)
        findings = UnsafeFileWriteRule().check(tree, "apis.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "unsafe_file_write"
