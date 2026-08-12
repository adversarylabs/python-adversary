import { type Confidence, type Severity } from "@adversarylabs/sdk";
export interface MatchExpression {
    pattern: string;
    flags: string;
}
interface ContentMatch {
    kind: "content";
    files: string[];
    excludeFiles?: string[];
    pattern: MatchExpression;
    anchors?: MatchExpression[];
    requires: MatchExpression[];
    excludes?: MatchExpression[];
}
interface MissingContentMatch {
    kind: "missing-content";
    files: string[];
    trigger: MatchExpression;
    required: MatchExpression;
}
interface MissingFileMatch {
    kind: "missing-file";
    triggerFiles: string[];
    requiredFiles: string[];
}
export interface RuleSpec {
    id: string;
    title: string;
    summary: string;
    category: string;
    severity: Severity;
    confidence: Confidence;
    whyItMatters: string;
    impact: string;
    recommendation: string;
    complexity: "trivial" | "small" | "medium" | "large";
    tags: string[];
    match: ContentMatch | MissingContentMatch | MissingFileMatch;
}
export interface AdversarySpec {
    id: string;
    displayName: string;
    description: string;
    files: string[];
    rules: RuleSpec[];
}
export declare const spec: {
    readonly id: "python";
    readonly displayName: "Python";
    readonly description: "Reviews Python for shell injection, unsafe deserialization, disabled TLS, and SQL string building.";
    readonly files: ["**/*.py"];
    readonly rules: [{
        readonly id: "python.shell-true";
        readonly title: "subprocess uses shell=True with a dynamic command";
        readonly summary: "subprocess uses shell=True with a dynamic command";
        readonly category: "security";
        readonly severity: "critical";
        readonly confidence: "high";
        readonly whyItMatters: "shell=True enables OS command injection on dynamic strings.";
        readonly impact: "Attacker-controlled input can execute arbitrary shell.";
        readonly recommendation: "Pass an argument list with shell=False.";
        readonly complexity: "small";
        readonly tags: ["security", "shell"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.py"];
            readonly pattern: {
                readonly pattern: "shell\\s*=\\s*True";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "python.os-system";
        readonly title: "os.system or os.popen with dynamic command";
        readonly summary: "os.system or os.popen with dynamic command";
        readonly category: "security";
        readonly severity: "critical";
        readonly confidence: "high";
        readonly whyItMatters: "os.system always goes through the shell.";
        readonly impact: "Command injection via string-built shell invocations.";
        readonly recommendation: "Use subprocess.run with an argv list.";
        readonly complexity: "small";
        readonly tags: ["security", "os-system"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.py"];
            readonly pattern: {
                readonly pattern: "os\\.(?:system|popen)\\s*\\(\\s*(?:f[\\\"']|[^\\\"']*[+%]|\\w+\\s*\\+)";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "python.pickle-loads";
        readonly title: "Untrusted pickle or unsafe torch.load";
        readonly summary: "Untrusted pickle or unsafe torch.load";
        readonly category: "security";
        readonly severity: "critical";
        readonly confidence: "high";
        readonly whyItMatters: "Pickle is an execution format; untrusted pickle is RCE.";
        readonly impact: "Arbitrary code execution on load.";
        readonly recommendation: "Use JSON/msgpack; never unpickle untrusted data.";
        readonly complexity: "small";
        readonly tags: ["security", "pickle"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.py"];
            readonly pattern: {
                readonly pattern: "(?:pickle\\.(?:loads?|Unpickler)|cPickle\\.loads?|joblib\\.load|torch\\.load\\s*\\([^)]*weights_only\\s*=\\s*False)\\s*\\(";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "python.unsafe-yaml";
        readonly title: "yaml.load without SafeLoader";
        readonly summary: "yaml.load without SafeLoader";
        readonly category: "security";
        readonly severity: "critical";
        readonly confidence: "high";
        readonly whyItMatters: "Historical full-loader RCE on untrusted YAML (CVE-2017-18342).";
        readonly impact: "Arbitrary code execution via crafted YAML.";
        readonly recommendation: "Use yaml.safe_load or SafeLoader exclusively.";
        readonly complexity: "small";
        readonly tags: ["security", "yaml"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.py"];
            readonly pattern: {
                readonly pattern: "yaml\\.load\\s*\\(";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "python.eval-exec-dynamic";
        readonly title: "eval or exec on non-literal input";
        readonly summary: "eval or exec on non-literal input";
        readonly category: "security";
        readonly severity: "critical";
        readonly confidence: "high";
        readonly whyItMatters: "Direct code injection when dynamic data reaches eval/exec.";
        readonly impact: "Arbitrary Python execution.";
        readonly recommendation: "Use ast.literal_eval for data, or redesign.";
        readonly complexity: "small";
        readonly tags: ["security", "eval"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.py"];
            readonly pattern: {
                readonly pattern: "(?:(?<!literal_)eval|(?<!literal_)exec)\\s*\\(\\s*\\w+";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "python.tls-disabled";
        readonly title: "TLS verification disabled";
        readonly summary: "TLS verification disabled";
        readonly category: "security";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "MITM on credentials and tokens.";
        readonly impact: "Credential interception on HTTPS calls.";
        readonly recommendation: "Keep verification on; fix CA trust properly.";
        readonly complexity: "small";
        readonly tags: ["security", "tls"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.py"];
            readonly pattern: {
                readonly pattern: "verify\\s*=\\s*False|ssl\\._create_unverified_context";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "python.sql-format-fstring";
        readonly title: "SQL built with f-string or format into execute";
        readonly summary: "SQL built with f-string or format into execute";
        readonly category: "security";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "String-built SQL enables injection.";
        readonly impact: "Database compromise via attacker-controlled SQL.";
        readonly recommendation: "Use bound parameters only.";
        readonly complexity: "small";
        readonly tags: ["security", "sqli"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.py"];
            readonly pattern: {
                readonly pattern: "\\.(?:execute|executemany)\\s*\\(\\s*(?:f[\\\"']|[\\\"'][^\\\"']*\\{)";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "python.flask-debug";
        readonly title: "Web framework debug or reload enabled";
        readonly summary: "Web framework debug or reload enabled";
        readonly category: "security";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "Debug mode can expose interactive debuggers and secrets.";
        readonly impact: "Remote code execution or secret disclosure in production.";
        readonly recommendation: "Never enable debug in production.";
        readonly complexity: "small";
        readonly tags: ["security", "debug"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.py"];
            readonly pattern: {
                readonly pattern: "\\.run\\s*\\([^)]*debug\\s*=\\s*True|FLASK_DEBUG\\s*=\\s*[\\\"']?1|uvicorn\\.run\\s*\\([^)]*reload\\s*=\\s*True";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "python.tempfile-mktemp";
        readonly title: "tempfile.mktemp creates a race-prone path";
        readonly summary: "tempfile.mktemp creates a race-prone path";
        readonly category: "security";
        readonly severity: "medium";
        readonly confidence: "high";
        readonly whyItMatters: "tempfile.mktemp returns a pathname without atomically creating it, leaving a race before the caller opens the path.";
        readonly impact: "Another process can claim or redirect the path, causing data disclosure, overwrite, or use of an attacker-controlled file.";
        readonly recommendation: "Use TemporaryFile, NamedTemporaryFile, TemporaryDirectory, or mkstemp so the temporary object is created atomically.";
        readonly complexity: "small";
        readonly tags: ["security", "tempfile", "race-condition"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.py"];
            readonly pattern: {
                readonly pattern: "^[ \\t]*(?!#)(?:(?:return|yield)\\s+|[A-Za-z_][\\w.\\[\\]'\\\"]*\\s*=\\s*|[A-Za-z_][\\w.]*\\s*\\([^#'\\\"\\r\\n]*)tempfile\\.mktemp\\s*\\(";
                readonly flags: "m";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "python.requests-no-timeout";
        readonly title: "HTTP client call without timeout";
        readonly summary: "HTTP client call without timeout";
        readonly category: "reliability";
        readonly severity: "medium";
        readonly confidence: "high";
        readonly whyItMatters: "requests has no default timeout; hung peers hang workers.";
        readonly impact: "Production outages from blocked workers.";
        readonly recommendation: "Pass timeout= on every call or session default.";
        readonly complexity: "small";
        readonly tags: ["reliability", "timeout"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.py"];
            readonly pattern: {
                readonly pattern: "requests\\.(?:get|post|put|patch|delete|head|request)\\s*\\((?![^)]*timeout\\s*=)";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "python.sqlalchemy-offline-postgres-literal";
        readonly title: "Offline PostgreSQL literal rendering may use the wrong backslash mode";
        readonly summary: "Offline PostgreSQL literal rendering may use the wrong backslash mode";
        readonly category: "correctness";
        readonly severity: "medium";
        readonly confidence: "medium";
        readonly whyItMatters: "SQLAlchemy normally derives PostgreSQL backslash behavior from a live connection. An offline dialect can retain the wrong default and silently alter backslash-containing values when generated quotes are stripped.";
        readonly impact: "Rendered values can be changed before interpolation, causing queries to match the wrong rows or persist different text than the caller supplied.";
        readonly recommendation: "Prefer bound parameters. If offline literal rendering is unavoidable, explicitly configure the PostgreSQL backslash mode and cover quotes and backslashes with regression tests.";
        readonly complexity: "small";
        readonly tags: ["correctness", "sqlalchemy", "postgresql"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.py"];
            readonly excludeFiles: ["**/*_test.py", "**/test_*.py", "**/tests/**"];
            readonly pattern: {
                readonly pattern: "\\.statement_compiler\\s*\\(\\s*[^,\\n]+,\\s*None\\s*\\)[\\s\\S]{0,1200}?\\.render_literal_value\\s*\\([^\\n]+\\)\\s*\\[\\s*1\\s*:\\s*-1\\s*\\]";
                readonly flags: "i";
            };
            readonly anchors: [{
                readonly pattern: "\\.statement_compiler\\s*\\(\\s*[^,\\n]+,\\s*None\\s*\\)";
                readonly flags: "i";
            }, {
                readonly pattern: "\\.render_literal_value\\s*\\([^\\n]+\\)\\s*\\[\\s*1\\s*:\\s*-1\\s*\\]";
                readonly flags: "i";
            }];
            readonly requires: [{
                readonly pattern: "\\bsqlalchemy\\b";
                readonly flags: "i";
            }, {
                readonly pattern: "(?:\\.get_dialect\\s*\\(\\s*\\)|postgresql\\.dialect\\s*\\(\\s*\\)|url\\.get_dialect\\s*\\(\\s*\\)\\s*\\(\\s*\\))";
                readonly flags: "i";
            }];
            readonly excludes: [{
                readonly pattern: "_?backslash_escapes\\s*=\\s*False";
                readonly flags: "i";
            }, {
                readonly pattern: "(?:if|assert)[^\\n]*dialect\\.name[^\\n]*(?:mysql|mariadb)[^\\n]*:\\s*\\r?\\n\\s+return\\b";
                readonly flags: "i";
            }];
        };
    }];
};
export {};
