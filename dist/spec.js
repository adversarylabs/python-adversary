export const spec = {
    "id": "python",
    "displayName": "Python",
    "description": "Reviews Python for shell injection, unsafe deserialization, disabled TLS, and SQL string building.",
    "files": [
        "**/*.py"
    ],
    "rules": [
        {
            "id": "python.shell-true",
            "title": "subprocess uses shell=True with a dynamic command",
            "summary": "subprocess uses shell=True with a dynamic command",
            "category": "security",
            "severity": "critical",
            "confidence": "high",
            "whyItMatters": "shell=True enables OS command injection on dynamic strings.",
            "impact": "Attacker-controlled input can execute arbitrary shell.",
            "recommendation": "Pass an argument list with shell=False.",
            "complexity": "small",
            "tags": [
                "security",
                "shell"
            ],
            "match": {
                "kind": "content",
                "files": [
                    "**/*.py"
                ],
                "pattern": {
                    "pattern": "shell\\s*=\\s*True",
                    "flags": "i"
                },
                "requires": []
            }
        },
        {
            "id": "python.os-system",
            "title": "os.system or os.popen with dynamic command",
            "summary": "os.system or os.popen with dynamic command",
            "category": "security",
            "severity": "critical",
            "confidence": "high",
            "whyItMatters": "os.system always goes through the shell.",
            "impact": "Command injection via string-built shell invocations.",
            "recommendation": "Use subprocess.run with an argv list.",
            "complexity": "small",
            "tags": [
                "security",
                "os-system"
            ],
            "match": {
                "kind": "content",
                "files": [
                    "**/*.py"
                ],
                "pattern": {
                    "pattern": "os\\.(?:system|popen)\\s*\\(\\s*(?:f[\\\"']|[^\\\"']*[+%]|\\w+\\s*\\+)",
                    "flags": "i"
                },
                "requires": []
            }
        },
        {
            "id": "python.pickle-loads",
            "title": "Untrusted pickle or unsafe torch.load",
            "summary": "Untrusted pickle or unsafe torch.load",
            "category": "security",
            "severity": "critical",
            "confidence": "high",
            "whyItMatters": "Pickle is an execution format; untrusted pickle is RCE.",
            "impact": "Arbitrary code execution on load.",
            "recommendation": "Use JSON/msgpack; never unpickle untrusted data.",
            "complexity": "small",
            "tags": [
                "security",
                "pickle"
            ],
            "match": {
                "kind": "content",
                "files": [
                    "**/*.py"
                ],
                "pattern": {
                    "pattern": "(?:pickle\\.(?:loads?|Unpickler)|cPickle\\.loads?|joblib\\.load|torch\\.load\\s*\\([^)]*weights_only\\s*=\\s*False)\\s*\\(",
                    "flags": "i"
                },
                "requires": []
            }
        },
        {
            "id": "python.unsafe-yaml",
            "title": "yaml.load without SafeLoader",
            "summary": "yaml.load without SafeLoader",
            "category": "security",
            "severity": "critical",
            "confidence": "high",
            "whyItMatters": "Historical full-loader RCE on untrusted YAML (CVE-2017-18342).",
            "impact": "Arbitrary code execution via crafted YAML.",
            "recommendation": "Use yaml.safe_load or SafeLoader exclusively.",
            "complexity": "small",
            "tags": [
                "security",
                "yaml"
            ],
            "match": {
                "kind": "content",
                "files": [
                    "**/*.py"
                ],
                "pattern": {
                    "pattern": "yaml\\.load\\s*\\(",
                    "flags": "i"
                },
                "requires": []
            }
        },
        {
            "id": "python.eval-exec-dynamic",
            "title": "eval or exec on non-literal input",
            "summary": "eval or exec on non-literal input",
            "category": "security",
            "severity": "critical",
            "confidence": "high",
            "whyItMatters": "Direct code injection when dynamic data reaches eval/exec.",
            "impact": "Arbitrary Python execution.",
            "recommendation": "Use ast.literal_eval for data, or redesign.",
            "complexity": "small",
            "tags": [
                "security",
                "eval"
            ],
            "match": {
                "kind": "content",
                "files": [
                    "**/*.py"
                ],
                "pattern": {
                    "pattern": "(?:(?<!literal_)eval|(?<!literal_)exec)\\s*\\(\\s*\\w+",
                    "flags": "i"
                },
                "requires": []
            }
        },
        {
            "id": "python.tls-disabled",
            "title": "TLS verification disabled",
            "summary": "TLS verification disabled",
            "category": "security",
            "severity": "high",
            "confidence": "high",
            "whyItMatters": "MITM on credentials and tokens.",
            "impact": "Credential interception on HTTPS calls.",
            "recommendation": "Keep verification on; fix CA trust properly.",
            "complexity": "small",
            "tags": [
                "security",
                "tls"
            ],
            "match": {
                "kind": "content",
                "files": [
                    "**/*.py"
                ],
                "pattern": {
                    "pattern": "verify\\s*=\\s*False|ssl\\._create_unverified_context",
                    "flags": "i"
                },
                "requires": []
            }
        },
        {
            "id": "python.sql-format-fstring",
            "title": "SQL built with f-string or format into execute",
            "summary": "SQL built with f-string or format into execute",
            "category": "security",
            "severity": "high",
            "confidence": "high",
            "whyItMatters": "String-built SQL enables injection.",
            "impact": "Database compromise via attacker-controlled SQL.",
            "recommendation": "Use bound parameters only.",
            "complexity": "small",
            "tags": [
                "security",
                "sqli"
            ],
            "match": {
                "kind": "content",
                "files": [
                    "**/*.py"
                ],
                "pattern": {
                    "pattern": "\\.(?:execute|executemany)\\s*\\(\\s*(?:f[\\\"']|[\\\"'][^\\\"']*\\{)",
                    "flags": "i"
                },
                "requires": []
            }
        },
        {
            "id": "python.flask-debug",
            "title": "Web framework debug or reload enabled",
            "summary": "Web framework debug or reload enabled",
            "category": "security",
            "severity": "high",
            "confidence": "high",
            "whyItMatters": "Debug mode can expose interactive debuggers and secrets.",
            "impact": "Remote code execution or secret disclosure in production.",
            "recommendation": "Never enable debug in production.",
            "complexity": "small",
            "tags": [
                "security",
                "debug"
            ],
            "match": {
                "kind": "content",
                "files": [
                    "**/*.py"
                ],
                "pattern": {
                    "pattern": "\\.run\\s*\\([^)]*debug\\s*=\\s*True|FLASK_DEBUG\\s*=\\s*[\\\"']?1|uvicorn\\.run\\s*\\([^)]*reload\\s*=\\s*True",
                    "flags": "i"
                },
                "requires": []
            }
        },
        {
            "id": "python.requests-no-timeout",
            "title": "HTTP client call without timeout",
            "summary": "HTTP client call without timeout",
            "category": "reliability",
            "severity": "medium",
            "confidence": "high",
            "whyItMatters": "requests has no default timeout; hung peers hang workers.",
            "impact": "Production outages from blocked workers.",
            "recommendation": "Pass timeout= on every call or session default.",
            "complexity": "small",
            "tags": [
                "reliability",
                "timeout"
            ],
            "match": {
                "kind": "content",
                "files": [
                    "**/*.py"
                ],
                "pattern": {
                    "pattern": "requests\\.(?:get|post|put|patch|delete|head|request)\\s*\\((?![^)]*timeout\\s*=)",
                    "flags": "i"
                },
                "requires": []
            }
        }
    ]
};
