export const spec = {
    "id": "python",
    "displayName": "Python",
    "description": "Reviews Python for shell injection, unsafe YAML, and disabled TLS verification.",
    "files": [
        "**/*.py"
    ],
    "rules": [
        {
            "id": "python.shell-true",
            "title": "Subprocess executes through a shell",
            "summary": "Subprocess executes through a shell",
            "category": "security",
            "severity": "critical",
            "confidence": "high",
            "whyItMatters": "Subprocess executes through a shell weakens an important security boundary.",
            "impact": "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.",
            "recommendation": "Pass an argument list with shell=False.",
            "complexity": "small",
            "tags": [
                "security",
                "shell-true"
            ],
            "match": {
                "kind": "content",
                "files": [
                    "**/*.py"
                ],
                "pattern": {
                    "pattern": "subprocess\\.(?:run|Popen|call|check_output)\\([^\\n]*shell\\s*=\\s*True",
                    "flags": "i"
                },
                "requires": []
            }
        },
        {
            "id": "python.unsafe-yaml",
            "title": "PyYAML loads objects unsafely",
            "summary": "PyYAML loads objects unsafely",
            "category": "security",
            "severity": "high",
            "confidence": "high",
            "whyItMatters": "PyYAML loads objects unsafely weakens an important security boundary.",
            "impact": "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.",
            "recommendation": "Use yaml.safe_load or SafeLoader.",
            "complexity": "small",
            "tags": [
                "security",
                "unsafe-yaml"
            ],
            "match": {
                "kind": "content",
                "files": [
                    "**/*.py"
                ],
                "pattern": {
                    "pattern": "yaml\\.load\\([^\\n]*\\)",
                    "flags": "i"
                },
                "requires": []
            }
        },
        {
            "id": "python.tls-disabled",
            "title": "HTTP request disables certificate verification",
            "summary": "HTTP request disables certificate verification",
            "category": "security",
            "severity": "high",
            "confidence": "high",
            "whyItMatters": "HTTP request disables certificate verification weakens an important security boundary.",
            "impact": "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.",
            "recommendation": "Keep TLS verification enabled.",
            "complexity": "small",
            "tags": [
                "security",
                "tls-disabled"
            ],
            "match": {
                "kind": "content",
                "files": [
                    "**/*.py"
                ],
                "pattern": {
                    "pattern": "requests\\.(?:get|post|put|delete|request)\\([^\\n]*verify\\s*=\\s*False",
                    "flags": "i"
                },
                "requires": []
            }
        }
    ]
};
