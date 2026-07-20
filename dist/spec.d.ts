import { type Confidence, type Severity } from "@adversarylabs/sdk";
export interface MatchExpression {
    pattern: string;
    flags: string;
}
interface ContentMatch {
    kind: "content";
    files: string[];
    pattern: MatchExpression;
    requires: MatchExpression[];
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
    readonly description: "Reviews Python for shell injection, unsafe YAML, and disabled TLS verification.";
    readonly files: ["**/*.py"];
    readonly rules: [{
        readonly id: "python.shell-true";
        readonly title: "Subprocess executes through a shell";
        readonly summary: "Subprocess executes through a shell";
        readonly category: "security";
        readonly severity: "critical";
        readonly confidence: "high";
        readonly whyItMatters: "Subprocess executes through a shell weakens an important security boundary.";
        readonly impact: "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.";
        readonly recommendation: "Pass an argument list with shell=False.";
        readonly complexity: "small";
        readonly tags: ["security", "shell-true"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.py"];
            readonly pattern: {
                readonly pattern: "subprocess\\.(?:run|Popen|call|check_output)\\([^\\n]*shell\\s*=\\s*True";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "python.unsafe-yaml";
        readonly title: "PyYAML loads objects unsafely";
        readonly summary: "PyYAML loads objects unsafely";
        readonly category: "security";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "PyYAML loads objects unsafely weakens an important security boundary.";
        readonly impact: "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.";
        readonly recommendation: "Use yaml.safe_load or SafeLoader.";
        readonly complexity: "small";
        readonly tags: ["security", "unsafe-yaml"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.py"];
            readonly pattern: {
                readonly pattern: "yaml\\.load\\([^\\n]*\\)";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "python.tls-disabled";
        readonly title: "HTTP request disables certificate verification";
        readonly summary: "HTTP request disables certificate verification";
        readonly category: "security";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "HTTP request disables certificate verification weakens an important security boundary.";
        readonly impact: "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.";
        readonly recommendation: "Keep TLS verification enabled.";
        readonly complexity: "small";
        readonly tags: ["security", "tls-disabled"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.py"];
            readonly pattern: {
                readonly pattern: "requests\\.(?:get|post|put|delete|request)\\([^\\n]*verify\\s*=\\s*False";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }];
};
export {};
