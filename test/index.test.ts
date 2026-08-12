import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";
import { createAdversaryRunEnvelope } from "@adversarylabs/sdk";
import { createApp } from "../src/index.ts";

const execute = promisify(execFile);

const fixture = (name: string) => new URL(`../fixtures/${name}`, import.meta.url).pathname;
const review = (name: string, raw = false) => createApp().run({ input: { source: { path: fixture(name) } }, includeRawObservations: raw });
const ruleCases = [{"key": "shell-true", "id": "python.shell-true"}, {"key": "os-system", "id": "python.os-system"}, {"key": "pickle-loads", "id": "python.pickle-loads"}, {"key": "unsafe-yaml", "id": "python.unsafe-yaml"}, {"key": "eval-exec-dynamic", "id": "python.eval-exec-dynamic"}, {"key": "tls-disabled", "id": "python.tls-disabled"}, {"key": "sql-format-fstring", "id": "python.sql-format-fstring"}, {"key": "flask-debug", "id": "python.flask-debug"}, {"key": "tempfile-mktemp", "id": "python.tempfile-mktemp"}, {"key": "requests-no-timeout", "id": "python.requests-no-timeout"}, {"key": "sqlalchemy-offline-postgres-literal", "id": "python.sqlalchemy-offline-postgres-literal"}];

test("offline PostgreSQL finding describes value corruption without claiming injection", async () => {
  const output = await review("rules/sqlalchemy-offline-postgres-literal/vulnerable", true);
  const finding = output.findings.find((item) => item.ruleId === "python.sqlalchemy-offline-postgres-literal");
  assert.ok(finding);
  assert.equal(finding.confidence, "medium");
  assert.match(finding.whyItMatters ?? "", /live connection/i);
  assert.match(finding.impact ?? "", /wrong rows|different text/i);
  assert.doesNotMatch(`${finding.title} ${finding.summary} ${finding.whyItMatters} ${finding.impact}`, /injection/i);
  assert.deepEqual(
    output.rawObservations
      ?.filter((item) => item.ruleId === "python.sqlalchemy-offline-postgres-literal")
      .map((item) => item.location?.file),
    ["app/direct.py", "app/literals.py"],
  );
});

test("every shipped rule has focused vulnerable and clean coverage", async () => {
  for (const rule of ruleCases) {
    const vulnerable = await review(`rules/${rule.key}/vulnerable`, true);
    assert.equal(vulnerable.findings.some((finding) => finding.ruleId === rule.id), true, `${rule.id} did not detect its vulnerable fixture`);
    assert.equal(vulnerable.rawObservations?.every((item) => item.location?.file !== undefined), true);
    const clean = await review(`rules/${rule.key}/clean`);
    assert.equal(clean.findings.some((finding) => finding.ruleId === rule.id), false, `${rule.id} flagged its clean fixture`);
  }
});

test("accepts a repository without applicable configuration", async () => {
  const output = await review("clean");
  assert.deepEqual(output.findings, []);
  assert.equal(output.assessment?.risk, "none");
  assert.equal(output.opinion?.ship, true);
});

test("tempfile.mktemp evidence points to the call", async () => {
  const output = await review("rules/tempfile-mktemp/vulnerable", true);
  const observation = output.rawObservations?.find((item) => item.ruleId === "python.tempfile-mktemp");
  assert.equal(observation?.location?.line, 5);
  assert.equal(observation?.location?.snippet, "path = tempfile.mktemp(suffix=\".log\")");
});

test("an unrelated edit does not surface a legacy local finding", async () => {
  const legacy = 'import requests\nrequests.get("https://example.test/legacy")\n';
  const root = await gitRepository({ "app.py": legacy });
  try {
    await writeFile(join(root, "app.py"), `${legacy}\n# unrelated documentation update\n`);
    const output = await changedReview(root, ["app.py"]);
    assert.equal(output.findings.some((finding) => finding.ruleId === "python.requests-no-timeout"), false);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("matching continues past legacy code to a later changed finding", async () => {
  const legacy = 'import requests\nrequests.get("https://example.test/legacy")\n';
  const root = await gitRepository({ "app.py": legacy });
  try {
    await writeFile(
      join(root, "app.py"),
      `${legacy}requests.post("https://example.test/new")\n`,
    );
    const output = await changedReview(root, ["app.py"]);
    const observation = output.rawObservations?.find(
      (item) => item.ruleId === "python.requests-no-timeout",
    );
    assert.equal(observation?.location?.line, 3);
    assert.equal(observation?.location?.snippet, 'requests.post("https://example.test/new")');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("unchanged prerequisites remain available as context for a changed match", async () => {
  const root = await gitRepository({
    "app.py": [
      "from sqlalchemy import String",
      "",
      "def escape(database, value):",
      "    dialect = database.get_dialect()",
      "    compiler = dialect.statement_compiler(dialect, None)",
      "    return compiler.process(value)",
      "",
    ].join("\n"),
  });
  try {
    await writeFile(
      join(root, "app.py"),
      [
        "from sqlalchemy import String",
        "",
        "def escape(database, value):",
        "    dialect = database.get_dialect()",
        "    compiler = dialect.statement_compiler(dialect, None)",
        "    return compiler.render_literal_value(value, String())[1:-1]",
        "",
      ].join("\n"),
    );
    const output = await changedReview(root, ["app.py"]);
    assert.equal(
      output.findings.some(
        (finding) => finding.ruleId === "python.sqlalchemy-offline-postgres-literal",
      ),
      true,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a newly added Python file remains fully eligible", async () => {
  const root = await gitRepository({ "README.md": "# service\n" });
  try {
    await writeFile(join(root, "app.py"), 'import requests\nrequests.get("https://example.test/new")\n');
    const output = await changedReview(root, ["app.py"]);
    assert.equal(output.findings.some((finding) => finding.ruleId === "python.requests-no-timeout"), true);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("output ordering and protocol envelope are deterministic", async () => {
  const first = await review(`rules/${ruleCases[0]?.key}/vulnerable`, true);
  const second = await review(`rules/${ruleCases[0]?.key}/vulnerable`, true);
  assert.deepEqual(second, first);
  const envelope = JSON.parse(JSON.stringify(createAdversaryRunEnvelope(first)));
  assert.equal(envelope.protocolVersion, 1);
  assert.equal(envelope.result.adversary.name, "python");
});

async function changedReview(root: string, changedFiles: string[]) {
  return createApp().run({
    input: {
      source: { path: root },
      change: {
        type: "diff",
        base_ref: "HEAD",
        head_ref: "WORKTREE",
        scan_mode: "changed",
        changed_files: changedFiles,
      },
    },
    includeRawObservations: true,
  });
}

async function gitRepository(files: Record<string, string>): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "python-adversary-git-"));
  await execute("git", ["init", "--quiet", root]);
  await execute("git", ["-C", root, "config", "user.email", "tests@example.com"]);
  await execute("git", ["-C", root, "config", "user.name", "Tests"]);
  for (const [path, content] of Object.entries(files)) {
    await writeFile(join(root, path), content);
  }
  await execute("git", ["-C", root, "add", "."]);
  await execute("git", ["-C", root, "commit", "--quiet", "-m", "baseline"]);
  return root;
}
