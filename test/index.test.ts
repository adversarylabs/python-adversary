import assert from "node:assert/strict";
import test from "node:test";
import { createAdversaryRunEnvelope } from "@adversarylabs/sdk";
import { createApp } from "../src/index.ts";

const fixture = (name: string) => new URL(`../fixtures/${name}`, import.meta.url).pathname;
const review = (name: string, raw = false) => createApp().run({ input: { source: { path: fixture(name) } }, includeRawObservations: raw });
const ruleCases = [{"key": "shell-true", "id": "python.shell-true"}, {"key": "os-system", "id": "python.os-system"}, {"key": "pickle-loads", "id": "python.pickle-loads"}, {"key": "unsafe-yaml", "id": "python.unsafe-yaml"}, {"key": "eval-exec-dynamic", "id": "python.eval-exec-dynamic"}, {"key": "tls-disabled", "id": "python.tls-disabled"}, {"key": "sql-format-fstring", "id": "python.sql-format-fstring"}, {"key": "flask-debug", "id": "python.flask-debug"}, {"key": "requests-no-timeout", "id": "python.requests-no-timeout"}, {"key": "sqlalchemy-offline-postgres-literal", "id": "python.sqlalchemy-offline-postgres-literal"}];

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

test("output ordering and protocol envelope are deterministic", async () => {
  const first = await review(`rules/${ruleCases[0]?.key}/vulnerable`, true);
  const second = await review(`rules/${ruleCases[0]?.key}/vulnerable`, true);
  assert.deepEqual(second, first);
  const envelope = JSON.parse(JSON.stringify(createAdversaryRunEnvelope(first)));
  assert.equal(envelope.protocolVersion, 1);
  assert.equal(envelope.result.adversary.name, "python");
});
