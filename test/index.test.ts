import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";
import { createAdversaryRunEnvelope } from "@adversarylabs/sdk";
import { createApp } from "../src/index.ts";

const execute = promisify(execFile);

const fixture = (name: string) => new URL(`../fixtures/${name}`, import.meta.url).pathname;
const review = (name: string, raw = false) => createApp().run({ input: { source: { path: fixture(name) } }, includeRawObservations: raw });
const ruleCases = [{"key": "shell-true", "id": "python.shell-true"}, {"key": "os-system", "id": "python.os-system"}, {"key": "pickle-loads", "id": "python.pickle-loads"}, {"key": "unsafe-yaml", "id": "python.unsafe-yaml"}, {"key": "eval-exec-dynamic", "id": "python.eval-exec-dynamic"}, {"key": "tls-disabled", "id": "python.tls-disabled"}, {"key": "sql-format-fstring", "id": "python.sql-format-fstring"}, {"key": "flask-debug", "id": "python.flask-debug"}, {"key": "tempfile-mktemp", "id": "python.tempfile-mktemp"}, {"key": "requests-no-timeout", "id": "python.requests-no-timeout"}, {"key": "oauth-client-credentials-reuse", "id": "python.oauth-client-credentials-reuse"}, {"key": "default-empty-destructive-sync", "id": "python.default-empty-destructive-sync"}, {"key": "sqlalchemy-offline-postgres-literal", "id": "python.sqlalchemy-offline-postgres-literal"}];

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

test("valid empty response collections remain eligible for intentional cleanup", async () => {
  const output = await review("rules/default-empty-destructive-sync/clean");
  assert.equal(
    output.findings.some((finding) => finding.ruleId === "python.default-empty-destructive-sync"),
    false,
  );
});

test("default-empty destructive sync findings are change-local", async () => {
  const legacy = `def sync(response, store):
    entries = response.get("records", [])
    seen = {entry["id"] for entry in entries}
    for saved in store.all():
        if saved.id not in seen:
            store.delete(saved)
`;
  const root = await gitRepository({ "sync.py": legacy });
  try {
    await writeFile(join(root, "sync.py"), `${legacy}\n# document synchronization ownership\n`);
    const unrelated = await changedReview(root, ["sync.py"]);
    assert.equal(
      unrelated.findings.some((finding) => finding.ruleId === "python.default-empty-destructive-sync"),
      false,
    );

    await writeFile(
      join(root, "sync.py"),
      legacy.replace('response.get("records", [])', 'response.get("records", ())'),
    );
    const changed = await changedReview(root, ["sync.py"]);
    const observation = changed.rawObservations?.find(
      (item) => item.ruleId === "python.default-empty-destructive-sync",
    );
    assert.equal(observation?.location?.line, 2);
    assert.equal(observation?.evidence?.responseField, "records");

    await writeFile(
      join(root, "sync.py"),
      legacy.replace("store.delete(saved)", "store.delete_item(saved)"),
    );
    const cleanupChanged = await changedReview(root, ["sync.py"]);
    const cleanupObservation = cleanupChanged.rawObservations?.find(
      (item) => item.ruleId === "python.default-empty-destructive-sync",
    );
    assert.equal(cleanupObservation?.location?.line, 6);
    assert.equal(cleanupObservation?.location?.snippet, "store.delete_item(saved)");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("OAuth client-credentials reuse requires a shared bearer and repeated request path", async () => {
  const positive = await reviewSource(oauthProgram([
    "    inventory.users.sync(api_session)",
    "    inventory.devices.sync(api_session)",
  ]));
  const observation = positive.rawObservations?.find(
    (item) => item.ruleId === "python.oauth-client-credentials-reuse",
  );
  assert.ok(observation);
  assert.equal(observation.confidence, "medium");
  assert.equal(observation.location?.snippet, 'api_session.headers.update({"Authorization": f"Bearer {bearer_token}"})');
  assert.deepEqual(observation.evidence?.consumerLines, [25, 26]);

  const repeated = await reviewSource(oauthProgram([
    "    for device in config.devices:",
    "        api_session.get(device.url, timeout=30)",
  ]));
  assert.equal(
    repeated.findings.some((finding) => finding.ruleId === "python.oauth-client-credentials-reuse"),
    true,
  );

  const sameStageRepeated = await reviewSource(oauthProgram([
    "    api_session.get(config.first_url, timeout=30)",
    "    api_session.get(config.second_url, timeout=30)",
  ]));
  assert.equal(
    sameStageRepeated.findings.some((finding) => finding.ruleId === "python.oauth-client-credentials-reuse"),
    true,
  );
});

test("OAuth bearer rule stays quiet for bounded, static, fresh, dead, and unresolved use", async () => {
  const variants = [
    oauthProgram(["    inventory.users.sync(api_session)"]),
    oauthProgram([
      "    inventory.users.sync(api_session)",
      "    inventory.devices.sync(api_session)",
    ]).replace("bearer_token = _mint_oauth_bearer(api_session, config)", "bearer_token = config.static_api_token"),
    oauthProgram([
      "    for device in config.devices:",
      "        bearer_token = _mint_oauth_bearer(api_session, config)",
      '        api_session.headers.update({"Authorization": f"Bearer {bearer_token}"})',
      "        api_session.get(device.url, timeout=30)",
    ]).replace(
      "    bearer_token = _mint_oauth_bearer(api_session, config)\n" +
      '    api_session.headers.update({"Authorization": f"Bearer {bearer_token}"})\n',
      "",
    ),
    oauthProgram([
      "    def callback():",
      "        inventory.users.sync(api_session)",
      "        inventory.devices.sync(api_session)",
      "    _ = callback",
    ]),
    oauthProgram([
      "    stage_one.process(api_session)",
      "    stage_two.process(api_session)",
    ]),
    oauthProgram([
      "        inventory.users.sync(api_session)",
      "        inventory.devices.sync(api_session)",
    ]).replace(
      "    bearer_token = _mint_oauth_bearer(api_session, config)",
      "    if False:\n        bearer_token = _mint_oauth_bearer(api_session, config)",
    ).replace(
      '    api_session.headers.update({"Authorization": f"Bearer {bearer_token}"})',
      '        api_session.headers.update({"Authorization": f"Bearer {bearer_token}"})',
    ),
  ];
  for (const [index, source] of variants.entries()) {
    const output = await reviewSource(source);
    assert.equal(
      output.findings.some((finding) => finding.ruleId === "python.oauth-client-credentials-reuse"),
      false,
      `quiet variant ${index}`,
    );
  }
});

test("OAuth bearer rule accepts bounded 401 and expiry-aware refresh", async () => {
  const bounded401 = await review("rules/oauth-client-credentials-reuse/clean");
  assert.equal(
    bounded401.findings.some((finding) => finding.ruleId === "python.oauth-client-credentials-reuse"),
    false,
  );

  const expiryAware = oauthProgram([
    "    expires_at = time.time() + config.oauth_expires_in",
    "    if time.time() >= expires_at:",
    "        bearer_token = _mint_oauth_bearer(api_session, config)",
    '        api_session.headers.update({"Authorization": f"Bearer {bearer_token}"})',
    "    inventory.users.sync(api_session)",
    "    inventory.devices.sync(api_session)",
  ]).replace("import requests", "import time\nimport requests").replace(
    "    response.raise_for_status()",
    '    response_ttl = response.json()["expires_in"]\n    response.raise_for_status()',
  );
  const output = await reviewSource(expiryAware);
  assert.equal(
    output.findings.some((finding) => finding.ruleId === "python.oauth-client-credentials-reuse"),
    false,
  );

  const unrelatedDeadline = oauthProgram([
    "    unrelated_deadline = time.time() + config.operation_ttl",
    "    if time.time() >= unrelated_deadline:",
    "        bearer_token = _mint_oauth_bearer(api_session, config)",
    '        api_session.headers.update({"Authorization": f"Bearer {bearer_token}"})',
    "    inventory.users.sync(api_session)",
    "    inventory.devices.sync(api_session)",
  ]).replace("import requests", "import time\nimport requests").replace(
    "    response.raise_for_status()",
    '    response_ttl = response.json()["expires_in"]\n    response.raise_for_status()',
  );
  assert.equal(
    (await reviewSource(unrelatedDeadline)).findings.some(
      (finding) => finding.ruleId === "python.oauth-client-credentials-reuse",
    ),
    true,
  );
});

test("OAuth bearer proof is binding-aware and rejects incomplete refresh lookalikes", async () => {
  const consumers = [
    "    inventory.users.sync(api_session)",
    "    inventory.devices.sync(api_session)",
  ];
  const aliased = oauthProgram(consumers)
    .replace("import requests", "import requests as http")
    .replaceAll("requests.", "http.");
  const aliasedOutput = await reviewSource(aliased);
  assert.equal(
    aliasedOutput.findings.some((finding) => finding.ruleId === "python.oauth-client-credentials-reuse"),
    true,
  );

  const quietVariants = [
    oauthProgram(consumers).replace(
      "    api_session = requests.Session()",
      "    requests = config.requests\n    api_session = requests.Session()",
    ),
    oauthProgram(consumers).replace(
      '    api_session.headers.update({"Authorization": f"Bearer {bearer_token}"})',
      '    api_session.headers.update({"Authorization": f"Bearer {bearer_token}"})\n    api_session = requests.Session()',
    ),
    oauthProgram(consumers).replace(
      '    api_session.headers.update({"Authorization": f"Bearer {bearer_token}"})',
      '    api_session.headers.update({"Authorization": f"Bearer {bearer_token}"})\n    api_session.headers["Authorization"] = "Basic replacement"',
    ),
    oauthProgram(consumers).replace(
      "    api_session = requests.Session()",
      "    if config.enabled:\n        api_session = requests.Session()",
    ),
    oauthProgram(consumers).replace(
      "    bearer_token = _mint_oauth_bearer(api_session, config)",
      "    if config.enabled:\n        bearer_token = _mint_oauth_bearer(api_session, config)",
    ),
    oauthProgram(consumers).replace(
      '    api_session.headers.update({"Authorization": f"Bearer {bearer_token}"})',
      '    if config.enabled:\n        api_session.headers.update({"Authorization": f"Bearer {bearer_token}"})',
    ),
  ];
  for (const [index, source] of quietVariants.entries()) {
    const output = await reviewSource(source);
    assert.equal(
      output.findings.some((finding) => finding.ruleId === "python.oauth-client-credentials-reuse"),
      false,
      `binding variant ${index}`,
    );
  }

  const expiryMetadataOnly = oauthProgram(consumers).replace(
    "    response.raise_for_status()",
    '    expires_in = response.json()["expires_in"]\n    response.raise_for_status()',
  );
  const metadataOutput = await reviewSource(expiryMetadataOnly);
  assert.equal(
    metadataOutput.findings.some((finding) => finding.ruleId === "python.oauth-client-credentials-reuse"),
    true,
  );

  const incompleteRefresh = oauthProgram(consumers).replace(
    "def synchronize(config):",
    `def _attach_unbounded_refresh(api_session: requests.Session, config):
    def refresh(response, **kwargs):
        if response.status_code == 401:
            new_token = _mint_oauth_bearer(api_session, config)
            api_session.headers["Authorization"] = f"Bearer {new_token}"
            retried = response.request.copy()
            retried.headers["Authorization"] = f"Bearer {new_token}"
            return api_session.send(retried, **kwargs)
        return response
    api_session.hooks["response"].append(refresh)


def synchronize(config):`,
  ).replace(
    '    api_session.headers.update({"Authorization": f"Bearer {bearer_token}"})',
    '    api_session.headers.update({"Authorization": f"Bearer {bearer_token}"})\n    _attach_unbounded_refresh(api_session, config)',
  );
  const incompleteOutput = await reviewSource(incompleteRefresh);
  assert.equal(
    incompleteOutput.findings.some((finding) => finding.ruleId === "python.oauth-client-credentials-reuse"),
    true,
  );
});

test("OAuth bearer reachability and refresh installation must precede repeated use on the same path", async () => {
  const deadAfterReturn = oauthProgram([
    "    return",
    "    inventory.users.sync(api_session)",
    "    inventory.devices.sync(api_session)",
  ]);
  assert.equal(
    (await reviewSource(deadAfterReturn)).findings.some(
      (finding) => finding.ruleId === "python.oauth-client-credentials-reuse",
    ),
    false,
  );

  const mutuallyExclusive = oauthProgram([
    "    if config.users_enabled:",
    "        inventory.users.sync(api_session)",
    "    else:",
    "        inventory.devices.sync(api_session)",
  ]);
  assert.equal(
    (await reviewSource(mutuallyExclusive)).findings.some(
      (finding) => finding.ruleId === "python.oauth-client-credentials-reuse",
    ),
    false,
  );

  const clean = await readFile(
    fixture("rules/oauth-client-credentials-reuse/clean/tailscale.py"),
    "utf8",
  );
  const refreshCall = `    _attach_oauth_refresh(
        api_session,
        config.tailscale_base_url,
        config.tailscale_oauth_client_id,
        config.tailscale_oauth_client_secret,
    )
`;
  const afterUse = clean.replace(refreshCall, "").replace(
    "    cartography.intel.tailscale.users.sync(api_session, org=config.tailscale_org)",
    "    cartography.intel.tailscale.users.sync(api_session, org=config.tailscale_org)\n" + refreshCall.trimEnd(),
  );
  assert.equal(
    (await reviewSource(afterUse)).findings.some(
      (finding) => finding.ruleId === "python.oauth-client-credentials-reuse",
    ),
    true,
  );

  const otherPath = clean.replace(
    refreshCall,
    `    if config.install_refresh:
${refreshCall.split("\n").filter(Boolean).map((line) => `    ${line}`).join("\n")}\n`,
  );
  assert.equal(
    (await reviewSource(otherPath)).findings.some(
      (finding) => finding.ruleId === "python.oauth-client-credentials-reuse",
    ),
    true,
  );
});

test("OAuth bearer rule ignores comments, docstrings, and unchanged legacy relationships", async () => {
  const fake = `def documentation():
    """
${oauthProgram(["    inventory.users.sync(api_session)", "    inventory.devices.sync(api_session)"])}
    """
    return None
`;
  const fakeOutput = await reviewSource(fake);
  assert.equal(
    fakeOutput.findings.some((finding) => finding.ruleId === "python.oauth-client-credentials-reuse"),
    false,
  );

  const legacy = oauthProgram([
    "    inventory.users.sync(api_session)",
    "    inventory.devices.sync(api_session)",
  ]);
  const root = await gitRepository({ "oauth.py": legacy });
  try {
    await writeFile(join(root, "oauth.py"), legacy.replace(
      'api_session.headers.update({"Authorization": f"Bearer {bearer_token}"})',
      'api_session.headers.update({"Authorization": f"Bearer {bearer_token}"})  # keep bearer current',
    ));
    const commentOnly = await changedReview(root, ["oauth.py"]);
    assert.equal(
      commentOnly.findings.some((finding) => finding.ruleId === "python.oauth-client-credentials-reuse"),
      false,
    );

    await writeFile(join(root, "oauth.py"), `${legacy}\n# unrelated operational documentation\n`);
    const unrelated = await changedReview(root, ["oauth.py"]);
    assert.equal(
      unrelated.findings.some((finding) => finding.ruleId === "python.oauth-client-credentials-reuse"),
      false,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("OAuth bearer relationship anchors the semantic change that activates repeated reuse", async () => {
  const single = oauthProgram(["    inventory.users.sync(api_session)"]);
  const root = await gitRepository({ "oauth.py": single });
  try {
    const current = oauthProgram([
      "    inventory.users.sync(api_session)",
      "    inventory.devices.sync(api_session)",
    ]);
    await writeFile(join(root, "oauth.py"), current);
    const output = await changedReview(root, ["oauth.py"]);
    const observation = output.rawObservations?.find(
      (item) => item.ruleId === "python.oauth-client-credentials-reuse",
    );
    assert.ok(observation);
    assert.equal(observation.location?.snippet, "inventory.devices.sync(api_session)");
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

async function reviewSource(source: string) {
  const root = await mkdtemp(join(tmpdir(), "python-adversary-oauth-"));
  try {
    await writeFile(join(root, "oauth.py"), source);
    return await createApp().run({
      input: { source: { path: root } },
      includeRawObservations: true,
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

function oauthProgram(consumers: string[]): string {
  return `import requests


def _mint_oauth_bearer(
    api_session: requests.Session,
    config,
) -> str:
    response = api_session.post(
        config.token_url,
        data={
            "grant_type": "client_credentials",
            "client_id": config.client_id,
            "client_secret": config.client_secret,
        },
        timeout=30,
    )
    response.raise_for_status()
    return response.json()["access_token"]


def synchronize(config):
    api_session = requests.Session()
    bearer_token = _mint_oauth_bearer(api_session, config)
    api_session.headers.update({"Authorization": f"Bearer {bearer_token}"})
${consumers.join("\n")}
`;
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
