import { execFile } from "node:child_process";
import { readFile, readdir } from "node:fs/promises";
import { join, sep } from "node:path";
import { promisify } from "node:util";
import { type RuleContext } from "@adversarylabs/sdk";
import { observationFor } from "./rules.js";
import { spec, type MatchExpression, type RuleSpec } from "./spec.js";

const SKIPPED = new Set([".adversary", ".git", ".hg", ".next", ".svn", "coverage", "dist", "node_modules", "target", "vendor"]);
const MAX_FILES = 5000;
const execute = promisify(execFile);

interface SourceFile {
  path: string;
  source: string;
  previousSource?: string;
  changedLines: Set<number>;
  status: "added" | "modified" | "repository";
}
interface Detection { rule: RuleSpec; file: string; line: number; snippet: string; label: string; data: Record<string, unknown> }

export async function analyzeRepository(ctx: RuleContext): Promise<void> {
  // Full tree for existence/context checks; content uses CLI/SDK review scope.
  const allPaths = await walk(ctx.repoPath);
  const scoped = await ctx.loadInScopeSources({
    include: (path) =>
      !path.split("/").some((segment) => SKIPPED.has(segment)) &&
      spec.files.some((glob) => matchesGlob(path, glob)),
    limit: MAX_FILES,
  });
  const wholeTarget = ctx.change === null || ctx.change.scanMode === "all";
  const sources: SourceFile[] = [];
  for (const file of scoped) {
    const change = wholeTarget || file.status === "repository"
      ? { changedLines: new Set<number>(), status: "repository" as const }
      : await changedSource(ctx, file.path);
    sources.push({
      path: file.path,
      source: file.content,
      changedLines: change.changedLines,
      status: change.status,
      ...(change.previousSource === undefined ? {} : { previousSource: change.previousSource }),
    });
  }
  ctx.summary.files_scanned = sources.length;

  const detections = spec.rules.flatMap((rule) => evaluate(rule, sources, allPaths));
  detections.sort((a, b) => a.rule.id.localeCompare(b.rule.id) || a.file.localeCompare(b.file) || a.line - b.line || a.label.localeCompare(b.label));
  for (const detection of detections) ctx.observe(observationFor(detection));

  if (sources.length > 0 && detections.length === 0) {
    ctx.review.positive({
      key: `${spec.id}.reviewed`,
      summary: `Reviewed ${sources.length} ${spec.displayName} configuration file${sources.length === 1 ? "" : "s"} without finding a material issue.`,
      evidence: sources.slice(0, 5).map((file) => ({ file: file.path, line: 1 })),
    });
  }
}

function evaluate(rule: RuleSpec, sources: SourceFile[], allPaths: string[]): Detection[] {
  const match = rule.match;
  if (match.kind === "missing-file") {
    const triggers = allPaths.filter((path) => match.triggerFiles.some((glob) => matchesGlob(path, glob))).sort();
    const required = allPaths.some((path) => match.requiredFiles.some((glob) => matchesGlob(path, glob)));
    if (triggers.length === 0 || required) return [];
    return [{ rule, file: triggers[0] ?? ".", line: 1, snippet: triggers[0] ?? "", label: rule.title, data: { triggerFiles: triggers.slice(0, 10), requiredFiles: match.requiredFiles } }];
  }

  if (match.kind === "default-empty-destructive-sync") {
    return sources
      .filter((file) => match.files.some((glob) => matchesGlob(file.path, glob)))
      .flatMap((file) => findDefaultEmptyDestructiveSync(rule, file));
  }

  if (match.kind === "oauth-client-credentials-reuse") {
    return sources
      .filter((file) => match.files.some((glob) => matchesGlob(file.path, glob)))
      .flatMap((file) => findOAuthClientCredentialsReuse(rule, file));
  }

  const matchingSources = sources.filter(
    (file) =>
      match.files.some((glob) => matchesGlob(file.path, glob)) &&
      !(match.kind === "content" && match.excludeFiles?.some((glob) => matchesGlob(file.path, glob))),
  );
  if (match.kind === "missing-content") {
    return matchingSources.flatMap((file) => {
      if (!test(file.source, match.trigger) || test(file.source, match.required)) return [];
      const location = locateEligible(file, match.trigger);
      if (location === undefined) return [];
      return [{ rule, file: file.path, ...location, label: rule.title, data: { requiredPattern: match.required.pattern } }];
    });
  }

  return matchingSources.flatMap((file) => {
    if (
      !match.requires.every((pattern) => test(file.source, pattern)) ||
      match.excludes?.some((pattern) => test(file.source, pattern))
    ) return [];
    const location = locateEligible(file, match.pattern, match.anchors);
    if (location === undefined) return [];
    return [{ rule, file: file.path, ...location, label: rule.title, data: { matchedPattern: match.pattern.pattern } }];
  });
}

interface FunctionBlock { body: string; start: number; end: number; headerStart: number; name: string; indent: number }
interface EmptyDefault { collection: string; items: string; index: number; text: string }
interface DestructiveSyncFlow { seenIndex: number; cleanupIndex: number }

function findDefaultEmptyDestructiveSync(rule: RuleSpec, file: SourceFile): Detection[] {
  const detections: Detection[] = [];
  for (const block of findFunctionBlocks(file.source)) {
    const defaults = findEmptyCollectionDefaults(block.body, block.start);
    for (const candidate of defaults) {
      const flow = destructiveSyncFlow(block.body, candidate, block.start);
      if (flow === undefined) continue;
      const semanticLines = [candidate.index, flow.seenIndex, flow.cleanupIndex]
        .map((index) => file.source.slice(0, index).split(/\r?\n/).length);
      const line = file.status === "modified"
        ? semanticLines.find((candidateLine) => file.changedLines.has(candidateLine))
        : semanticLines[0];
      if (line === undefined) continue;
      detections.push({
        rule,
        file: file.path,
        line,
        snippet: file.source.split(/\r?\n/)[line - 1]?.trim().slice(0, 240) ?? "",
        label: `${candidate.collection} defaults a missing response collection to empty before destructive cleanup`,
        data: { collectionVariable: candidate.collection, responseField: candidate.items },
      });
    }
  }
  return detections;
}

function findFunctionBlocks(source: string): FunctionBlock[] {
  const blocks: FunctionBlock[] = [];
  const definition = /^(?<indent>[ \t]*)(?:async\s+)?def\s+(?<name>[A-Za-z_]\w*)\s*\(/gm;
  for (const match of source.matchAll(definition)) {
    if (match.index === undefined) continue;
    const indent = match.groups?.indent?.length ?? 0;
    const open = source.indexOf("(", match.index);
    const parameters = balancedPythonCall(source, open);
    if (parameters === undefined) continue;
    const headerEnd = source.indexOf("\n", parameters.endIndex);
    const headerTail = source.slice(parameters.endIndex, headerEnd < 0 ? source.length : headerEnd);
    if (!/^\s*(?:->\s*[^:]+)?\s*:\s*$/.test(headerTail)) continue;
    const bodyStart = (headerEnd < 0 ? source.length : headerEnd) + 1;
    if (bodyStart <= 0) continue;
    let end = source.length;
    let cursor = bodyStart;
    while (cursor < source.length) {
      const nextNewline = source.indexOf("\n", cursor);
      const lineEnd = nextNewline < 0 ? source.length : nextNewline;
      const line = source.slice(cursor, lineEnd);
      if (line.trim() !== "" && (line.match(/^[ \t]*/)?.[0].length ?? 0) <= indent) {
        end = cursor;
        break;
      }
      cursor = nextNewline < 0 ? source.length : nextNewline + 1;
    }
    blocks.push({
      body: source.slice(bodyStart, end),
      start: bodyStart,
      end,
      headerStart: match.index,
      name: match.groups?.name ?? "",
      indent,
    });
  }
  return blocks;
}

interface OAuthMintHelper {
  fn: FunctionBlock;
  sessionParameter: string;
  sessionPosition: number;
  responseVariable: string;
  acquisitionIndex: number;
  tokenIndex: number;
}

interface OAuthConsumer {
  index: number;
  path: string;
}

function findOAuthClientCredentialsReuse(rule: RuleSpec, file: SourceFile): Detection[] {
  if (/(?:^|\/)(?:tests?|examples?|docs?|fixtures?|vendor|generated)(?:\/|$)|(?:^|\/)test_[^/]*\.py$|_test\.py$/i.test(file.path)) {
    return [];
  }
  const executable = executablePythonSource(file.source);
  const functions = findFunctionBlocks(executable);
  const requestsAliases = requestModuleAliases(executable);
  if (requestsAliases.size === 0) return [];
  const helpers = functions.flatMap((fn) => oauthMintHelpers(fn, executable, requestsAliases));
  if (helpers.length === 0) return [];

  const detections: Detection[] = [];
  for (const fn of functions) {
    for (const session of requestSessions(fn, executable, requestsAliases)) {
      const token = tokenFromMintHelper(fn, session.name, helpers, executable, functions, session.index);
      if (token === undefined) continue;
      const attachment = bearerAttachment(fn, session.name, token.name, executable, functions, token.index);
      if (attachment === undefined || isStaticallyDeadPythonLine(fn, token.index, executable) ||
        isStaticallyDeadPythonLine(fn, attachment.index, executable) || isInsidePythonLoop(fn, token.index, executable) ||
        isInsidePythonLoop(fn, attachment.index, executable) ||
        pythonLineIndent(executable, token.index) !== pythonFunctionBodyIndent(fn, executable) ||
        pythonLineIndent(executable, attachment.index) !== pythonFunctionBodyIndent(fn, executable)) continue;
      const consumers = oauthConsumers(fn, session.name, executable, functions, attachment.endIndex);
      if (!provesRepeatedOrMultistageUse(fn, consumers, executable)) continue;
      const firstConsumer = consumers[0]?.index ?? fn.end;
      if (hasBoundedUnauthorizedRefresh(
        fn, session.name, token.helper, executable, functions, attachment.index, attachment.endIndex, firstConsumer,
      ) || hasExpiryAwareRefresh(
        fn, session.name, token.name, token.helper, executable, functions,
        attachment.endIndex, firstConsumer,
      )) continue;

      const semanticIndices = [
        token.helper.acquisitionIndex,
        token.index,
        attachment.index,
        ...consumers.slice(0, 2).map((consumer) => consumer.index),
      ];
      const semanticLines = semanticIndices.map((index) => lineAt(file.source, index));
      const line = file.status === "modified"
        ? semanticLines.find((candidate) => eligibleOAuthSemanticLine(file, candidate))
        : semanticLines[2];
      if (line === undefined) continue;
      detections.push({
        rule,
        file: file.path,
        line,
        snippet: file.source.split(/\r?\n/)[line - 1]?.trim().slice(0, 240) ?? "",
        label: `${session.name} reuses one client-credentials bearer across ${consumers.length} request stages without refresh`,
        data: {
          sessionVariable: session.name,
          tokenVariable: token.name,
          mintHelper: token.helper.fn.name,
          acquisitionLine: lineAt(file.source, token.helper.acquisitionIndex),
          bearerAttachmentLine: lineAt(file.source, attachment.index),
          consumerLines: consumers.slice(0, 5).map((consumer) => lineAt(file.source, consumer.index)),
        },
      });
    }
  }
  return detections;
}

function requestModuleAliases(source: string): Set<string> {
  const aliases = new Set<string>();
  for (const match of source.matchAll(/^[ \t]*import\s+requests(?:\s+as\s+([A-Za-z_]\w*))?\s*$/gm)) {
    const alias = match[1] ?? "requests";
    if (!new RegExp(`^[ \\t]*${escapeRegExp(alias)}\\s*=`, "m").test(source)) aliases.add(alias);
  }
  return aliases;
}

function oauthMintHelpers(fn: FunctionBlock, source: string, requestAliases: Set<string>): OAuthMintHelper[] {
  if (fn.indent !== 0) return [];
  const helpers: OAuthMintHelper[] = [];
  const parameters = functionParameters(fn, source);
  const assignment = /^[ \t]*([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\.post\s*\(/gm;
  for (const match of fn.body.matchAll(assignment)) {
    if (match.index === undefined || match[1] === undefined || match[2] === undefined) continue;
    const absolute = fn.start + match.index;
    if (!samePythonOwner(functionAt(functionBlocksContaining(source, absolute), absolute), fn)) continue;
    const sessionPosition = parameters.indexOf(match[2]);
    if (sessionPosition < 0 || !parameterIsRequestsSession(fn, match[2], source, requestAliases)) continue;
    const open = source.indexOf("(", absolute + match[0].lastIndexOf(".post"));
    const call = balancedPythonCall(source, open);
    if (call === undefined ||
      !/["']grant_type["']\s*:\s*["']client_credentials["']/.test(call.text) ||
      !/["']client_id["']\s*:/.test(call.text) ||
      !/["']client_secret["']\s*:/.test(call.text)) continue;
    const response = escapeRegExp(match[1]);
    const after = source.slice(call.endIndex, fn.end);
    const returned = new RegExp(`^[ \\t]*return\\s+${response}\\.json\\s*\\(\\s*\\)\\s*\\[\\s*["']access_token["']\\s*\\]`, "m").exec(after);
    if (returned?.index === undefined) continue;
    helpers.push({
      fn,
      sessionParameter: match[2],
      sessionPosition,
      responseVariable: match[1],
      acquisitionIndex: absolute,
      tokenIndex: call.endIndex + returned.index,
    });
  }
  return helpers;
}

function requestSessions(
  fn: FunctionBlock,
  source: string,
  requestAliases: Set<string>,
): Array<{ name: string; index: number }> {
  const sessions: Array<{ name: string; index: number }> = [];
  const pattern = /^[ \t]*([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\.(?:session|Session)\s*\(\s*\)/gm;
  for (const match of fn.body.matchAll(pattern)) {
    if (match.index === undefined || match[1] === undefined || match[2] === undefined ||
      !requestAliases.has(match[2])) continue;
    const index = fn.start + match.index;
    if (samePythonOwner(owningPythonFunction(source, index), fn) &&
      pythonLineIndent(source, index) === pythonFunctionBodyIndent(fn, source) &&
      !isStaticallyDeadPythonLine(fn, index, source)) sessions.push({ name: match[1], index });
  }
  return sessions;
}

function tokenFromMintHelper(
  fn: FunctionBlock,
  session: string,
  helpers: OAuthMintHelper[],
  source: string,
  functions: FunctionBlock[],
  afterIndex: number,
): { name: string; index: number; helper: OAuthMintHelper } | undefined {
  const pattern = /^[ \t]*([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*\(/gm;
  for (const match of fn.body.matchAll(pattern)) {
    if (match.index === undefined || match[1] === undefined || match[2] === undefined) continue;
    const index = fn.start + match.index;
    if (index <= afterIndex || !samePythonOwner(functionAt(functions, index), fn)) continue;
    const matchingHelpers = helpers.filter((candidate) => candidate.fn.name === match[2]);
    if (matchingHelpers.length !== 1) continue;
    const helper = matchingHelpers[0]!;
    const open = source.indexOf("(", index + match[0].lastIndexOf(match[2]) + match[2].length);
    const call = balancedPythonCall(source, open);
    if (call === undefined) continue;
    const args = topLevelPythonArguments(call.text.slice(1, -1));
    if (args[helper.sessionPosition]?.trim() !== session ||
      bindingReassignedBetween(fn, session, afterIndex, index, source, functions)) continue;
    return { name: match[1], index, helper };
  }
  return undefined;
}

function bearerAttachment(
  fn: FunctionBlock,
  session: string,
  token: string,
  source: string,
  functions: FunctionBlock[],
  afterIndex: number,
): { index: number; endIndex: number } | undefined {
  const escapedSession = escapeRegExp(session);
  const escapedToken = escapeRegExp(token);
  const patterns = [
    new RegExp(`^[ \\t]*${escapedSession}\\.headers\\.update\\s*\\(`, "gm"),
    new RegExp(`^[ \\t]*${escapedSession}\\.headers\\s*\\[\\s*["']Authorization["']\\s*\\]\\s*=`, "gm"),
  ];
  for (const pattern of patterns) {
    for (const match of fn.body.matchAll(pattern)) {
      if (match.index === undefined) continue;
      const index = fn.start + match.index;
      if (index <= afterIndex || !samePythonOwner(functionAt(functions, index), fn)) continue;
      if (bindingReassignedBetween(fn, session, afterIndex, index, source, functions) ||
        bindingReassignedBetween(fn, token, afterIndex, index, source, functions)) continue;
      const lineEnd = source.indexOf("\n", index);
      const boundedEnd = match[0].includes("update")
        ? balancedPythonCall(source, source.indexOf("(", index))?.endIndex
        : lineEnd < 0 ? fn.end : lineEnd;
      if (boundedEnd === undefined) continue;
      const text = source.slice(index, boundedEnd);
      if (/["']Authorization["']/.test(text) && /Bearer/i.test(text) && new RegExp(`\\b${escapedToken}\\b`).test(text)) {
        return { index, endIndex: boundedEnd };
      }
    }
  }
  return undefined;
}

function oauthConsumers(
  fn: FunctionBlock,
  session: string,
  source: string,
  functions: FunctionBlock[],
  afterIndex: number,
): OAuthConsumer[] {
  const consumers: OAuthConsumer[] = [];
  const callStart = /([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*\(/g;
  for (const match of fn.body.matchAll(callStart)) {
    if (match.index === undefined || match[1] === undefined) continue;
    const index = fn.start + match.index;
    if (index <= afterIndex || !samePythonOwner(functionAt(functions, index), fn)) continue;
    const open = source.indexOf("(", index + match[1].length);
    const call = balancedPythonCall(source, open);
    if (call === undefined) continue;
    const terminal = match[1].split(".").at(-1) ?? "";
    if (!/^(?:sync|fetch|load|list|get|post|put|patch|delete|request|collect|scan|ingest)$/i.test(terminal)) continue;
    const directSessionRequest = match[1].startsWith(`${session}.`) &&
      /^(?:get|post|put|patch|delete|request)$/i.test(terminal);
    if (!directSessionRequest &&
      !topLevelPythonArguments(call.text.slice(1, -1)).some((arg) => arg.trim() === session)) continue;
    if (isStaticallyDeadPythonLine(fn, index, source) ||
      bindingReassignedBetween(fn, session, afterIndex, index, source, functions) ||
      bearerRemovedBetween(session, afterIndex, index, source)) continue;
    consumers.push({ index, path: match[1] });
  }
  return consumers.sort((left, right) => left.index - right.index);
}

function provesRepeatedOrMultistageUse(fn: FunctionBlock, consumers: OAuthConsumer[], source: string): boolean {
  if (consumers.some((consumer) => isInsidePythonLoop(fn, consumer.index, source))) return true;
  const bodyIndent = pythonFunctionBodyIndent(fn, source);
  const sequential = consumers.filter((consumer) => pythonLineIndent(source, consumer.index) === bodyIndent);
  return sequential.length >= 2;
}

function hasBoundedUnauthorizedRefresh(
  fn: FunctionBlock,
  session: string,
  mint: OAuthMintHelper,
  source: string,
  functions: FunctionBlock[],
  attachmentIndex: number,
  afterIndex: number,
  beforeIndex: number,
): boolean {
  const helperCall = /^[ \t]*([A-Za-z_]\w*)\s*\(/gm;
  for (const match of fn.body.matchAll(helperCall)) {
    if (match.index === undefined || match[1] === undefined) continue;
    const index = fn.start + match.index;
    if (index <= afterIndex || index >= beforeIndex || !samePythonOwner(functionAt(functions, index), fn) ||
      !samePythonControlPath(fn, attachmentIndex, index, source)) continue;
    const matchingRefreshes = functions.filter((candidate) => candidate.name === match[1] && candidate.indent === 0);
    if (matchingRefreshes.length !== 1) continue;
    const refresh = matchingRefreshes[0]!;
    const open = source.indexOf("(", index + match[1].length);
    const call = balancedPythonCall(source, open);
    const args = call === undefined ? [] : topLevelPythonArguments(call.text.slice(1, -1));
    const sessionPosition = args.findIndex((arg) => arg.trim() === session);
    if (sessionPosition < 0 || isStaticallyDeadPythonLine(fn, index, source)) continue;
    const refreshSession = functionParameters(refresh, source)[sessionPosition];
    if (refreshSession === undefined || !parameterIsRequestsSession(refresh, refreshSession, source, requestModuleAliases(source))) {
      continue;
    }
    const body = refresh.body;
    const remints = new RegExp(`\\b${escapeRegExp(mint.fn.name)}\\s*\\(`).test(body);
    const bounded = /\b(?:retried|retry|attempt)[A-Za-z_]*\b/i.test(body) &&
      /(?:\.add\s*\(|\bin\s+[A-Za-z_]\w*|>=?\s*1|["'](?:X-)?[A-Za-z-]*Retry)/i.test(body);
    const excludesTokenEndpoint = /if\s+[^:\n]*\.request\.url\s*==\s*[A-Za-z_]\w*[^:\n]*:\s*\n[ \t]+return\b/.test(body) ||
      /if\s+[^:\n]*\.request\.url\s*!=\s*[A-Za-z_]\w*[^:\n]*:/.test(body);
    const installsResponseHook = new RegExp(
      `\\b${escapeRegExp(refreshSession)}\\.hooks\\s*\\[\\s*["']response["']\\s*\\][^\\n]*\\.(?:append|insert)\\s*\\(`,
    ).test(body);
    if (/\.status_code\b/.test(body) && /\b401\b/.test(body) &&
      excludesTokenEndpoint && /(?:token_url|oauth\/token)/i.test(body) && installsResponseHook &&
      remints && bounded && /\.request\.copy\s*\(\s*\)/.test(body) &&
      /\.headers\s*\[\s*["']Authorization["']\s*\]/.test(body) && /Bearer/i.test(body) &&
      new RegExp(`\\b${escapeRegExp(refreshSession)}\\.send\\s*\\(`).test(body)) return true;
  }
  return false;
}

function hasExpiryAwareRefresh(
  fn: FunctionBlock,
  session: string,
  token: string,
  mint: OAuthMintHelper,
  source: string,
  functions: FunctionBlock[],
  afterIndex: number,
  beforeIndex: number,
): boolean {
  if (!/["']expires_in["']/.test(mint.fn.body)) return false;
  const clock = String.raw`(?:time\.(?:time|monotonic)\s*\(\)|datetime\.(?:now|utcnow)\s*\(\))`;
  const deadlines: Array<{ name: string; index: number }> = [];
  const deadlinePattern = /^[ \t]*([A-Za-z_]\w*)\s*=\s*([^\n]+)$/gm;
  for (const match of fn.body.matchAll(deadlinePattern)) {
    if (match.index === undefined || match[1] === undefined || match[2] === undefined) continue;
    const index = fn.start + match.index;
    const expression = match[2];
    if (index <= afterIndex || index >= beforeIndex || pythonLineIndent(source, index) !== pythonFunctionBodyIndent(fn, source) ||
      !new RegExp(clock).test(expression) || !/(?:expires?_in|token_ttl)\b/i.test(expression) ||
      !samePythonOwner(functionAt(functions, index), fn) || isStaticallyDeadPythonLine(fn, index, source)) continue;
    deadlines.push({ name: match[1], index });
  }
  const refreshCall = new RegExp(`\\b${escapeRegExp(token)}\\s*=\\s*${escapeRegExp(mint.fn.name)}\\s*\\(`, "g");
  for (const match of fn.body.matchAll(refreshCall)) {
    if (match.index === undefined) continue;
    const index = fn.start + match.index;
    if (index <= afterIndex || index >= beforeIndex || !samePythonOwner(functionAt(functions, index), fn) ||
      !isInsidePythonConditional(fn, index, source)) continue;
    const guardingIf = enclosingPythonIfHeader(fn, index, source);
    if (guardingIf === undefined) continue;
    const deadline = deadlines.find((candidate) => {
      if (candidate.index >= guardingIf.index ||
        bindingReassignedBetween(fn, candidate.name, candidate.index, guardingIf.index, source, functions)) return false;
      const escaped = escapeRegExp(candidate.name);
      return new RegExp(`(?:${clock})\\s*(?:>=|>)\\s*${escaped}\\b|\\b${escaped}\\s*(?:<=|<)\\s*(?:${clock})`).test(
        guardingIf.text,
      );
    });
    if (deadline === undefined) continue;
    const open = source.indexOf("(", index + match[0].lastIndexOf(mint.fn.name) + mint.fn.name.length);
    const call = balancedPythonCall(source, open);
    const args = call === undefined ? [] : topLevelPythonArguments(call.text.slice(1, -1));
    if (args[mint.sessionPosition]?.trim() !== session) continue;
    const refreshedAttachment = bearerAttachment(fn, session, token, source, functions, call?.endIndex ?? index);
    if (refreshedAttachment !== undefined && refreshedAttachment.index < guardingIf.endIndex) {
      return true;
    }
  }
  return false;
}

function enclosingPythonIfHeader(
  fn: FunctionBlock,
  index: number,
  source: string,
): { index: number; endIndex: number; text: string } | undefined {
  const before = source.slice(fn.start, index).split(/\r?\n/);
  const childIndent = pythonLineIndent(source, index);
  for (let line = before.length - 1; line >= 0; line -= 1) {
    const text = before[line] ?? "";
    const indent = pythonTextIndent(text);
    if (text.trim() === "" || indent >= childIndent || !/^if\b[^:]*:\s*$/.test(text.trim())) continue;
    const headerIndex = fn.start + before.slice(0, line).reduce((total, value) => total + value.length + 1, 0);
    let endIndex = fn.end;
    const tail = source.slice(source.indexOf("\n", headerIndex) + 1, fn.end).split(/\r?\n/);
    let cursor = source.indexOf("\n", headerIndex) + 1;
    for (const candidate of tail) {
      if (candidate.trim() !== "" && pythonTextIndent(candidate) <= indent) { endIndex = cursor; break; }
      cursor += candidate.length + 1;
    }
    if (index < endIndex) return { index: headerIndex, endIndex, text: text.trim() };
  }
  return undefined;
}

function functionParameters(fn: FunctionBlock, source: string): string[] {
  const header = source.slice(fn.headerStart, fn.start);
  const open = header.indexOf("(");
  const close = header.lastIndexOf(")");
  if (open < 0 || close <= open) return [];
  return topLevelPythonArguments(header.slice(open + 1, close)).map((parameter) =>
    parameter.trim().replace(/^\*{0,2}/, "").split(/\s*[:=]\s*/, 1)[0] ?? ""
  );
}

function parameterIsRequestsSession(
  fn: FunctionBlock,
  parameter: string,
  source: string,
  aliases: Set<string>,
): boolean {
  const header = source.slice(fn.headerStart, fn.start);
  return [...aliases].some((alias) =>
    new RegExp(`\\b${escapeRegExp(parameter)}\\s*:\\s*${escapeRegExp(alias)}\\.Session\\b`).test(header)
  );
}

function executablePythonSource(source: string): string {
  const output = source.split("");
  let quote: "'" | '"' | "'''" | '\"\"\"' | null = null;
  let index = 0;
  while (index < source.length) {
    if (quote === "'''" || quote === '\"\"\"') {
      if (source.startsWith(quote, index)) {
        for (let offset = 0; offset < 3; offset += 1) output[index + offset] = " ";
        index += 3;
        quote = null;
      } else {
        if (source[index] !== "\n" && source[index] !== "\r") output[index] = " ";
        index += 1;
      }
      continue;
    }
    if (quote === "'" || quote === '"') {
      if (source[index] === "\\") index += 2;
      else if (source[index] === quote) { quote = null; index += 1; }
      else index += 1;
      continue;
    }
    if (source.startsWith("'''", index) || source.startsWith('\"\"\"', index)) {
      quote = source.slice(index, index + 3) as "'''" | '\"\"\"';
      for (let offset = 0; offset < 3; offset += 1) output[index + offset] = " ";
      index += 3;
    } else if (source[index] === "'" || source[index] === '"') {
      quote = source[index] as "'" | '"';
      index += 1;
    } else if (source[index] === "#") {
      while (index < source.length && source[index] !== "\n") { output[index] = " "; index += 1; }
    } else index += 1;
  }
  return output.join("");
}

function balancedPythonCall(source: string, openIndex: number): { text: string; endIndex: number } | undefined {
  if (openIndex < 0 || source[openIndex] !== "(") return undefined;
  let depth = 0;
  let quote: "'" | '"' | null = null;
  for (let index = openIndex; index < source.length; index += 1) {
    const character = source[index];
    if (quote !== null) {
      if (character === "\\") index += 1;
      else if (character === quote) quote = null;
      continue;
    }
    if (character === "'" || character === '"') quote = character;
    else if (character === "(") depth += 1;
    else if (character === ")") {
      depth -= 1;
      if (depth === 0) return { text: source.slice(openIndex, index + 1), endIndex: index + 1 };
    }
  }
  return undefined;
}

function topLevelPythonArguments(source: string): string[] {
  const parts: string[] = [];
  let start = 0;
  let depth = 0;
  let quote: "'" | '"' | null = null;
  for (let index = 0; index < source.length; index += 1) {
    const character = source[index];
    if (quote !== null) {
      if (character === "\\") index += 1;
      else if (character === quote) quote = null;
      continue;
    }
    if (character === "'" || character === '"') quote = character;
    else if ("([{ ".trim().includes(character ?? "")) depth += 1;
    else if (")] }".replaceAll(" ", "").includes(character ?? "")) depth -= 1;
    else if (character === "," && depth === 0) { parts.push(source.slice(start, index)); start = index + 1; }
  }
  parts.push(source.slice(start));
  return parts;
}

function functionBlocksContaining(source: string, index: number): FunctionBlock[] {
  return findFunctionBlocks(source).filter((fn) => fn.headerStart <= index && index < fn.end);
}

function functionAt(functions: FunctionBlock[], index: number): FunctionBlock | undefined {
  return functions
    .filter((fn) => fn.headerStart <= index && index < fn.end)
    .sort((left, right) => right.indent - left.indent)[0];
}

function owningPythonFunction(source: string, index: number): FunctionBlock | undefined {
  return functionAt(findFunctionBlocks(source), index);
}

function samePythonOwner(left: FunctionBlock | undefined, right: FunctionBlock): boolean {
  return left !== undefined && left.headerStart === right.headerStart && left.end === right.end;
}

function isInsidePythonLoop(fn: FunctionBlock, index: number, source: string): boolean {
  return isInsideIndentedControl(fn, index, source, /^(?:async\s+)?(?:for|while)\b/);
}

function isInsidePythonConditional(fn: FunctionBlock, index: number, source: string): boolean {
  return isInsideIndentedControl(fn, index, source, /^if\b/);
}

function isStaticallyDeadPythonLine(fn: FunctionBlock, index: number, source: string): boolean {
  const bodyIndent = pythonFunctionBodyIndent(fn, source);
  const preceding = source.slice(fn.start, index).split(/\r?\n/);
  if (preceding.some((line) =>
    pythonTextIndent(line) === bodyIndent && /^(?:return\b|raise\b)/.test(line.trim())
  )) return true;
  const before = source.slice(fn.start, index).split(/\r?\n/);
  const currentLine = source.slice(source.lastIndexOf("\n", index - 1) + 1, source.indexOf("\n", index) < 0 ? source.length : source.indexOf("\n", index));
  let containingIndent = currentLine.match(/^[ \t]*/)?.[0].length ?? 0;
  for (let line = before.length - 1; line >= 0; line -= 1) {
    const text = before[line] ?? "";
    if (text.trim() === "") continue;
    const indent = text.match(/^[ \t]*/)?.[0].length ?? 0;
    if (indent >= containingIndent || !text.trimEnd().endsWith(":")) continue;
    if (/^(?:if\s+(?:False|0|None)|while\s+False)\s*:/.test(text.trim())) return true;
    containingIndent = indent;
    if (containingIndent <= fn.indent) break;
  }
  return false;
}

function pythonFunctionBodyIndent(fn: FunctionBlock, source: string): number {
  return source.slice(fn.start, fn.end).split(/\r?\n/)
    .filter((line) => line.trim() !== "")
    .map(pythonTextIndent)
    .filter((indent) => indent > fn.indent)
    .sort((left, right) => left - right)[0] ?? fn.indent + 4;
}

function pythonLineIndent(source: string, index: number): number {
  const start = source.lastIndexOf("\n", index - 1) + 1;
  const end = source.indexOf("\n", index);
  return pythonTextIndent(source.slice(start, end < 0 ? source.length : end));
}

function pythonTextIndent(line: string): number {
  return line.match(/^[ \t]*/)?.[0].length ?? 0;
}

function samePythonControlPath(fn: FunctionBlock, left: number, right: number, source: string): boolean {
  const path = (index: number): string[] => {
    const before = source.slice(fn.start, index).split(/\r?\n/);
    let containingIndent = pythonLineIndent(source, index);
    const controls: string[] = [];
    for (let line = before.length - 1; line >= 0; line -= 1) {
      const text = before[line] ?? "";
      const indent = pythonTextIndent(text);
      if (text.trim() === "" || indent >= containingIndent || !text.trimEnd().endsWith(":")) continue;
      if (/^(?:if|elif|else|for|while|try|except|finally|with)\b/.test(text.trim())) {
        controls.unshift(`${indent}:${text.trim()}`);
      }
      containingIndent = indent;
      if (containingIndent <= fn.indent) break;
    }
    return controls;
  };
  const leftPath = path(left);
  const rightPath = path(right);
  return leftPath.length === rightPath.length && leftPath.every((item, index) => item === rightPath[index]);
}

function eligibleOAuthSemanticLine(file: SourceFile, line: number): boolean {
  if (!file.changedLines.has(line)) return false;
  const current = normalizedPythonLine(file.source, line);
  if (current === "" || file.previousSource === undefined) return current !== "";
  return !file.previousSource.split(/\r?\n/).some((_, index) =>
    normalizedPythonLine(file.previousSource ?? "", index + 1) === current
  );
}

function normalizedPythonLine(source: string, line: number): string {
  const text = source.split(/\r?\n/)[line - 1] ?? "";
  return executablePythonSource(text).trim().replace(/\s+/g, " ");
}

function bindingReassignedBetween(
  fn: FunctionBlock,
  name: string,
  startIndex: number,
  endIndex: number,
  source: string,
  functions: FunctionBlock[],
): boolean {
  const escaped = escapeRegExp(name);
  const pattern = new RegExp(`^[ \\t]*(?:${escaped}\\s*(?::[^=\\n]+)?=|(?:for|with)\\b[^\\n]*\\b(?:as\\s+)?${escaped}\\b)`, "gm");
  for (const match of fn.body.matchAll(pattern)) {
    if (match.index === undefined) continue;
    const index = fn.start + match.index;
    if (index > startIndex && index < endIndex && samePythonOwner(functionAt(functions, index), fn) &&
      !isStaticallyDeadPythonLine(fn, index, source)) return true;
  }
  return false;
}

function bearerRemovedBetween(session: string, startIndex: number, endIndex: number, source: string): boolean {
  const between = source.slice(startIndex, endIndex);
  const escaped = escapeRegExp(session);
  return new RegExp(`\\b${escaped}\\.headers\\s*\\[\\s*["']Authorization["']\\s*\\]\\s*=\\s*(?!f?["']Bearer\\b)`, "i").test(between) ||
    new RegExp(`\\b${escaped}\\.headers\\.(?:clear|pop)\\s*\\(`).test(between);
}

function isInsideIndentedControl(fn: FunctionBlock, index: number, source: string, control: RegExp): boolean {
  const before = source.slice(fn.start, index).split(/\r?\n/);
  const currentLine = source.slice(source.lastIndexOf("\n", index - 1) + 1, source.indexOf("\n", index) < 0 ? source.length : source.indexOf("\n", index));
  let containingIndent = currentLine.match(/^[ \t]*/)?.[0].length ?? 0;
  for (let line = before.length - 1; line >= 0; line -= 1) {
    const text = before[line] ?? "";
    if (text.trim() === "") continue;
    const indent = text.match(/^[ \t]*/)?.[0].length ?? 0;
    if (indent >= containingIndent || !text.trimEnd().endsWith(":")) continue;
    if (control.test(text.trim())) return true;
    containingIndent = indent;
    if (containingIndent <= fn.indent) break;
  }
  return false;
}

function lineAt(source: string, index: number): number {
  return source.slice(0, index).split(/\r?\n/).length;
}

function findEmptyCollectionDefaults(body: string, offset: number): EmptyDefault[] {
  const defaults: EmptyDefault[] = [];
  const patterns = [
    /^[ \t]*([A-Za-z_]\w*)\s*=\s*[A-Za-z_]\w*\.get\(\s*["']([A-Za-z_]\w*)["']\s*,\s*(?:\[\s*\]|\(\s*\))\s*\)/gm,
    /^[ \t]*([A-Za-z_]\w*)\s*=\s*getattr\(\s*[A-Za-z_]\w*\s*,\s*["']([A-Za-z_]\w*)["']\s*,\s*(?:\[\s*\]|\(\s*\))\s*\)/gm,
  ];
  for (const pattern of patterns) {
    for (const match of body.matchAll(pattern)) {
      if (match.index === undefined || match[1] === undefined || match[2] === undefined) continue;
      defaults.push({ collection: match[1], items: match[2], index: offset + match.index, text: match[0] });
    }
  }
  return defaults.sort((left, right) => left.index - right.index);
}

function destructiveSyncFlow(body: string, candidate: EmptyDefault, offset: number): DestructiveSyncFlow | undefined {
  const relative = candidate.index - offset;
  const after = body.slice(relative + candidate.text.length);
  const variable = escapeRegExp(candidate.collection);
  const seenAssignment = after.match(
    new RegExp(`\\b([A-Za-z_]\\w*)\\s*=\\s*(?:\\{|set\\s*\\()[\\s\\S]{0,240}?\\bfor\\s+[A-Za-z_]\\w*\\s+in\\s+${variable}\\b`),
  );
  if (seenAssignment === null || seenAssignment[1] === undefined || seenAssignment.index === undefined) return undefined;
  const seen = seenAssignment[1];
  const cleanupTarget = escapeRegExp(seen);
  const cleanup = new RegExp(
    `(?:\\bfor\\s+[A-Za-z_]\\w*\\s+in[\\s\\S]{0,300}?\\bif\\s+[A-Za-z_]\\w*[^\\n]*\\bnot\\s+in\\s+${cleanupTarget}\\b[\\s\\S]{0,240}?\\.(?:delete(?:_item|_many)?|remove|unlink)\\s*\\(|\\.(?:delete(?:_item|_many)?|remove|unlink)\\s*\\([^\\n]{0,160}\\bnot\\s+in\\s+${cleanupTarget}\\b)`,
    "i",
  );
  const cleanupMatch = cleanup.exec(after);
  if (cleanupMatch?.index === undefined) return undefined;
  const method = /\.(?:delete(?:_item|_many)?|remove|unlink)\s*\(/i.exec(cleanupMatch[0]);
  if (method?.index === undefined) return undefined;
  const afterOffset = candidate.index + candidate.text.length;
  return {
    seenIndex: afterOffset + seenAssignment.index,
    cleanupIndex: afterOffset + cleanupMatch.index + method.index,
  };
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

async function changedSource(
  ctx: RuleContext,
  path: string,
): Promise<Pick<SourceFile, "changedLines" | "status" | "previousSource">> {
  const base = ctx.change?.baseRef;
  if (base === undefined || !(await existsAtRevision(ctx.repoPath, base, path))) {
    return { changedLines: new Set<number>(), status: "added" };
  }

  const args = ["diff", "--unified=0", base];
  const head = ctx.change?.headRef;
  if (head !== undefined && !ctx.change?.worktree) args.push(head);
  args.push("--", path);
  const [patch, previousSource] = await Promise.all([
    gitOutput(ctx.repoPath, args),
    gitOutput(ctx.repoPath, ["show", `${base}:${path}`]),
  ]);
  return { changedLines: changedLineNumbers(patch), status: "modified", previousSource };
}

async function existsAtRevision(repoPath: string, revision: string, path: string): Promise<boolean> {
  try {
    await execute("git", ["-C", repoPath, "cat-file", "-e", `${revision}:${path}`], {
      maxBuffer: 1024 * 1024,
    });
    return true;
  } catch {
    return false;
  }
}

async function gitOutput(repoPath: string, args: string[]): Promise<string> {
  const result = await execute("git", ["-C", repoPath, ...args], {
    encoding: "utf8",
    maxBuffer: 8 * 1024 * 1024,
  });
  return result.stdout;
}

function changedLineNumbers(patch: string): Set<number> {
  const lines = new Set<number>();
  for (const match of patch.matchAll(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/gm)) {
    const start = Number(match[1]);
    const count = match[2] === undefined ? 1 : Number(match[2]);
    for (let line = start; line < start + count; line += 1) lines.add(line);
  }
  return lines;
}

function test(source: string, expression: MatchExpression): boolean {
  return new RegExp(expression.pattern, expression.flags).test(source);
}

function locateEligible(
  file: SourceFile,
  expression: MatchExpression,
  anchors?: readonly MatchExpression[],
): { line: number; snippet: string } | undefined {
  const flags = expression.flags.includes("g") ? expression.flags : `${expression.flags}g`;
  const re = new RegExp(expression.pattern, flags);
  const sourceLines = file.source.split(/\r?\n/);
  let match: RegExpExecArray | null;

  while ((match = re.exec(file.source)) !== null) {
    if (match.index === undefined) break;
    if (match[0] === "") {
      re.lastIndex += 1;
      continue;
    }
    const line = file.status === "modified" && anchors !== undefined
      ? eligibleSemanticAnchor(file, match[0], match.index, anchors)
      : file.source.slice(0, match.index).split(/\r?\n/).length;
    if (line === undefined) continue;
    if (file.status === "modified" && !file.changedLines.has(line)) continue;
    return { line, snippet: sourceLines[line - 1]?.trim().slice(0, 240) ?? "" };
  }

  return undefined;
}

function eligibleSemanticAnchor(
  file: SourceFile,
  matchedSource: string,
  offset: number,
  anchors: readonly MatchExpression[],
): number | undefined {
  for (const anchor of anchors) {
    const flags = anchor.flags.includes("g") ? anchor.flags : `${anchor.flags}g`;
    for (const match of matchedSource.matchAll(new RegExp(anchor.pattern, flags))) {
      if (match.index === undefined) continue;
      const line = file.source.slice(0, offset + match.index).split(/\r?\n/).length;
      if (file.changedLines.has(line)) return line;
    }
  }
  return undefined;
}

async function walk(root: string): Promise<string[]> {
  const files: string[] = [];
  async function visit(relative: string): Promise<void> {
    if (files.length >= MAX_FILES) return;
    const entries = await readdir(join(root, relative), { withFileTypes: true });
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (files.length >= MAX_FILES) return;
      const path = relative ? join(relative, entry.name) : entry.name;
      if (entry.isDirectory() && !SKIPPED.has(entry.name)) await visit(path);
      else if (entry.isFile()) files.push(path.split(sep).join("/"));
    }
  }
  await visit("");
  return files.sort();
}

function matchesGlob(path: string, glob: string): boolean {
  let pattern = "^";
  for (let index = 0; index < glob.length; index += 1) {
    const character = glob[index];
    if (character === "*" && glob[index + 1] === "*") {
      if (glob[index + 2] === "/") { pattern += "(?:.*/)?"; index += 2; }
      else { pattern += ".*"; index += 1; }
    } else if (character === "*") pattern += "[^/]*";
    else if (character === "?") pattern += "[^/]";
    else pattern += character !== undefined && "^$+?.()|{}[]".includes(character) ? "\\" + character : character;
  }
  return new RegExp(`${pattern}$`, "i").test(path);
}
