import { execFile } from "node:child_process";
import { readdir } from "node:fs/promises";
import { join, sep } from "node:path";
import { promisify } from "node:util";
import { observationFor } from "./rules.js";
import { spec } from "./spec.js";
const SKIPPED = new Set([".adversary", ".git", ".hg", ".next", ".svn", "coverage", "dist", "node_modules", "target", "vendor"]);
const MAX_FILES = 5000;
const execute = promisify(execFile);
export async function analyzeRepository(ctx) {
    // Full tree for existence/context checks; content uses CLI/SDK review scope.
    const allPaths = await walk(ctx.repoPath);
    const scoped = await ctx.loadInScopeSources({
        include: (path) => !path.split("/").some((segment) => SKIPPED.has(segment)) &&
            spec.files.some((glob) => matchesGlob(path, glob)),
        limit: MAX_FILES,
    });
    const wholeTarget = ctx.change === null || ctx.change.scanMode === "all";
    const sources = [];
    for (const file of scoped) {
        const change = wholeTarget || file.status === "repository"
            ? { changedLines: new Set(), status: "repository" }
            : await changedSource(ctx, file.path);
        sources.push({
            path: file.path,
            source: file.content,
            changedLines: change.changedLines,
            status: change.status,
        });
    }
    ctx.summary.files_scanned = sources.length;
    const detections = spec.rules.flatMap((rule) => evaluate(rule, sources, allPaths));
    detections.sort((a, b) => a.rule.id.localeCompare(b.rule.id) || a.file.localeCompare(b.file) || a.line - b.line || a.label.localeCompare(b.label));
    for (const detection of detections)
        ctx.observe(observationFor(detection));
    if (sources.length > 0 && detections.length === 0) {
        ctx.review.positive({
            key: `${spec.id}.reviewed`,
            summary: `Reviewed ${sources.length} ${spec.displayName} configuration file${sources.length === 1 ? "" : "s"} without finding a material issue.`,
            evidence: sources.slice(0, 5).map((file) => ({ file: file.path, line: 1 })),
        });
    }
}
function evaluate(rule, sources, allPaths) {
    const match = rule.match;
    if (match.kind === "missing-file") {
        const triggers = allPaths.filter((path) => match.triggerFiles.some((glob) => matchesGlob(path, glob))).sort();
        const required = allPaths.some((path) => match.requiredFiles.some((glob) => matchesGlob(path, glob)));
        if (triggers.length === 0 || required)
            return [];
        return [{ rule, file: triggers[0] ?? ".", line: 1, snippet: triggers[0] ?? "", label: rule.title, data: { triggerFiles: triggers.slice(0, 10), requiredFiles: match.requiredFiles } }];
    }
    if (match.kind === "default-empty-destructive-sync") {
        return sources
            .filter((file) => match.files.some((glob) => matchesGlob(file.path, glob)))
            .flatMap((file) => findDefaultEmptyDestructiveSync(rule, file));
    }
    const matchingSources = sources.filter((file) => match.files.some((glob) => matchesGlob(file.path, glob)) &&
        !(match.kind === "content" && match.excludeFiles?.some((glob) => matchesGlob(file.path, glob))));
    if (match.kind === "missing-content") {
        return matchingSources.flatMap((file) => {
            if (!test(file.source, match.trigger) || test(file.source, match.required))
                return [];
            const location = locateEligible(file, match.trigger);
            if (location === undefined)
                return [];
            return [{ rule, file: file.path, ...location, label: rule.title, data: { requiredPattern: match.required.pattern } }];
        });
    }
    return matchingSources.flatMap((file) => {
        if (!match.requires.every((pattern) => test(file.source, pattern)) ||
            match.excludes?.some((pattern) => test(file.source, pattern)))
            return [];
        const location = locateEligible(file, match.pattern, match.anchors);
        if (location === undefined)
            return [];
        return [{ rule, file: file.path, ...location, label: rule.title, data: { matchedPattern: match.pattern.pattern } }];
    });
}
function findDefaultEmptyDestructiveSync(rule, file) {
    const detections = [];
    for (const block of findFunctionBlocks(file.source)) {
        const defaults = findEmptyCollectionDefaults(block.body, block.start);
        for (const candidate of defaults) {
            const flow = destructiveSyncFlow(block.body, candidate, block.start);
            if (flow === undefined)
                continue;
            const semanticLines = [candidate.index, flow.seenIndex, flow.cleanupIndex]
                .map((index) => file.source.slice(0, index).split(/\r?\n/).length);
            const line = file.status === "modified"
                ? semanticLines.find((candidateLine) => file.changedLines.has(candidateLine))
                : semanticLines[0];
            if (line === undefined)
                continue;
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
function findFunctionBlocks(source) {
    const blocks = [];
    const definition = /^(?<indent>[ \t]*)(?:async\s+)?def\s+[A-Za-z_]\w*\s*\([^\n]*\)\s*(?:->\s*[^:]+)?\s*:\s*(?:#.*)?$/gm;
    for (const match of source.matchAll(definition)) {
        if (match.index === undefined)
            continue;
        const indent = match.groups?.indent?.length ?? 0;
        const bodyStart = source.indexOf("\n", match.index) + 1;
        if (bodyStart <= 0)
            continue;
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
        blocks.push({ body: source.slice(bodyStart, end), start: bodyStart });
    }
    return blocks;
}
function findEmptyCollectionDefaults(body, offset) {
    const defaults = [];
    const patterns = [
        /^[ \t]*([A-Za-z_]\w*)\s*=\s*[A-Za-z_]\w*\.get\(\s*["']([A-Za-z_]\w*)["']\s*,\s*(?:\[\s*\]|\(\s*\))\s*\)/gm,
        /^[ \t]*([A-Za-z_]\w*)\s*=\s*getattr\(\s*[A-Za-z_]\w*\s*,\s*["']([A-Za-z_]\w*)["']\s*,\s*(?:\[\s*\]|\(\s*\))\s*\)/gm,
    ];
    for (const pattern of patterns) {
        for (const match of body.matchAll(pattern)) {
            if (match.index === undefined || match[1] === undefined || match[2] === undefined)
                continue;
            defaults.push({ collection: match[1], items: match[2], index: offset + match.index, text: match[0] });
        }
    }
    return defaults.sort((left, right) => left.index - right.index);
}
function destructiveSyncFlow(body, candidate, offset) {
    const relative = candidate.index - offset;
    const after = body.slice(relative + candidate.text.length);
    const variable = escapeRegExp(candidate.collection);
    const seenAssignment = after.match(new RegExp(`\\b([A-Za-z_]\\w*)\\s*=\\s*(?:\\{|set\\s*\\()[\\s\\S]{0,240}?\\bfor\\s+[A-Za-z_]\\w*\\s+in\\s+${variable}\\b`));
    if (seenAssignment === null || seenAssignment[1] === undefined || seenAssignment.index === undefined)
        return undefined;
    const seen = seenAssignment[1];
    const cleanupTarget = escapeRegExp(seen);
    const cleanup = new RegExp(`(?:\\bfor\\s+[A-Za-z_]\\w*\\s+in[\\s\\S]{0,300}?\\bif\\s+[A-Za-z_]\\w*[^\\n]*\\bnot\\s+in\\s+${cleanupTarget}\\b[\\s\\S]{0,240}?\\.(?:delete(?:_item|_many)?|remove|unlink)\\s*\\(|\\.(?:delete(?:_item|_many)?|remove|unlink)\\s*\\([^\\n]{0,160}\\bnot\\s+in\\s+${cleanupTarget}\\b)`, "i");
    const cleanupMatch = cleanup.exec(after);
    if (cleanupMatch?.index === undefined)
        return undefined;
    const method = /\.(?:delete(?:_item|_many)?|remove|unlink)\s*\(/i.exec(cleanupMatch[0]);
    if (method?.index === undefined)
        return undefined;
    const afterOffset = candidate.index + candidate.text.length;
    return {
        seenIndex: afterOffset + seenAssignment.index,
        cleanupIndex: afterOffset + cleanupMatch.index + method.index,
    };
}
function escapeRegExp(value) {
    return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
async function changedSource(ctx, path) {
    const base = ctx.change?.baseRef;
    if (base === undefined || !(await existsAtRevision(ctx.repoPath, base, path))) {
        return { changedLines: new Set(), status: "added" };
    }
    const args = ["diff", "--unified=0", base];
    const head = ctx.change?.headRef;
    if (head !== undefined && !ctx.change?.worktree)
        args.push(head);
    args.push("--", path);
    const patch = await gitOutput(ctx.repoPath, args);
    return { changedLines: changedLineNumbers(patch), status: "modified" };
}
async function existsAtRevision(repoPath, revision, path) {
    try {
        await execute("git", ["-C", repoPath, "cat-file", "-e", `${revision}:${path}`], {
            maxBuffer: 1024 * 1024,
        });
        return true;
    }
    catch {
        return false;
    }
}
async function gitOutput(repoPath, args) {
    const result = await execute("git", ["-C", repoPath, ...args], {
        encoding: "utf8",
        maxBuffer: 8 * 1024 * 1024,
    });
    return result.stdout;
}
function changedLineNumbers(patch) {
    const lines = new Set();
    for (const match of patch.matchAll(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/gm)) {
        const start = Number(match[1]);
        const count = match[2] === undefined ? 1 : Number(match[2]);
        for (let line = start; line < start + count; line += 1)
            lines.add(line);
    }
    return lines;
}
function test(source, expression) {
    return new RegExp(expression.pattern, expression.flags).test(source);
}
function locateEligible(file, expression, anchors) {
    const flags = expression.flags.includes("g") ? expression.flags : `${expression.flags}g`;
    const re = new RegExp(expression.pattern, flags);
    const sourceLines = file.source.split(/\r?\n/);
    let match;
    while ((match = re.exec(file.source)) !== null) {
        if (match.index === undefined)
            break;
        if (match[0] === "") {
            re.lastIndex += 1;
            continue;
        }
        const line = file.status === "modified" && anchors !== undefined
            ? eligibleSemanticAnchor(file, match[0], match.index, anchors)
            : file.source.slice(0, match.index).split(/\r?\n/).length;
        if (line === undefined)
            continue;
        if (file.status === "modified" && !file.changedLines.has(line))
            continue;
        return { line, snippet: sourceLines[line - 1]?.trim().slice(0, 240) ?? "" };
    }
    return undefined;
}
function eligibleSemanticAnchor(file, matchedSource, offset, anchors) {
    for (const anchor of anchors) {
        const flags = anchor.flags.includes("g") ? anchor.flags : `${anchor.flags}g`;
        for (const match of matchedSource.matchAll(new RegExp(anchor.pattern, flags))) {
            if (match.index === undefined)
                continue;
            const line = file.source.slice(0, offset + match.index).split(/\r?\n/).length;
            if (file.changedLines.has(line))
                return line;
        }
    }
    return undefined;
}
async function walk(root) {
    const files = [];
    async function visit(relative) {
        if (files.length >= MAX_FILES)
            return;
        const entries = await readdir(join(root, relative), { withFileTypes: true });
        entries.sort((a, b) => a.name.localeCompare(b.name));
        for (const entry of entries) {
            if (files.length >= MAX_FILES)
                return;
            const path = relative ? join(relative, entry.name) : entry.name;
            if (entry.isDirectory() && !SKIPPED.has(entry.name))
                await visit(path);
            else if (entry.isFile())
                files.push(path.split(sep).join("/"));
        }
    }
    await visit("");
    return files.sort();
}
function matchesGlob(path, glob) {
    let pattern = "^";
    for (let index = 0; index < glob.length; index += 1) {
        const character = glob[index];
        if (character === "*" && glob[index + 1] === "*") {
            if (glob[index + 2] === "/") {
                pattern += "(?:.*/)?";
                index += 2;
            }
            else {
                pattern += ".*";
                index += 1;
            }
        }
        else if (character === "*")
            pattern += "[^/]*";
        else if (character === "?")
            pattern += "[^/]";
        else
            pattern += character !== undefined && "^$+?.()|{}[]".includes(character) ? "\\" + character : character;
    }
    return new RegExp(`${pattern}$`, "i").test(path);
}
