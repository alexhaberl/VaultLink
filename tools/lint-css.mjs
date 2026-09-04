#!/usr/bin/env node

import { readFileSync } from "node:fs";

const paths = process.argv.slice(2);
if (paths.length === 0) {
  console.error("usage: node tools/lint-css.mjs <stylesheet> [...]");
  process.exit(64);
}

let failed = false;

function report(path, line, column, message) {
  console.error(`${path}:${line}:${column}: CSS lint: ${message}`);
  failed = true;
}

for (const path of paths) {
  let source;
  try {
    source = readFileSync(path, "utf8");
  } catch (error) {
    console.error(`${path}: CSS lint: ${error.message}`);
    failed = true;
    continue;
  }

  if (source.length === 0) {
    report(path, 1, 1, "stylesheet is empty");
    continue;
  }
  if (source.charCodeAt(0) === 0xfeff) {
    report(path, 1, 1, "UTF-8 byte-order marks are not allowed");
  }

  const stack = [];
  let state = "code";
  let quote = "";
  let line = 1;
  let column = 0;
  let stateLine = 1;
  let stateColumn = 1;

  for (let index = 0; index < source.length; index += 1) {
    const character = source[index];
    const next = source[index + 1] ?? "";
    if (character === "\n") {
      line += 1;
      column = 0;
    } else {
      column += 1;
    }

    if (state === "comment") {
      if (character === "*" && next === "/") {
        index += 1;
        column += 1;
        state = "code";
      }
      continue;
    }

    if (state === "string") {
      if (character === "\\") {
        if (next === "\n") {
          line += 1;
          column = 0;
        } else if (next !== "") {
          column += 1;
        }
        index += 1;
      } else if (character === quote) {
        state = "code";
        quote = "";
      } else if (character === "\n") {
        report(path, stateLine, stateColumn, "unterminated string");
        state = "code";
        quote = "";
      }
      continue;
    }

    if (character === "/" && next === "*") {
      state = "comment";
      stateLine = line;
      stateColumn = column;
      index += 1;
      column += 1;
      continue;
    }
    if (character === '"' || character === "'") {
      state = "string";
      quote = character;
      stateLine = line;
      stateColumn = column;
      continue;
    }

    const codePoint = character.codePointAt(0);
    if (codePoint < 0x20 && character !== "\n" && character !== "\r" && character !== "\t") {
      report(path, line, column, "unexpected control character");
    }

    const opening = "{([";
    const closing = "})]";
    const openingIndex = opening.indexOf(character);
    if (openingIndex !== -1) {
      stack.push({ character, line, column });
      continue;
    }
    const closingIndex = closing.indexOf(character);
    if (closingIndex !== -1) {
      const expected = opening[closingIndex];
      const actual = stack.pop();
      if (!actual || actual.character !== expected) {
        report(path, line, column, `unmatched ${character}`);
      }
    }
  }

  if (state === "comment") {
    report(path, stateLine, stateColumn, "unterminated comment");
  } else if (state === "string") {
    report(path, stateLine, stateColumn, "unterminated string");
  }
  for (const opening of stack.reverse()) {
    report(path, opening.line, opening.column, `unclosed ${opening.character}`);
  }

  source.split(/\r?\n/u).forEach((sourceLine, index) => {
    if (/[ \t]+$/u.test(sourceLine)) {
      report(path, index + 1, sourceLine.length, "trailing whitespace");
    }
    if (/\t/u.test(sourceLine)) {
      report(path, index + 1, sourceLine.indexOf("\t") + 1, "tab indentation is not allowed");
    }
  });

  if (/@import(?:\s|;)/iu.test(source)) {
    report(path, 1, 1, "@import is forbidden for the self-contained asset bundle");
  }
  if (/url\(\s*["']?(?:https?:)?\/\//iu.test(source)) {
    report(path, 1, 1, "remote CSS URLs are forbidden");
  }
}

if (failed) process.exit(1);
