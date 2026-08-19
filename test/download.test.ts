import assert from "node:assert/strict";
import { test } from "node:test";
import { planResume } from "../src/download.js";

test("a fresh file is written from the start", () => {
  assert.deepEqual(planResume(0, 100), { skip: false, start: 0, append: false });
});

test("a part file resumes from its byte offset", () => {
  assert.deepEqual(planResume(40, 100), { skip: false, start: 40, append: true });
});

test("a full file is skipped", () => {
  assert.deepEqual(planResume(100, 100), { skip: true, start: 100, append: false });
});

test("a local file bigger than the remote is written again from the start", () => {
  assert.deepEqual(planResume(120, 100), { skip: false, start: 0, append: false });
});

test("an empty file is done and skipped", () => {
  assert.deepEqual(planResume(0, 0), { skip: true, start: 0, append: false });
});
