import assert from 'node:assert/strict';
import { test } from 'node:test';
import { markdownTableCell } from './markdown-table.mjs';

test('a backslash before a pipe stays a backslash and the pipe stays in its cell', () => {
  assert.equal(markdownTableCell('a\\|b'), 'a\\\\\\|b');
  assert.equal(markdownTableCell('C:\\temp\\'), 'C:\\\\temp\\\\');
});

test('pipes are escaped and each line break becomes the separator', () => {
  assert.equal(markdownTableCell('x|y\nz'), 'x\\|y z');
  assert.equal(markdownTableCell('x\r\ny\nz\rw', '<br>'), 'x<br>y<br>z<br>w');
});

test('a trailing backslash stays a backslash before the line break separator', () => {
  assert.equal(markdownTableCell('C:\\tmp\\\nnext', '<br>'), 'C:\\\\tmp\\\\<br>next');
});

test('values that are not strings are written as text', () => {
  assert.equal(markdownTableCell(42), '42');
  assert.equal(markdownTableCell(null), 'null');
});
