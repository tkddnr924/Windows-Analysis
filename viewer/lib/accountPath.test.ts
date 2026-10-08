import { test } from 'node:test';
import assert from 'node:assert/strict';
// @ts-expect-error app bundling resolves the extensionless import separately.
import { expandAccountPath } from './accountPath.ts';

test('account paths use target registry root without assuming a drive', () => {
  assert.equal(expandAccountPath('%systemroot%\\system32\\config', 'D:\\test'), 'D:\\test\\system32\\config');
  assert.equal(expandAccountPath('%SystemRoot%\\ServiceProfiles', 'D:\\test\\'), 'D:\\test\\ServiceProfiles');
  assert.equal(expandAccountPath('%SystemRoot%\\ServiceProfiles', ''), '%SystemRoot%\\ServiceProfiles');
  assert.equal(expandAccountPath('E:\\Users\\alice', 'D:\\test'), 'E:\\Users\\alice');
});
