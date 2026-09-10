
const assert = require('node:assert/strict');
const { createRequire } = require('node:module');
const path = require('node:path');
async function main() {
 const classic = createRequire(path.resolve('packages/classic/package.json'));
 const modern = createRequire(path.resolve('packages/modern/package.json'));
 for (const [r, version] of [[classic, '18.3.1'], [modern, '19.1.1']]) {
  const react = r('react');
  assert.equal(react.version, version);
  assert.equal(r('react-dom/server').renderToStaticMarkup(react.createElement('p', null, version)), `<p>${version}</p>`);
  assert.equal(r('is-odd')(3), true);
  const fromOdd = createRequire(r.resolve('is-odd'));
  assert.equal(fromOdd('is-number/package.json').version, '7.0.0');
 }
 const result = classic('esbuild').transformSync('const answer: number = 42', {loader: 'ts'});
 assert.ok(result.code.includes('42'));
 const bundle = await modern('rollup').rollup({input: 'virtual', plugins: [{name: 'fixture', resolveId: () => 'virtual', load: () => 'export const answer = 42'}]});
 const output = await bundle.generate({format: 'cjs'});
 assert.ok(output.output[0].code.includes('42'));
 await bundle.close();
 console.log(JSON.stringify({platform:process.platform, architecture:process.arch, node:process.version, react18:true, react19:true, esbuild:true, rollup:true, override:true}));
}
main().catch(error => {console.error(error); process.exitCode = 1});
