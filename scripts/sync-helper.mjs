import { readFile, writeFile } from 'node:fs/promises';

const helperPath = new URL('../helper.sh', import.meta.url);
const installerPath = new URL('../server-setup/install-jarvis-remediation.sh', import.meta.url);
const begin = '\n# JARVIS_HELPER_BEGIN\n';
const end = '\n# JARVIS_HELPER_END\n';
const helper = await readFile(helperPath, 'utf8');
const installer = await readFile(installerPath, 'utf8');
const start = installer.indexOf(begin);
const finish = installer.indexOf(end);

if (start < 0 || finish < 0 || finish <= start) throw new Error('helper embed anchors are missing');

const generated = `${installer.slice(0, start + begin.length)}${helper}${helper.endsWith('\n') ? '' : '\n'}${installer.slice(finish)}`;
if (process.argv[2] === '--check') {
  if (installer !== generated) throw new Error('embedded helper does not equal helper.sh; run node scripts/sync-helper.mjs');
} else if (process.argv.length === 2) {
  await writeFile(installerPath, generated, 'utf8');
} else {
  throw new Error('Usage: node scripts/sync-helper.mjs [--check]');
}
