import { readFileSync } from "node:fs";

const source = readFileSync(new URL("../../../../src/main.ts", import.meta.url), "utf8");
const failures = [];

if (/await invoke\("start_ssh",[\s\S]{0,900}?setConnectionStatus\("online"\)/.test(source)) {
  failures.push("start receipt is treated as authenticated");
}
if (/listen<string>\("ssh-output"/.test(source)) {
  failures.push("terminal output has no generation guard");
}
if (/result \|\| "Güncelleme başarıyla tamamlandı\./.test(source)) {
  failures.push("empty update output is displayed as success");
}
if (/resultEl\.dataset\.state = "ok";[\s\S]{0,900}?await loadSecurityEffectiveDurum\(\)/.test(source)) {
  failures.push("security apply is positive before an effective reread");
}
if (/resultEl\.dataset\.state = "ok";[\s\S]{0,700}?await loadSecurityAudit\(\)/.test(source)) {
  failures.push("security rollback is positive before an effective reread");
}

if (failures.length > 0) {
  throw new Error(`baseline invariants violated: ${failures.join("; ")}`);
}
