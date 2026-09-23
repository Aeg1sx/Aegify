import process from "node:process";
import { parseArgs } from "node:util";
import { log, error } from "node:console";
import { createEncryptedBackup, databasePathFromUrl, enableRecoveredUser, listRecoveryAccounts, restoreEncryptedBackup, verifyEncryptedBackup } from "../src/lib/backup.ts";

async function main() {
  const { positionals, values } = parseArgs({ allowPositionals: true, options: {
    output: { type: "string" }, archive: { type: "string" }, email: { type: "string" }, help: { type: "boolean" },
  } });
  if (values.help) {
    log(`Aegify operator recovery (local SQLite only)
  node scripts/recovery.mjs backup --output /private/directory/backup.aegify
  node scripts/recovery.mjs verify --archive /private/directory/backup.aegify
  node scripts/recovery.mjs restore --archive /private/directory/backup.aegify --output /private/directory/restored.db
  node scripts/recovery.mjs accounts
  node scripts/recovery.mjs enable-user --email reviewed@example.test

Backup/verify/restore require AEGIFY_BACKUP_KEY (64 hex characters) and the original
ENCRYPTION_SECRET. Backup/accounts/enable-user use DATABASE_URL. Restore always
creates a new database and disables all accounts, old sessions, CI credentials and
unfinished jobs. Review access before enabling individual admitted accounts.
Local accounts also require a new AEGIFY_RECOVERY_PASSWORD during enable-user.
No command replaces a running database or promotes it into an installation.`);
    return;
  }
  if (positionals.length !== 1) throw new Error("Choose one recovery operation; see --help.");
  const required = (value, name) => { if (!value) throw new Error(`Provide --${name}.`); return value; };
  const keys = { backupKey: process.env.AEGIFY_BACKUP_KEY || "", encryptionSecret: process.env.ENCRYPTION_SECRET || "" };
  const started = Date.now();
  let receipt;
  switch (positionals[0]) {
    case "backup":
      receipt = { status: "backup_created", manifest: await createEncryptedBackup({ ...keys, databasePath: databasePathFromUrl(process.env.DATABASE_URL), outputPath: required(values.output, "output") }) };
      break;
    case "verify":
      receipt = { status: "backup_verified", manifest: await verifyEncryptedBackup({ ...keys, archivePath: required(values.archive, "archive") }) };
      break;
    case "restore":
      receipt = { status: "restored_candidate", ...await restoreEncryptedBackup({ ...keys, archivePath: required(values.archive, "archive"), outputPath: required(values.output, "output") }), access: "disabled_until_operator_review" };
      break;
    case "accounts": {
      const accounts = await listRecoveryAccounts(databasePathFromUrl(process.env.DATABASE_URL));
      receipt = { status: "recovery_accounts", accounts: accounts.slice(0, 1000), truncated: accounts.length > 1000 };
      break;
    }
    case "enable-user":
      receipt = { status: "account_enabled", account: await enableRecoveredUser({ databasePath: databasePathFromUrl(process.env.DATABASE_URL), email: required(values.email, "email"), password: process.env.AEGIFY_RECOVERY_PASSWORD, environment: process.env }) };
      break;
    default: throw new Error("Unknown recovery operation; see --help.");
  }
  log(JSON.stringify({ ...receipt, durationMs: Date.now() - started }));
}

try { await main(); }
catch (failure) { error(failure instanceof Error ? failure.message : "Recovery failed."); process.exitCode = 1; }
