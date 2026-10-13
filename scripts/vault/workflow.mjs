// 7IT Guard Vault: the workflow generator (V1, 2026-10-08; docs/features/backup-vault.md sections 3 and 4).
// Lior's decision 1 of 2026-10-08: no public repository and no reusable workflow. The 7IT Guard plugin (/7it-guard:vault, V4)
// writes two COMPLETE, self-contained workflow files into the customer's own repository, every step visible there:
//   .github/workflows/7it-vault.yml          the nightly backup (database + storage files), encrypted, to the customer's storage
//   .github/workflows/7it-vault-restore.yml  the weekly restore test, and a restore by date in three modes (full, database, files)
// Tool versions are pinned and verified by checksum; the only container image is pinned by digest; no third-party action is used.
// Each file starts with a version header (`# 7IT Guard Vault workflow v1`); the receipt carries the version, so the app can say
// "A newer vault workflow is ready" (an optional one-step update: run the plugin command again). Never required.
//
// Use from code: import { vaultFiles } from './workflow.mjs'; vaultFiles(opts) -> [{ path, text }, { path, text }]
// Use from a shell (the plugin calls this, and Lior can for V0):
//   node scripts/vault/workflow.mjs --recipient age1... --ci age1... [--pg 17] [--files supabase|s3|none] [--remote-path my-bucket/app]
//        [--remote-kind r2|s3|b2|drive|gcs|other] [--tz America/New_York] [--hour 3] [--seed owner/repo] [--out <dir>]
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';

const HERE = dirname(fileURLToPath(import.meta.url));
export const VAULT_WF_VERSION = 1;
export const WF_HEADER = `# 7IT Guard Vault workflow v${VAULT_WF_VERSION}`;
export const BACKUP_PATH = '.github/workflows/7it-vault.yml';
export const RESTORE_PATH = '.github/workflows/7it-vault-restore.yml';
export const RECEIPT_URL = 'https://7it.co.il/api/guard?a=vault';

// Pinned tools (checked 2026-10-08). age: the release tarball's sha256 (computed from the download; age publishes no sums file).
// rclone: matches the official SHA256SUMS. The PostgreSQL apt signing key (apt.postgresql.org) by sha256. The restore test's
// database image by digest (Docker Hub, the multi-arch index of <major>-bookworm).
export const PINS = {
  age: { version: 'v1.3.2', url: 'https://github.com/FiloSottile/age/releases/download/v1.3.2/age-v1.3.2-linux-amd64.tar.gz', sha256: 'cbe24006683f8eb669266162894b9a522a1af52f2665fbc63a4bb032ed26ac10' },
  rclone: { version: 'v1.75.1', url: 'https://downloads.rclone.org/v1.75.1/rclone-v1.75.1-linux-amd64.zip', sha256: '982b5aa772841168f8e380f139e9e787b2a105403e32b94da8676a0e1c0a13ab' },
  pgdgKey: { url: 'https://www.postgresql.org/media/keys/ACCC4CF8.asc', sha256: '0144068502a1eddd2a0280ede10ef607d1ec592ce819940991203941564e8e76' },
  postgres: {
    15: 'postgres@sha256:d4a8e1f88f475ee3e0137fa89d21ebc59f6c6ab16bf369ee92907607cc3455ae',
    16: 'postgres@sha256:0ea6700a3b4f0ae6ce746519073558aed4d88a79d8d07622a9a644946c7319c4',
    17: 'postgres@sha256:3645570cccdfa447589da9f57dd740faa29b30938e861289a5574b6ca6b03826',
    18: 'postgres@sha256:afc7e2d441324c0388fa80c3d24f733b4194a4eb7f47dd8ee2b08eb1a24a647c',
  },
  runner: 'ubuntu-24.04',
};
export const KEEP_DEFAULT = { daily: 14, weekly: 8, monthly: 12 };
const AGE_RE = /^age1[02-9ac-hj-np-z]{58}$/;
const PATH_RE = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$/;
const REMOTE_KINDS = ['r2', 's3', 'b2', 'drive', 'gcs', 'other'];

// The schedule: a quiet hour in the owner's zone (default 03:00), turned into UTC for today's offset (GitHub's cron is UTC;
// a daylight saving change moves the run by one hour, which is fine for a nightly copy). The minute is odd and never on a
// multiple of five, nor near the top of the hour (GitHub delays runs at busy minutes), picked from a seed (the repository name) so customers spread out.
export function tzOffsetMin(tz, at = new Date()) {
  try {
    const p = Object.fromEntries(new Intl.DateTimeFormat('en-US', { timeZone: tz, hourCycle: 'h23', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }).formatToParts(at).map((x) => [x.type, x.value]));
    const local = Date.UTC(+p.year, +p.month - 1, +p.day, +p.hour, +p.minute);
    return Math.round((local - Math.floor(at.getTime() / 60000) * 60000) / 60000);
  } catch { return 0; }
}
export function scheduleFor({ tz = 'UTC', hour = 3, seed = '', at = new Date() } = {}) {
  const mins = [...Array(60).keys()].filter((m) => m >= 7 && m <= 53 && m % 2 === 1 && m % 5 !== 0);
  const n = parseInt(createHash('sha256').update('7it-vault|' + seed).digest('hex').slice(0, 8), 16);
  const minute = mins[n % mins.length], off = tzOffsetMin(tz, at);
  const utcMin = (((hour * 60 + minute - off) % 1440) + 1440) % 1440;
  const h = Math.floor(utcMin / 60), m = utcMin % 60;
  // The weekly restore test: Sunday, two hours after the backup's hour (UTC day may shift; fine).
  const rh = (h + 2) % 24, rdow = h + 2 >= 24 ? 1 : 0;
  return { cron: `${m} ${h} * * *`, restoreCron: `${m} ${rh} * * ${rdow}`, local: `${String(hour).padStart(2, '0')}:${String(minute).padStart(2, '0')}`, tz, hourUtc: h, minuteUtc: m, restoreDow: rdow };
}

// Every value that reaches the YAML is validated here; the rest of the file is fixed text. Throws on a bad value.
export function vaultOptions(o = {}) {
  const recipient = String(o.recipient || ''), ci = String(o.ci || '');
  if (!AGE_RE.test(recipient)) throw new Error('recipient must be an age public key (age1...)');
  if (!AGE_RE.test(ci)) throw new Error('ci must be an age public key (age1...) for the restore-test key');
  if (recipient === ci) throw new Error('the restore-test key must differ from your own key');
  const extra = (o.extra || []).map(String);
  for (const r of extra) if (!AGE_RE.test(r)) throw new Error('every extra recipient must be an age public key');
  const pg = Number(o.pg ?? 17);
  if (!PINS.postgres[pg]) throw new Error('pg must be one of ' + Object.keys(PINS.postgres).join(', '));
  const files = o.files ?? 'none';
  if (!['none', 'supabase', 's3'].includes(files)) throw new Error('files must be none, supabase or s3');
  const remotePath = String(o.remotePath || '7it-vault');
  if (!PATH_RE.test(remotePath) || remotePath.includes('..')) throw new Error('remote path: letters, digits, . _ / - only');
  const remoteKind = o.remoteKind ?? 'other';
  if (!REMOTE_KINDS.includes(remoteKind)) throw new Error('remote kind must be one of ' + REMOTE_KINDS.join(', '));
  const keep = { ...KEEP_DEFAULT, ...(o.keep || {}) };
  for (const [k, max] of [['daily', 400], ['weekly', 260], ['monthly', 120]]) if (!Number.isInteger(keep[k]) || keep[k] < (k === 'daily' ? 1 : 0) || keep[k] > max) throw new Error(`keep.${k} out of range`);
  const hour = Number(o.hour ?? 3);
  if (!Number.isInteger(hour) || hour < 0 || hour > 23) throw new Error('hour must be 0 to 23');
  const tz = String(o.tz || 'UTC');
  try { new Intl.DateTimeFormat('en-US', { timeZone: tz }); } catch { throw new Error('unknown time zone'); }
  const sample = Number(o.sample ?? 20);
  if (!Number.isInteger(sample) || sample < 1 || sample > 1000) throw new Error('sample must be 1 to 1000');
  return { recipient, ci, extra, pg, files, remotePath, remoteKind, keep, hour, tz, sample, seed: String(o.seed || ''), at: o.at instanceof Date ? o.at : new Date() };
}

// LF only: a checkout with CRLF line endings (Windows) must never put a carriage return into the customer's workflow file.
export const runnerSource = () => readFileSync(join(HERE, 'runner.mjs'), 'utf8').replace(/\r\n/g, '\n');
const ind = (text, n) => text.split('\n').map((l) => (l ? ' '.repeat(n) + l : l)).join('\n');
const COUNTS_SQL = "select count(*), coalesce(sum(greatest(c.reltuples, 0)), 0)::bigint from pg_class c join pg_namespace n on n.oid = c.relnamespace where c.relkind in ('r', 'p') and n.nspname not in ('pg_catalog', 'information_schema') and n.nspname not like 'pg_toast%' and n.nspname not like 'pg_temp%'";

function header(title, o, s) {
  return `${WF_HEADER}
# ${title}
# Written by the 7IT Guard plugin (/7it-guard:vault). Every step that touches your data is in this file.
# Your data is encrypted with your own key and stored in storage you own. 7IT receives only a short receipt
# (times, sizes, checksums, counts, which dates can be restored, ok or not). Never the data, the passwords,
# the storage keys or any private key.
# Tools are pinned and checked by checksum. To update this file, run the 7IT Guard vault setup again.
# Schedule: ${s.local} in ${o.tz} (cron is in UTC).
`;
}
const prepareStep = (o, s) => `      - name: Prepare
        id: prepare
        env:
          VAULT_RCLONE_CONFIG: \${{ secrets.VAULT_RCLONE_CONFIG }}
        run: |
          umask 077
          T="$RUNNER_TEMP/vault"
          mkdir -p "$T"
          echo "T=$T" >> "$GITHUB_ENV"
          echo "RCLONE_CONFIG=$T/rclone.conf" >> "$GITHUB_ENV"
          echo "VAULT_STARTED=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$GITHUB_ENV"
          if [ -z "$VAULT_RCLONE_CONFIG" ]; then echo "The secret VAULT_RCLONE_CONFIG is missing."; exit 1; fi
          printf '%s\\n' "$VAULT_RCLONE_CONFIG" > "$T/rclone.conf"
          cat > "$T/vault.mjs" <<'VAULT_RUNNER_JS'
${ind(runnerSource().replace(/\n+$/, ''), 10)}
          VAULT_RUNNER_JS
`;
const toolsStep = (o) => `      - name: Install pinned tools
        id: tools
        run: |
          cd "$T"
          curl -fsSL -o age.tgz ${PINS.age.url}
          echo "${PINS.age.sha256}  age.tgz" | sha256sum -c --quiet
          tar xzf age.tgz && sudo install -m 0755 age/age age/age-keygen /usr/local/bin/
          curl -fsSL -o rclone.zip ${PINS.rclone.url}
          echo "${PINS.rclone.sha256}  rclone.zip" | sha256sum -c --quiet
          unzip -q rclone.zip && sudo install -m 0755 rclone-*-linux-amd64/rclone /usr/local/bin/
          curl -fsSL -o pgdg.asc ${PINS.pgdgKey.url}
          echo "${PINS.pgdgKey.sha256}  pgdg.asc" | sha256sum -c --quiet
          sudo install -m 0644 pgdg.asc /usr/share/keyrings/pgdg.asc
          echo "deb [signed-by=/usr/share/keyrings/pgdg.asc] https://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" | sudo tee /etc/apt/sources.list.d/pgdg.list > /dev/null
          sudo apt-get -qq update -o Dir::Etc::sourcelist=sources.list.d/pgdg.list -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0
          sudo apt-get -qq install -y --no-install-recommends postgresql-client-${o.pg} > /dev/null
          # The runner image ships an older client first on the PATH: this version's tools come first from here on.
          echo "/usr/lib/postgresql/${o.pg}/bin" >> "$GITHUB_PATH"
          export PATH="/usr/lib/postgresql/${o.pg}/bin:$PATH"
          rm -rf age age.tgz rclone.zip rclone-*-linux-amd64 pgdg.asc
          age --version && rclone version | head -1 && pg_dump --version
`;
const commonEnv = (o) => `      VAULT_WF: '${VAULT_WF_VERSION}'
      VAULT_PG: '${o.pg}'
      VAULT_REMOTE: 'vault:${o.remotePath}'
      VAULT_REMOTE_KIND: '${o.remoteKind}'
      VAULT_FILES_SRC: '${o.files === 'none' ? '' : 'src-files:'}'
      VAULT_KEEP_D: '${o.keep.daily}'
      VAULT_KEEP_W: '${o.keep.weekly}'
      VAULT_KEEP_M: '${o.keep.monthly}'
      VAULT_RECEIPT_URL: '${RECEIPT_URL}'`;

export function backupWorkflow(input) {
  const o = vaultOptions(input), s = scheduleFor(o);
  const recips = [o.recipient, o.ci, ...o.extra];
  return `${header('Nightly backup: your database and your stored files, encrypted, to your own storage.', o, s)}
name: 7IT Guard Vault
on:
  schedule:
    - cron: '${s.cron}'
  workflow_dispatch: {}
permissions:
  contents: read
  id-token: write
concurrency:
  group: 7it-vault
  cancel-in-progress: false
jobs:
  backup:
    runs-on: ${PINS.runner}
    timeout-minutes: 120
    env:
${commonEnv(o)}
      VAULT_KIND: backup
      VAULT_RECIPIENTS: '${recips.join(' ')}'
    defaults:
      run:
        shell: bash
    steps:
${prepareStep(o, s)}${toolsStep(o)}      - name: Copy the database
        id: dump
        env:
          VAULT_DATABASE_URL: \${{ secrets.VAULT_DATABASE_URL }}
        run: |
          set -euo pipefail
          if [ -z "$VAULT_DATABASE_URL" ]; then echo "config" > "$T/err"; echo "The secret VAULT_DATABASE_URL is missing."; exit 1; fi
          if ! pg_dump --format=custom --compress=6 --no-password --file "$T/db.dump" --dbname "$VAULT_DATABASE_URL" 2> "$T/dump.err"; then
            node "$T/vault.mjs" classify "$T/dump.err" > "$T/err"
            echo "The database copy did not finish ($(cat "$T/err"))."
            exit 1
          fi
          VAULT_COUNTS="$(psql "$VAULT_DATABASE_URL" -X -At -F '|' -c "${COUNTS_SQL}")" node "$T/vault.mjs" db-stats
          rm -f "$T/dump.err"
      - name: Encrypt the database copy
        id: encrypt
        run: |
          set -euo pipefail
          age $(printf -- '-r %s ' $VAULT_RECIPIENTS) -o "$T/db.dump.age" "$T/db.dump"
          shred -u "$T/db.dump"
      - name: Store the database copy
        id: upload
        run: |
          set -euo pipefail
          D="$(date -u +%Y-%m-%d)"
          rclone copyto "$T/db.dump.age" "$VAULT_REMOTE/db/$D/db.dump.age" --retries 3 -q
          rclone copyto "$T/db.json" "$VAULT_REMOTE/db/$D/db.json" --retries 3 -q
      - name: Copy the stored files
        id: files
        if: \${{ env.VAULT_FILES_SRC != '' }}
        run: node "$T/vault.mjs" files-backup
      - name: Keep the restorable dates
        id: prune
        run: node "$T/vault.mjs" prune
      - name: Send the receipt to 7IT Guard
        if: \${{ always() }}
        env:
          VAULT_STEPS: prepare=\${{ steps.prepare.outcome }} tools=\${{ steps.tools.outcome }} dump=\${{ steps.dump.outcome }} encrypt=\${{ steps.encrypt.outcome }} upload=\${{ steps.upload.outcome }} files=\${{ steps.files.outcome }} prune=\${{ steps.prune.outcome }}
        run: node "$T/vault.mjs" receipt
      - name: Clean up
        if: \${{ always() }}
        run: |
          [ -n "\${T:-}" ] || exit 0
          [ -f "$T/db.dump" ] && shred -u "$T/db.dump"
          rm -rf "$T"
`;
}

export function restoreWorkflow(input) {
  const o = vaultOptions(input), s = scheduleFor(o);
  return `${header('Restore: a weekly test that your backups really open, and a restore of any kept date, in three modes.', o, s)}# A restore never writes to your live database or your live storage. It writes to a NEW database
# (secret VAULT_RESTORE_DATABASE_URL) and a NEW storage place (the remote "restore-files" in VAULT_RCLONE_CONFIG).
# Check it there, then switch your app over when you are ready.
name: 7IT Guard Vault restore
on:
  schedule:
    - cron: '${s.restoreCron}'
  workflow_dispatch:
    inputs:
      date:
        description: 'Backup date to restore (YYYY-MM-DD), or latest'
        required: true
        default: latest
        type: string
      mode:
        description: 'What to restore'
        required: true
        default: full
        type: choice
        options: [full, database, files]
      target:
        description: 'new = into a new database and storage place; check = only test that it opens'
        required: true
        default: new
        type: choice
        options: [new, check]
permissions:
  contents: read
  id-token: write
concurrency:
  group: 7it-vault
  cancel-in-progress: false
jobs:
  restore:
    runs-on: ${PINS.runner}
    timeout-minutes: 180
    services:
      scratch:
        image: ${PINS.postgres[o.pg]}
        env:
          POSTGRES_PASSWORD: vault-scratch
        ports: ['5432:5432']
        options: >-
          --health-cmd "pg_isready -U postgres" --health-interval 5s --health-timeout 5s --health-retries 20
    env:
${commonEnv(o)}
      VAULT_KIND: restore
      VAULT_FILES_ON: '${o.files === 'none' ? '0' : '1'}'
      VAULT_SAMPLE: '${o.sample}'
      VAULT_WANT: \${{ inputs.date || 'latest' }}
      VAULT_MODE: \${{ inputs.mode || 'full' }}
      VAULT_TARGET: \${{ inputs.target || 'check' }}
    defaults:
      run:
        shell: bash
    steps:
${prepareStep(o, s)}${toolsStep(o)}      - name: Restore-test key
        id: key
        env:
          VAULT_AGE_KEY: \${{ secrets.VAULT_AGE_KEY }}
        run: |
          umask 077
          if [ -z "$VAULT_AGE_KEY" ]; then echo "The secret VAULT_AGE_KEY (the restore-test key) is missing."; exit 1; fi
          printf '%s\\n' "$VAULT_AGE_KEY" > "$T/key.txt"
          echo "VAULT_KEY_FILE=$T/key.txt" >> "$GITHUB_ENV"
      - name: Pick the date
        id: pick
        run: node "$T/vault.mjs" resolve-date
      - name: Restore the database
        id: db
        if: \${{ steps.pick.outputs.db == '1' }}
        env:
          VAULT_RESTORE_DATABASE_URL: \${{ secrets.VAULT_RESTORE_DATABASE_URL }}
          VAULT_DATE: \${{ steps.pick.outputs.date }}
        run: |
          set -euo pipefail
          rclone copyto "$VAULT_REMOTE/db/$VAULT_DATE/db.dump.age" "$T/db.dump.age" --retries 3 -q
          rclone copyto "$VAULT_REMOTE/db/$VAULT_DATE/db.json" "$T/db.json" --retries 3 -q
          age -d -i "$VAULT_KEY_FILE" -o "$T/db.dump" "$T/db.dump.age"
          rm -f "$T/db.dump.age"
          if [ "$VAULT_TARGET" = "new" ]; then
            if [ -z "$VAULT_RESTORE_DATABASE_URL" ]; then echo "The secret VAULT_RESTORE_DATABASE_URL (a NEW, empty database) is missing."; exit 1; fi
            TARGET_URL="$VAULT_RESTORE_DATABASE_URL"
          else
            TARGET_URL="postgresql://postgres:vault-scratch@localhost:5432/postgres"
          fi
          pg_restore --no-owner --no-privileges --dbname "$TARGET_URL" "$T/db.dump" 2> "$T/restore.err" || true
          shred -u "$T/db.dump"
          psql "$TARGET_URL" -X -q -c "analyze" > /dev/null
          VAULT_COUNTS="$(psql "$TARGET_URL" -X -At -F '|' -c "${COUNTS_SQL}")" node "$T/vault.mjs" db-check
      - name: Restore the stored files
        id: files
        if: \${{ steps.pick.outputs.files == '1' }}
        env:
          VAULT_DATE: \${{ steps.pick.outputs.date }}
        run: node "$T/vault.mjs" files-restore
      - name: Send the receipt to 7IT Guard
        if: \${{ always() }}
        env:
          VAULT_DATE: \${{ steps.pick.outputs.date }}
          VAULT_STEPS: prepare=\${{ steps.prepare.outcome }} tools=\${{ steps.tools.outcome }} key=\${{ steps.key.outcome }} pick=\${{ steps.pick.outcome }} db=\${{ steps.db.outcome }} files=\${{ steps.files.outcome }}
        run: node "$T/vault.mjs" receipt
      - name: Clean up
        if: \${{ always() }}
        run: |
          [ -n "\${T:-}" ] || exit 0
          [ -f "$T/db.dump" ] && shred -u "$T/db.dump"
          rm -rf "$T"
`;
}

export function vaultFiles(input) { return [{ path: BACKUP_PATH, text: backupWorkflow(input) }, { path: RESTORE_PATH, text: restoreWorkflow(input) }]; }
export function workflowVersionOf(text) { const m = /^# 7IT Guard Vault workflow v(\d{1,4})\s*$/m.exec(String(text || '').split('\n')[0] || ''); return m ? Number(m[1]) : null; }

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const a = process.argv.slice(2), get = (k) => { const i = a.indexOf('--' + k); return i >= 0 ? a[i + 1] : undefined; };
  const out = get('out');
  const files = vaultFiles({ recipient: get('recipient'), ci: get('ci'), pg: get('pg') ? Number(get('pg')) : undefined, files: get('files'), remotePath: get('remote-path'), remoteKind: get('remote-kind'), tz: get('tz'), hour: get('hour') ? Number(get('hour')) : undefined, seed: get('seed') });
  for (const f of files) { if (out) { const p = join(out, f.path); mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, f.text); console.log('wrote ' + p); } else console.log(f.text); }
}
