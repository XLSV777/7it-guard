# Changelog

## 0.4.1 (2026-10-26)

- The text report has one more line, right after the "Full report:" link: it names the 7IT Guard app, which checks the app from outside on a schedule after launch and says when it stops answering, with its address (`https://7it.co.il/guard/app/?from=plugin`). The address is fixed: nothing from the check is in it.
- The skill and `/7it-guard:check` pass that line on once, after the closing "Not checked from outside" line.
- The check script now reports 0.4.1 (it said 0.3.2 through 0.4.0).

## 0.4.0 (2026-10-13)

- New command `/7it-guard:vault`: a nightly encrypted backup of the app's database and stored files into storage you own, with a weekly restore test and restore by date (full, database only or files only), all running in your own GitHub account. Needs a 7IT key whose plan or Vault add-on includes the vault.
- The local fix server gains a second tool, `vault_register`, which registers the vault with 7IT (never a database address, a password, a storage key or any private key).
- On Lovable Cloud or Bolt Database the command writes nothing and explains the manual export and the move to your own Supabase project.
- The check script itself is unchanged (it still reports 0.3.2).

## 0.3.2

- Supabase grants in the database guidance.
