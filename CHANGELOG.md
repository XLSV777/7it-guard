# Changelog

## 0.4.0 (2026-10-13)

- New command `/7it-guard:vault`: a nightly encrypted backup of the app's database and stored files into storage you own, with a weekly restore test and restore by date (full, database only or files only), all running in your own GitHub account. Needs a 7IT key whose plan or Vault add-on includes the vault.
- The local fix server gains a second tool, `vault_register`, which registers the vault with 7IT (never a database address, a password, a storage key or any private key).
- On Lovable Cloud or Bolt Database the command writes nothing and explains the manual export and the move to your own Supabase project.
- The check script itself is unchanged (it still reports 0.3.2).

## 0.3.2

- Supabase grants in the database guidance.
