#ifndef LPM_ENV_H
#define LPM_ENV_H
#include <stddef.h>
#include <stdint.h>

#define LPM_ENV_ABI_VERSION 1
#define LPM_ENV_INPUT_LIMIT (2 * 1024 * 1024)
#define LPM_ENV_OUTPUT_LIMIT (8 * 1024 * 1024)
#define LPM_ENV_SEAL_INPUT_LIMIT (64 * 1024)
#define LPM_ENV_BACKUP_FILE_LIMIT (64 * 1024 * 1024)
#define LPM_ENV_BACKUP_PASSPHRASE_LIMIT (4 * 1024)

typedef struct LPMEnvSnapshot LPMEnvSnapshot;
typedef struct {
    uint32_t status;
    uint8_t *data;
    size_t length;
    LPMEnvSnapshot *snapshot;
} LPMEnvResult;

uint32_t lpm_env_abi_version(void);
/* Input and folder pointers must reference valid UTF-8 byte ranges during the call.
 * status: 0=resolved, 1=invalid schema/source, 2=invalid input, 3=panic, 4=output limit,
 * 5=refused (the LPM home and project files).
 * Every returned result must be released exactly once, including failures.
 * The result and snapshot cannot be used after release. */
/* Validate a flat schema without filesystem access. Authored imports require resolve. */
LPMEnvResult lpm_env_validate(const uint8_t *input, size_t input_length);
LPMEnvResult lpm_env_resolve(const uint8_t *input, size_t input_length,
                           const uint8_t *folder, size_t folder_length);
/* 0=unchanged, 1=changed, 2=null snapshot, 3=panic. Retains no new ownership. */
uint32_t lpm_env_verify(const LPMEnvSnapshot *snapshot);
/* Check stored values against a flat schema, such as the "effective" schema that
 * lpm_env_resolve returns, the way the runner evaluates them at runtime, without
 * project files or the process environment. Both ranges must be valid UTF-8 JSON.
 * Input: {"environments":{"<name>":{"<KEY>":"<value>"}}}.
 * Output per environment: readsDefaultEnvironment (it has no values of its own, so
 * "default"'s values were checked), problems [{key, code, format?, constraint?,
 * group?, mode?}], defaults {KEY: schema default that fills it}, and ignored keys the
 * runner never passes to a process. Output never contains stored values.
 * At most 256 environments and 262144 work units are checked. Each environment
 * costs one unit per declaration, enum member, enum UTF-8 byte, group, group member,
 * and selected stored value (including fallback values), plus one.
 * Larger inputs fail before evaluation.
 * status: 0=checked, 1=invalid schema or names differing only in case where the host
 * ignores case, 2=invalid input, 3=panic, 4=work or output limit. */
LPMEnvResult lpm_env_check(const uint8_t *schema, size_t schema_length,
                         const uint8_t *input, size_t input_length);
/* Encrypt plaintext as a libsodium sealed box (crypto_box_seal) to a 32-byte
 * Curve25519 public key, the form GitHub requires for an Actions secret. Output:
 * the ephemeral public key then the box, plaintext_length + 48 bytes. plaintext
 * may be null only when plaintext_length is 0; at most LPM_ENV_SEAL_INPUT_LIMIT.
 * A low-order key, which libsodium refuses to open a box for, is invalid input.
 * status: 0=sealed, 2=invalid input, 3=failure or panic. */
LPMEnvResult lpm_env_seal_box(const uint8_t *public_key, size_t public_key_length,
                            const uint8_t *plaintext, size_t plaintext_length);
/* The LPM home and project files, kept as the CLI keeps them. Every path is an
 * absolute UTF-8 path of at most 32 KiB.
 * Status 5 refuses with {code, message} and, for a secret file, path and, where
 * git tracks it, untrack: the commands that untrack it, each quoted in backticks. */
/* Where the LPM home at `home` is once links are followed, whether it is the
 * default home (`.lpm` in `user_home`), and the suffix the CLI appends to its
 * credential-store service names there: {identity, isDefault, scope}, scope null
 * for the default home, else 16 hex digits, used as "<service>:<scope>". identity
 * is canonical as far as the path exists, with the rest appended.
 * status: 0=described, 2=invalid input, 3=panic. */
LPMEnvResult lpm_env_describe_home(const uint8_t *home, size_t home_length,
                                 const uint8_t *user_home, size_t user_home_length);
/* Create the LPM home owner-only where it is missing and keep it out of git with
 * a .gitignore that ignores everything, as the CLI does before it writes login or
 * env state there. Output {exposed}: null, or {reason, atRepositoryRoot} where a
 * git repository around the home could commit what it holds, so nothing secret
 * may be written there; only another home keeps a repository's root out.
 * status: 0=prepared, 2=invalid input, 3=panic, 5=could not create the home. */
LPMEnvResult lpm_env_prepare_home(const uint8_t *home, size_t home_length);
/* The project the CLI's env commands act on for `folder`: the nearest directory at
 * or above it with a package.json or lpm.json, stopping before `user_home`, else
 * `folder`. Output {root, isProject, stateIsHome}; stateIsHome means the project's
 * .lpm is the LPM home at `home`, where project state must not be kept.
 * status: 0=found, 2=invalid input, 3=panic. */
LPMEnvResult lpm_env_project_root(const uint8_t *folder, size_t folder_length,
                                const uint8_t *user_home, size_t user_home_length,
                                const uint8_t *home, size_t home_length);
/* Open the .lpm of the open project directory `project`, at `display`, as the CLI
 * does: created owner-only where missing, never through a link, kept from group
 * and other access and from inherited macOS access lists where the user owns it,
 * and with a .gitignore that ignores everything. A project whose .lpm would be the
 * LPM home at `home` is refused. On success *state receives a new descriptor for
 * .lpm that the caller closes. status: 0=opened, 2=invalid input, 3=panic,
 * 5=refused: code env.project_state_is_home, env.project_state_link (.lpm is a
 * link or not a directory), or env.project_state. */
LPMEnvResult lpm_env_open_project_state(int32_t project, const uint8_t *display,
                                      size_t display_length, const uint8_t *home,
                                      size_t home_length, int32_t *state);
/* Ready `path` for a file of secrets that the caller then writes, as `lpm env
 * export` readies one for the project at `project`: git is made to ignore it, by a
 * rule in the .gitignore of the project or of the repository that holds it, and a
 * file git tracks is refused, as is one git can't be run for where a repository
 * holds it. Runs git. Output {ignore: {kind, files}, warnings}, kind one of
 * outsideProject, alreadyIgnored, added, noRepository, unverified (git can't run
 * and no repository holds it), failed. status: 0=ready, 2=invalid input,
 * 3=panic, 5=refused: code env.secret_tracked, env.secret_unverified,
 * env.secret_ignore, or env.secret_write. */
LPMEnvResult lpm_env_prepare_secret_file(const uint8_t *project, size_t project_length,
                                       const uint8_t *path, size_t path_length);
/* Backup files: env projects in one file protected by a passphrase, in the
 * lpm-env-backup format the CLI shares. Passphrases are UTF-8 of at most
 * LPM_ENV_BACKUP_PASSPHRASE_LIMIT bytes, used in Unicode NFC (at most 1 KiB) and
 * otherwise exactly as typed. A file is at most LPM_ENV_BACKUP_FILE_LIMIT bytes.
 * Sealing and opening derive a key with Argon2id over 256 MiB of memory, one
 * derivation at a time, so call them off the main thread.
 * Status 5 refuses with {code} and, where noted, more fields:
 *   backup.passphrase_empty, backup.passphrase_not_utf8, backup.passphrase_too_long;
 *   backup.passphrase_weak {guessesLog10};
 *   backup.too_large; backup.not_a_backup; backup.newer_format {formatVersion};
 *   backup.damaged; backup.wrong_passphrase (or the file was changed);
 *   backup.invalid_contents {reason, offset?}, never quoting the contents; offset
 *   is the payload byte where the problem was found.
 * Status 3 is a panic, backup.random_failed, or backup.out_of_memory.
 * A pointer may be null only when its length is 0; a length over its limit is
 * refused before the pointer is read. Every output buffer is zeroed when released,
 * and the engine zeroes all memory it frees.
 * The format records no platform logins; sync keys travel only through
 * lpm_env_backup_open_split's records. */
/* zxcvbn's estimate for a passphrase, of at most its first 100 characters:
 * {acceptable, guessesLog10, minimumGuessesLog10}; acceptable means a backup can be
 * sealed with it. The first call loads zxcvbn's dictionaries; an estimate can then
 * take a quarter of a second for symbol-heavy text, so run it off the main thread
 * and keep only the latest. Only the first 100 characters, once normalized, count.
 * status: 0=checked, 2=invalid input, 3=panic, 5=refused. */
LPMEnvResult lpm_env_backup_check_passphrase(const uint8_t *passphrase, size_t length);
/* Six words drawn uniformly from the EFF large wordlist, separated by spaces, as
 * UTF-8 bytes (not JSON); always acceptable. status: 0=generated, 3=failure. */
LPMEnvResult lpm_env_backup_generate_passphrase(void);
/* Check a payload (described in lpm-env-backup's payload module) and the
 * passphrase's strength, then encrypt the payload into a backup file, the output.
 * status: 0=sealed, 2=invalid input, 3=failure, 5=refused. */
LPMEnvResult lpm_env_backup_seal(const uint8_t *payload, size_t payload_length,
                               const uint8_t *passphrase, size_t passphrase_length);
/* Read a file's header without the passphrase: {formatVersion}.
 * status: 0=a backup this engine reads, 2=invalid input, 3=panic, 5=refused. */
LPMEnvResult lpm_env_backup_inspect(const uint8_t *file, size_t length);
/* Decrypt a backup file and check its payload. The output is the whole decrypted
 * plaintext, so the payload isn't copied: on success *payload_offset and
 * *payload_length say where the payload is in it. The file's header is checked
 * before the key is derived, and strength isn't checked again.
 * status: 0=opened, 2=invalid input, 3=failure, 5=refused. */
LPMEnvResult lpm_env_backup_open(const uint8_t *file, size_t file_length,
                               const uint8_t *passphrase, size_t passphrase_length,
                               size_t *payload_offset, size_t *payload_length);
/* Open as lpm_env_backup_open does, and take the payload's keys out of it, so
 * keys never reach a JSON parser as text: *payload_offset and *payload_length say
 * where the payload, without its keys member, is in the output, and *keys_offset
 * and *keys_length where the keys' records are, right after it. Records follow
 * one another, each a kind byte, then:
 *   1 personal root key: account digest (32 bytes), key as 64 lowercase hex digits;
 *   2 live sharing key, 3 pending sharing key: account digest (32 bytes), key as
 *     44 standard base64 digits;
 *   4 legacy wrapping key: key as 64 lowercase hex digits;
 *   5 key floor: name digest (32 bytes), version as a big-endian uint32.
 * Keys and floors are written as their stores keep them; an account digest's hex
 * is its store account (sharing keys under "__x25519_private_key__." and its
 * ".pending" form), and a floor's is its file name after
 * ".env-project-key-floor-". With no keys, *keys_length is 0.
 * status: 0=opened, 2=invalid input, 3=failure, 5=refused. */
LPMEnvResult lpm_env_backup_open_split(const uint8_t *file, size_t file_length,
                                     const uint8_t *passphrase, size_t passphrase_length,
                                     size_t *payload_offset, size_t *payload_length,
                                     size_t *keys_offset, size_t *keys_length);
/* Release only the output buffer after decoding; the snapshot stays live.
 * Exclusively borrow result. Clears data/length; repeated calls are harmless.
 * A matching lpm_env_release is still required for the result. */
void lpm_env_clear_output(LPMEnvResult *result);
void lpm_env_release(LPMEnvResult result);
#endif
