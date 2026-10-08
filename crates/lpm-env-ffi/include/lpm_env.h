#ifndef LPM_ENV_H
#define LPM_ENV_H
#include <stddef.h>
#include <stdint.h>

#define LPM_ENV_ABI_VERSION 1
#define LPM_ENV_INPUT_LIMIT (2 * 1024 * 1024)
#define LPM_ENV_OUTPUT_LIMIT (8 * 1024 * 1024)

typedef struct LPMEnvSnapshot LPMEnvSnapshot;
typedef struct {
    uint32_t status;
    uint8_t *data;
    size_t length;
    LPMEnvSnapshot *snapshot;
} LPMEnvResult;

uint32_t lpm_env_abi_version(void);
/* Input and folder pointers must reference valid UTF-8 byte ranges during the call.
 * status: 0=resolved, 1=invalid schema/source, 2=invalid input, 3=panic, 4=output limit.
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
 * At most 256 environments, and environments x (declarations + groups + 1) plus
 * stored values of at most 262144, are checked; larger inputs fail before evaluation.
 * status: 0=checked, 1=invalid schema or names differing only in case where the host
 * ignores case, 2=invalid input, 3=panic, 4=work or output limit. */
LPMEnvResult lpm_env_check(const uint8_t *schema, size_t schema_length,
                         const uint8_t *input, size_t input_length);
/* Release only the output buffer after decoding; the snapshot stays live.
 * Exclusively borrow result. Clears data/length; repeated calls are harmless.
 * A matching lpm_env_release is still required for the result. */
void lpm_env_clear_output(LPMEnvResult *result);
void lpm_env_release(LPMEnvResult result);
#endif
