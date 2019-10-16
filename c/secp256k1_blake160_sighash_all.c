#include "blake2b.h"
#include "ckb_syscalls.h"
#include "common.h"
#include "protocol_reader.h"
#include "secp256k1_helper.h"

#define BLAKE2B_BLOCK_SIZE 32
#define BLAKE160_SIZE 20
#define PUBKEY_SIZE 33
#define TEMP_SIZE 1024
#define RECID_INDEX 64
/* 32 KB */
#define MAX_WITNESS_SIZE 32768
#define SCRIPT_SIZE 32768
#define SIGNATURE_SIZE 65

/* Extract lock from WitnessArgs */
int extract_witness_lock(const uint8_t *witness, uint64_t len,
                         mol_read_res_t *lock_bytes_res) {
  mol_pos_t witness_pos;
  witness_pos.ptr = witness;
  witness_pos.size = len;

  mol_read_res_t lock_res = mol_cut(&witness_pos, MOL_WitnessArgs_lock());
  if (lock_res.code != 0) {
    return ERROR_ENCODING;
  }
  *lock_bytes_res = mol_cut_bytes(&lock_res.pos);
  if (lock_bytes_res->code != 0) {
    return ERROR_ENCODING;
  }

  return 0;
}

/*
 * Arguments:
 * pubkey blake160 hash, blake2b hash of pubkey first 20 bytes, used to
 * shield the real pubkey.
 *
 * Witness:
 * WitnessArgs with a signature in lock field used to present ownership.
 */
int main() {
  int ret;
  uint64_t len = 0;
  unsigned char temp[TEMP_SIZE];
  unsigned char lock_bytes[SIGNATURE_SIZE];

  /* Load args */
  unsigned char script[SCRIPT_SIZE];
  len = SCRIPT_SIZE;
  ret = ckb_load_script(script, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }
  if (len > SCRIPT_SIZE) {
    return ERROR_SCRIPT_TOO_LONG;
  }
  mol_pos_t script_pos;
  script_pos.ptr = (const uint8_t *)script;
  script_pos.size = len;

  mol_read_res_t args_res = mol_cut(&script_pos, MOL_Script_args());
  if (args_res.code != 0) {
    return ERROR_ENCODING;
  }
  mol_read_res_t args_bytes_res = mol_cut_bytes(&args_res.pos);
  if (args_bytes_res.code != 0) {
    return ERROR_ENCODING;
  } else if (args_bytes_res.pos.size != BLAKE160_SIZE) {
    return ERROR_ARGUMENTS_LEN;
  }

  /* Check witnesses is less than or equals to inputs  */
  ret = check_witnesses_len();
  if (ret != CKB_SUCCESS) {
    return ERROR_INVALID_WITNESSES_COUNT;
  }

  /* Load witness of first input */
  unsigned char witness[MAX_WITNESS_SIZE];
  uint64_t witness_len = MAX_WITNESS_SIZE;
  ret = ckb_load_witness(witness, &witness_len, 0, 0, CKB_SOURCE_GROUP_INPUT);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }

  if (witness_len > MAX_WITNESS_SIZE) {
    return ERROR_WITNESS_SIZE;
  }

  /* load signature */
  mol_read_res_t lock_bytes_res;
  ret = extract_witness_lock(witness, witness_len, &lock_bytes_res);
  if (ret != 0) {
    return ERROR_ENCODING;
  }

  if (lock_bytes_res.pos.size != SIGNATURE_SIZE) {
    return ERROR_ARGUMENTS_LEN;
  }
  memcpy(lock_bytes, lock_bytes_res.pos.ptr, lock_bytes_res.pos.size);

  /* Load tx hash */
  unsigned char tx_hash[BLAKE2B_BLOCK_SIZE];
  len = BLAKE2B_BLOCK_SIZE;
  ret = ckb_load_tx_hash(tx_hash, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }

  /* Prepare sign message */
  unsigned char message[BLAKE2B_BLOCK_SIZE];
  blake2b_state blake2b_ctx;
  blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&blake2b_ctx, tx_hash, BLAKE2B_BLOCK_SIZE);

  /* Clear lock field to zero, then digest the first witness */
  memset((void *)lock_bytes_res.pos.ptr, 0, lock_bytes_res.pos.size);
  blake2b_update(&blake2b_ctx, (char *)&witness_len, sizeof(uint64_t));
  blake2b_update(&blake2b_ctx, witness, witness_len);

  /* Digest other witnesses */
  size_t i = 1;
  while (1) {
    len = MAX_WITNESS_SIZE;
    ret = ckb_load_witness(temp, &len, 0, i, CKB_SOURCE_GROUP_INPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ERROR_SYSCALL;
    }
    if (len > MAX_WITNESS_SIZE) {
      return ERROR_WITNESS_SIZE;
    }
    blake2b_update(&blake2b_ctx, (char *)&len, sizeof(uint64_t));
    blake2b_update(&blake2b_ctx, temp, len);
    i += 1;
  }
  blake2b_final(&blake2b_ctx, message, BLAKE2B_BLOCK_SIZE);

  /* Load signature */
  secp256k1_context context;
  uint8_t secp_data[CKB_SECP256K1_DATA_SIZE];
  ret = ckb_secp256k1_custom_verify_only_initialize(&context, secp_data);
  if (ret != 0) {
    return ret;
  }

  secp256k1_ecdsa_recoverable_signature signature;
  if (secp256k1_ecdsa_recoverable_signature_parse_compact(
          &context, &signature, lock_bytes, lock_bytes[RECID_INDEX]) == 0) {
    return ERROR_SECP_PARSE_SIGNATURE;
  }

  /* Recover pubkey */
  secp256k1_pubkey pubkey;
  if (secp256k1_ecdsa_recover(&context, &pubkey, &signature, message) != 1) {
    return ERROR_SECP_RECOVER_PUBKEY;
  }

  /* Check pubkey hash */
  size_t pubkey_size = PUBKEY_SIZE;
  if (secp256k1_ec_pubkey_serialize(&context, temp, &pubkey_size, &pubkey,
                                    SECP256K1_EC_COMPRESSED) != 1) {
    return ERROR_SECP_SERIALIZE_PUBKEY;
  }

  blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&blake2b_ctx, temp, pubkey_size);
  blake2b_final(&blake2b_ctx, temp, BLAKE2B_BLOCK_SIZE);

  if (memcmp(args_bytes_res.pos.ptr, temp, BLAKE160_SIZE) != 0) {
    return ERROR_PUBKEY_BLAKE160_HASH;
  }

  return 0;
}
