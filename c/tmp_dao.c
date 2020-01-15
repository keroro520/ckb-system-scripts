#include "ckb_syscalls.h"
#include "protocol.h"

#define ERROR_UNKNOWN -1
#define ERROR_WRONG_NUMBER_OF_ARGUMENTS -2
#define ERROR_SYSCALL -4
#define ERROR_BUFFER_NOT_ENOUGH -10
#define ERROR_ENCODING -11
#define ERROR_WITNESS_TOO_LONG -12
#define ERROR_OVERFLOW -13
#define ERROR_INVALID_WITHDRAW_BLOCK -14
#define ERROR_INCORRECT_CAPACITY -15
#define ERROR_INCORRECT_EPOCH -16
#define ERROR_INCORRECT_SINCE -17
#define ERROR_TOO_MANY_OUTPUT_CELLS -18
#define ERROR_NEWLY_CREATED_CELL -19
#define ERROR_INVALID_WITHDRAWING_CELL -20
#define ERROR_SCRIPT_TOO_LONG -21

#define HASH_SIZE 32
#define SCRIPT_SIZE 32768 /* 32 KB */
#define DAO_DATA_SIZE 8

bool is_dao_input(
    unsigned char *dao_script_hash,
    size_t index
) {
  unsigned char input_script_hash[HASH_SIZE];
  uint64_t len = HASH_SIZE;
  int ret = ckb_load_cell_by_field(
      input_script_hash,
      &len,
      0,
      index,
      CKB_SOURCE_INPUT,
      CKB_CELL_FIELD_TYPE_HASH
  );
  return ret == CKB_SUCCESS &&
    len == HASH_SIZE &&
    memcmp(dao_script_hash, input_script_hash, HASH_SIZE) == 0;
}

int load_input_capacity(uint64_t *capacity , size_t index ) {
  uint64_t len;
  int ret = ckb_load_cell_by_field(
      ((unsigned char *)capacity),
      &len,
      0,
      index,
      CKB_SOURCE_INPUT,
      CKB_CELL_FIELD_CAPACITY
  );
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len != 8) {
    return ERROR_SYSCALL;
  }
  return CKB_SUCCESS;
}

mol_seg_res_t load_script() {
  unsigned char script[SCRIPT_SIZE];
  uint64_t len = SCRIPT_SIZE;
  mol_seg_res_t script_seg_res;

  int ret = ckb_load_script(script, &len, 0);
  if (ret != CKB_SUCCESS) {
    script_seg_res.errno = ret;
    return script_seg_res;
  }
  if (len > SCRIPT_SIZE) {
    script_seg_res.errno = ERROR_SCRIPT_TOO_LONG;
    return script_seg_res;
  }

  script_seg_res.seg.ptr = (uint8_t *)script;
  script_seg_res.seg.size = len;

  if (MolReader_Script_verify(&script_seg_res.seg, false /* compatible */) != MOL_OK) {
    script_seg_res.errno = ERROR_ENCODING;
    return script_seg_res;
  }

  script_seg_res.errno = MOL_OK;
  return script_seg_res;
}

mol_seg_t get_args_in_bytes(mol_seg_t *script_seg ) {
  mol_seg_t args_seg = MolReader_Script_get_args(script_seg);
  mol_seg_t bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);
  return bytes_seg;
}

mol_seg_res_t load_script_hash() {
  unsigned char script_hash[HASH_SIZE];
  uint64_t len = HASH_SIZE;
  mol_seg_res_t script_hash_seg_res;

  int ret = ckb_load_script_hash(script_hash, &len, 0);
  if (ret != CKB_SUCCESS) {
    script_hash_seg_res.errno = ret;
    return script_hash_seg_res;
  }
  if (len != HASH_SIZE) {
    script_hash_seg_res.errno = ERROR_SYSCALL;
    return script_hash_seg_res;
  }

  script_hash_seg_res.errno = MOL_OK;
  script_hash_seg_res.seg.ptr = script_hash;
  script_hash_seg_res.seg.size = HASH_SIZE;
  return script_hash_seg_res;
}

int main() {
  uint64_t len = 0;

  // Load script
  mol_seg_res_t script_seg_res = load_script();
  if (script_seg_res.errno != MOL_OK) {
    return script_seg_res.errno;
  }
  mol_seg_t script_seg = script_seg_res.seg;

  // Load script args
  // NOTE: nervosdao 没有参与，所以所有的 nervosdao cell 的 type script 可以映射为同一个 type group。我还需要再思考一下 script args 的作用...

  // Load script hash
  mol_seg_res_t script_hash_seg_res = load_script_hash();
  if (script_hash_seg_res.errno != MOL_OK) {
    return script_seg_res.errno;
  }
  mol_seg_t script_hash_seg = script_hash_seg_res.seg;

  // Load dao-inputs
  size_t index = 0;
  // uint64_t input_capacities = 0;
  // uint64_t output_withdrawing_mask = 0;
  int ret;
  while (true) {
    uint64_t capacity = 0;
    
    ret = load_input_capacity(&capacity, index);
    if (ret == CKB_SUCCESS) {
      continue;
    } else if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    } else {
      return ret;
    }
    index += 1;
  }
}
