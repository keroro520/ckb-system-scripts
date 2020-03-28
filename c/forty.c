#include "ckb_syscalls.h"
#include "protocol.h"
#include "common.h"
#include "stdio.h"

#define SCRIPT_SIZE       32768 /* 32 KB */
#define WITNESS_SIZE      32768 /* 32 KB */
#define OUT_POINT_SIZE    36
#define HASH_SIZE         32

#define ERROR_FT_RULE1            42
#define ERROR_FT_RULE2            43
#define ERROR_LOAD_AMOUNT_HASH    44
#define ERROR_LOAD_PROOF          45

/* ====== NOTES ===== 
 *
 * * TODO UDT unique identifier
 *
 * * FT rules
 *
 *   * Rule1: FT-input and FT-output are 1v1 and at the same index
 *   * Rule2: FT-input.amount >= FT-output.amount (verified by syscall zk42)
 *   * Rule3: Free to burn the FT
 *
 * * FT OutputData format
 *
 *   ```
 *   [ amount_hash::Byte32, encrypted_amount::Bytes ]
 *   ```
 *
 * * Workflow
 *
 *   The script is positioned as FT type script. Hence here it should be an
 *   **output-type script** to do its verification jobs.
 *
 *     ```
 *     < normal checks ... >
 *     identifier := script.args[0:32]
 *     lock_hash = input.lock_hash
 *
 *     // "Issue" operation.
 *     IF identifier == lock_hash {
 *       RETURN CKB_SUCCESS
 *     }
 *
 *     // Next is "transfer" operation.
 *
 *     FOR (i, output) in ENUMERATE(outputs) {
 *       IF output.type_script.hash() == THE_CURRENT_SCRIPT_HASH {
 *         input = inputs[i]
 *         IF input.type_script.hash() != THE_CURRENT_SCRIPT_HASH {
 *           RETURN ERROR_RULE_1
 *         }
 *       }
 *      
 *       // Involve syscall "zk42" with the zk-proof fetched from witness
 *       input_amount_hash = input.data[0:32]
 *       output_amount_hash = output.data[0:32]
 *       witness = load_witness(i)
 *       zk_proof = witness.as_bytes()
 *       IF verify_zk_proof(input_amount_hash, output_amount_hash, zk_proof) {
 *         RETURN ERROR_RULE_2
 *       }
 *     }
 *
 *     RETURN CKB_SUCCESS
 *     ```
*/

// Load the current script.
mol_seg_res_t load_current_script() {
  mol_seg_res_t script_seg_res;
  unsigned char script[SCRIPT_SIZE];
  uint64_t len = SCRIPT_SIZE;
  int ret = ckb_load_script(script, &len, 0);
  if (ret != CKB_SUCCESS) {
    script_seg_res.errno = ret;
  } else if (len > SCRIPT_SIZE) {
    script_seg_res.errno = ERROR_SCRIPT_TOO_LONG;
  } else {
    script_seg_res.seg.ptr = (uint8_t *)script;
    script_seg_res.seg.size = len;

    if (MolReader_Script_verify(&script_seg_res.seg, false) != MOL_OK) {
      script_seg_res.errno = ERROR_ENCODING;
    } else {
      script_seg_res.errno = MOL_OK;
    }
  }
  return script_seg_res;
}

// Load the script-hash of the current script
mol_seg_res_t load_current_script_hash() {
  mol_seg_res_t script_hash_seg_res;
  mol_seg_t script_hash[HASH_SIZE];
  uint64_t len = HASH_SIZE;
  int ret = ckb_load_script_hash(script_hash, &len, 0);
  if (ret != CKB_SUCCESS) {
    script_hash_seg_res.errno = ret;
  } else if (len != HASH_SIZE) {
    script_hash_seg_res.errno = ERROR_SYSCALL;
  } else {
    script_hash_seg_res.errno = MOL_OK;
    script_hash_seg_res.seg.ptr = (uint8_t *)script_hash;
    script_hash_seg_res.seg.size = len;
  }
  return script_hash_seg_res;
}

// Load the amount_hash from OutputData corresponding to the `index` and `source`
mol_seg_res_t load_amount_hash(size_t index, size_t source) {
  mol_seg_res_t amount_hash_seg_res;
  mol_seg_t amount_hash[HASH_SIZE];
  uint64_t len = HASH_SIZE;

  int ret = ckb_load_cell_data(
    (unsigned char *)amount_hash, &len, 0, index, source
  );
  if (ret != CKB_SUCCESS) {
    amount_hash_seg_res.errno = ret;
  } else if (len != HASH_SIZE) {
    amount_hash_seg_res.errno = ERROR_LOAD_AMOUNT_HASH;
  } else {
    amount_hash_seg_res.errno = MOL_OK;
    amount_hash_seg_res.seg.ptr = (uint8_t *)amount_hash;
    amount_hash_seg_res.seg.size = len;
  }
  return amount_hash_seg_res;
}

// Load zk-proof from witness at index `index`
mol_seg_res_t load_proof(size_t index) {
  unsigned char witness[WITNESS_SIZE];
  uint64_t len = 0;
  int ret = ckb_load_witness(witness, &len, 0, index, CKB_SOURCE_GROUP_INPUT);
  if (ret != CKB_SUCCESS) {
    ret = ERROR_LOAD_PROOF;
  }

  mol_seg_res_t proof_seg_res;
  proof_seg_res.errno = ret;
  proof_seg_res.seg.ptr = witness;
  proof_seg_res.seg.size = len;

  return proof_seg_res;
}

// Verify zk-proof via syscall
int ft_verify(
    mol_seg_t input_amount_hash_seg,
    mol_seg_t output_amount_hash_seg,
    mol_seg_t proof_seg
) {
  return syscall(
    42,
    &input_amount_hash_seg.ptr,
    &output_amount_hash_seg.ptr,
    &proof_seg.ptr,
    proof_seg.size,
    0, 0
  );
}

int main() {
  // Load current script
  mol_seg_res_t script_seg_res = load_current_script();
  if (script_seg_res.errno != MOL_OK) {
    return script_seg_res.errno;
  }

  // Load current script hash
  mol_seg_res_t script_hash_seg_res = load_current_script_hash();
  if (script_hash_seg_res.errno != MOL_OK) {
    return script_hash_seg_res.errno;
  }
  unsigned char *current_script_hash = script_hash_seg_res.seg.ptr;

  // Load current script args
  mol_seg_t args_seg = MolReader_Script_get_args(&script_seg_res.seg);
  mol_seg_t args_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);
  if (args_bytes_seg.size != HASH_SIZE) {
    return ERROR_ENCODING;
  }

  int ret = CKB_SUCCESS;
  for (size_t index = 0; ret == CKB_SUCCESS; index++) {
    unsigned char actual_script_hash[HASH_SIZE];
    uint64_t len = HASH_SIZE;

    ret = ckb_load_cell_by_field(
        actual_script_hash, &len, 0, index,
        CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_TYPE_HASH
    );
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    } else if (ret != CKB_SUCCESS) {
      return ret;
    } else if (len != HASH_SIZE) {
      return ERROR_SYSCALL;
    } else if (memcmp(actual_script_hash, current_script_hash, HASH_SIZE) != 0) {
      // Rule3: Free to burn FT. Hence here ignore non-FT output
      continue;
    }

    // We now know the output[index] is a FT cell

    // Rule1: FT input and FT output are 1v1 and at the same index
    ret = ckb_load_cell_by_field(
        actual_script_hash, &len, 0, index,
        CKB_SOURCE_INPUT, CKB_CELL_FIELD_TYPE_HASH
    );
    if (ret != CKB_SUCCESS) {
      return ret;
    } else if (len != HASH_SIZE) {
      return ERROR_SYSCALL;
    } else if (memcmp(actual_script_hash, current_script_hash, HASH_SIZE) != 0) {
      return ERROR_FT_RULE1;
    }

    // Rule2: FT-input.amount >= FT-output.amount (verified by syscall zk42)
    mol_seg_res_t input_amount_hash_seg_res = load_amount_hash(index, CKB_SOURCE_INPUT);
    if (input_amount_hash_seg_res.errno != MOL_OK) {
      return input_amount_hash_seg_res.errno;
    }

    mol_seg_res_t output_amount_hash_seg_res = load_amount_hash(index, CKB_SOURCE_INPUT);
    if (output_amount_hash_seg_res.errno != MOL_OK) {
      return output_amount_hash_seg_res.errno;
    }

    mol_seg_res_t proof_seg_res = load_proof(index);
    if (proof_seg_res.errno != MOL_OK) {
      return proof_seg_res.errno;
    }

    ret = ft_verify(
        input_amount_hash_seg_res.seg,
        output_amount_hash_seg_res.seg,
        proof_seg_res.seg
    );
    if (ret != CKB_SUCCESS) {
      return ret;
    }
  }

  return CKB_SUCCESS;
}
