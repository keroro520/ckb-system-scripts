#include "ckb_syscalls.h"
#include "protocol.h"
#include "common.h"
#include "stdio.h"

//      char s[100];
//      sprintf(s, "jjjjj %ld ", len);
//      ckb_debug(s);

// TODO * remove the requirement of same phases of inputs/outputs
// TODO * time lock checking
// TODO * verify phase transfer
// TODO MolReader_Verify 里应该会校验长度，其实没必要在前面还检查一次 if len == xxx
// TODO 对于 challenge ，要加上对 capacity 的检查
// TODO 搞懂 "static" 关键字的用处
// TODO 什么时候用 CKB_SOURCE_INPUT 什么时候用 CKB_SOURCE_GROUP_INPUT
// TODO 验证 input 的时候，其实只需要验证 layout，不需要验证 content，所以直接调 verify_xxx 来验证 input 有点浪费
// TODO 把 extract_* 个格式统一一下？
// TODO 分账
// TODO Compare the input-summary and output-summary by alphabetical order
// TODO 因为 finalize 分账时要从 input AggrCell 里拿到 `reveals index` 列表，然后再去 cell-deps 拿到 RevealCell。那么 finalize 分账前就要校验一下这个当前的 cell-deps 是不是有作假。如果通过记录 `cell-deps-hash` 来防止作假的话，就要引入哈希库；所以我想就不管了，就比较个数目就可以了，我觉得这个安全假设可以接受。 ======> 其实也不用比较数目，因为 `reveals index` 是从 input.output_data 里拿到的，做不了假。 ======> 好吧，直接分账，不用做多余的检查了
// TODO 我在 finalize 分账的时候做了一个假设/限制：finalize tx 的 outputs 只能包含分账 output! 不能和其它类别的 input/output 混在一块！主要是为了减少分账的复杂度
// TODO 看一下有没有这样的 bug: 定义 mol_seg_t/mol_seg_res_t 然后直接用 xxx.ptr 传给 ckb_load_cell_data
// TODO finalize 再加一个限制：inputs.len() == 1 && 0th-input is AggregateCell && 0th-output is for finalizer, 1th-output is for aggregator, 2+i output is for i-th partitioner
// TODO 现在的方案的 AggrCell 中把 unreveals 作为 inputs、reveals 作为 cell_deps，但是这个问题在于要对 cell_deps 做 (block_number, tx_index, output_index) 做排序来确保 “唯一性”（主要是因为 StartCell.capacity 作为奖励可能只够 N 个参与者，即“奖励不够分”问题）。我觉得可以改一下方案，把 unreveals/reveals 都放到 input，这样就解决了 “奖励不够分” 的问题了
// TODO phase字段只要用 u8 即可，不需要用 u64

#define ERROR_INVALID_PHASE               -100
#define ERROR_INVALID_CAMPAIGN_ID         -101
#define ERROR_INVALID_CAPACITY            -102
#define ERROR_INVALID_COMMITMENT          -103
#define ERROR_INVALID_REVEAL              -104
#define ERROR_INVALID_AGGREGATE_UNREVEAL  -105
#define ERROR_INVALID_AGGREGATE_REVEAL    -106
#define ERROR_INVALID_AGGREGATE_INPUT     -107
#define ERROR_INVALID_CHALLENGE           -108
#define ERROR_INVALID_FINALIZE            -109

#define SCRIPT_SIZE       32768 /* 32 KB */
#define WITNESS_SIZE      32768 /* 32 KB */
#define OUT_POINT_SIZE    36
#define HASH_SIZE         32
#define REVEAL_SIZE       32768 /* 32 KB */
#define SUMMARY_SIZE      32768 /* 32 KB */

#define START_PHASE       1
#define COMMIT_PHASE      2
#define REVEAL_PHASE      3
#define AGGREGATE_PHASE   4
#define FINALIZE_PHASE    5

#define CAMPAIGN_PRE_OCCUPIED 8

struct {
  uint8_t* id;          // OutPoint
  uint64_t deposit;
  uint64_t period;
  uint8_t* script_hash;
} campaign;

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

int extract_campaign_info(
  bool* is_campaign_cell, uint8_t* phase, size_t index, size_t source
) {
    int ret;
    unsigned char actual_script_hash[HASH_SIZE];
    uint64_t len = HASH_SIZE;

    // Check if this is a campaign cell
    ret = ckb_load_cell_by_field(
        actual_script_hash, &len, 0, index,
        source, CKB_CELL_FIELD_TYPE_HASH
    );
    if (ret != CKB_SUCCESS) {
      char s[100];
      sprintf(s, "ffff %d ", *phase);
      ckb_debug(s);
      //ckb_debug("iiiiiiiiii\0");
      ckb_debug("ffffffffff\0");
      return ret;
    }
    if (len != HASH_SIZE) {
      ckb_debug("hhhhhhhhhh\0");
      return ERROR_SYSCALL;
    }
    if (memcmp(actual_script_hash, campaign.script_hash, HASH_SIZE) != 0) {
      *is_campaign_cell = false;
      return CKB_SUCCESS;
    }

    // Get phase
    len = 8;
    ret = ckb_load_cell_data(
        (unsigned char *)phase, &len, 0, index, source
    );
    if (ret != CKB_SUCCESS) {
      ckb_debug("gggggggggf\0");
      return ret;
    }
    if (len != 1) {
      return ERROR_ENCODING;
    }
    if (*phase < START_PHASE || FINALIZE_PHASE < *phase) {
      return ERROR_INVALID_PHASE;
    }

    // Now we know this cell is campaign cell,
    // and we alreaady get the `phase` and `capacity`.
    *is_campaign_cell = true;
    return CKB_SUCCESS;
}

mol_seg_res_t extract_summary(size_t index, size_t source) {
  mol_seg_res_t summary_seg_res;
  unsigned char summary[SUMMARY_SIZE];
  uint64_t len = 0;
  int ret = ckb_load_cell_data(summary, &len, CAMPAIGN_PRE_OCCUPIED, index, source);
  if (ret == CKB_SUCCESS) {
    summary_seg_res.seg.ptr = (uint8_t *)summary;
    summary_seg_res.seg.size = len;
    if (MolReader_Summary_verify(&summary_seg_res.seg, false) != MOL_OK) {
      ret = ERROR_ENCODING;
    }
  }

  summary_seg_res.errno = ret;
  return summary_seg_res;
}

mol_seg_res_t extract_reveal_lock_script(size_t index, size_t source) {
  mol_seg_res_t script_seg_res;
  unsigned char script[SCRIPT_SIZE];
  uint64_t len = 0;
  int ret = ckb_load_cell_data(
    script, &len, CAMPAIGN_PRE_OCCUPIED, index, source
  );
  if (ret != CKB_SUCCESS) {
    script_seg_res.errno = ret;
    return script_seg_res;
  }

  script_seg_res.seg.ptr = (uint8_t *)script;
  script_seg_res.seg.size = len;
  if (MolReader_Script_verify(&script_seg_res.seg, false) != MOL_OK) {
    script_seg_res.errno = ERROR_ENCODING;
  }

  script_seg_res.errno = MOL_OK;
  return script_seg_res;
}

int initialize() {
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

  mol_seg_t args_seg = MolReader_Script_get_args(&script_seg_res.seg);
  mol_seg_t campaign_seg = MolReader_Bytes_raw_bytes(&args_seg);
  if (MolReader_CampaignArgs_verify(&campaign_seg, false) != MOL_OK) {
    return ERROR_ENCODING;
  }

  campaign.id = (uint8_t*)(MolReader_CampaignArgs_get_id(&campaign_seg).ptr);
  campaign.period = *(uint64_t*)(MolReader_CampaignArgs_get_period(&campaign_seg).ptr);
  campaign.deposit = *(uint64_t*)(MolReader_CampaignArgs_get_deposit(&campaign_seg).ptr);
  campaign.script_hash = (uint8_t*)(script_hash_seg_res.seg.ptr);
  return CKB_SUCCESS;
}

int verify_campaign_id(size_t index, size_t source) {
  uint8_t out_point[OUT_POINT_SIZE];
  uint64_t len = OUT_POINT_SIZE;
  int ret = ckb_load_input_by_field(
      out_point, &len, 0, index, source,
      CKB_INPUT_FIELD_OUT_POINT
  );
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len != OUT_POINT_SIZE) {
    return ERROR_SYSCALL;
  }

  mol_seg_t out_point_seg;
  out_point_seg.ptr = out_point;
  out_point_seg.size = OUT_POINT_SIZE;
  if (MolReader_OutPoint_verify(&out_point_seg, false) != MOL_OK) {
    return ERROR_SYSCALL;
  }

  if (memcmp(out_point, campaign.id, OUT_POINT_SIZE) != 0) {
    return ERROR_INVALID_CAMPAIGN_ID;
  }
  return MOL_OK;
}

int verify_capacity(uint64_t expected_capacity, size_t index) {
  uint64_t capacity = 0;
  uint64_t len = 8;
  int ret = ckb_load_cell_by_field(
      (unsigned char *)&capacity, &len, 0, index,
      CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_CAPACITY
  );
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len != 8) {
    return ERROR_SYSCALL;
  }

  if (capacity != expected_capacity) {
    return ERROR_INVALID_CAPACITY;
  }
  return CKB_SUCCESS;
}

int verify_commitment(size_t index, size_t source) {
  uint64_t len = HASH_SIZE;
  unsigned char commitment[HASH_SIZE];
  int ret = ckb_load_cell_data(
      commitment, &len, CAMPAIGN_PRE_OCCUPIED,
      index, source
  );
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len != HASH_SIZE) {
    return ERROR_INVALID_COMMITMENT;
  }

  mol_seg_t commitment_seg;
  commitment_seg.ptr = commitment;
  commitment_seg.size = HASH_SIZE;
  if (MolReader_Byte32_verify(&commitment_seg, false) != MOL_OK) {
    return ERROR_ENCODING;
  }

  return CKB_SUCCESS;
}

int verify_reveal_witness(size_t index) {
  unsigned char witness[WITNESS_SIZE];
  uint64_t len = 0;
  int ret = ckb_load_witness(
      witness, &len, 0, index,
      CKB_SOURCE_GROUP_INPUT
  );
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  mol_seg_t witness_seg;
  witness_seg.ptr = witness;
  witness_seg.size = len;
  if (MolReader_WitnessArgs_verify(&witness_seg, false) != MOL_OK) {
    return ERROR_SYSCALL;
  }

  mol_seg_t reveal_seg = MolReader_WitnessArgs_get_output_type(&witness_seg);
  if (reveal_seg.size != 8) {
    return ERROR_INVALID_REVEAL;
  }
  return CKB_SUCCESS;
}

int verify_summary(size_t index, size_t source) {
  mol_num_t minimal;
  mol_seg_res_t summary_seg_res = extract_summary(index, source);
  if (summary_seg_res.errno != MOL_OK) {
    return summary_seg_res.errno;
  }

  if (source == CKB_SOURCE_OUTPUT) {
    // Only check unreveals when source is CKB_SOURCE_OUTPUT
    mol_seg_t unreveals_seg = MolReader_Summary_get_unreveals(&summary_seg_res.seg);
    for (mol_num_t i = 0, n = MolReader_IndexVec_length(&unreveals_seg); i < n; i++) {
      mol_num_t pos = *(mol_num_t*)(MolReader_IndexVec_get(&unreveals_seg, i).seg.ptr);
      if (i == 0 || pos > minimal) {
        minimal = pos;
      } else {
        return ERROR_INVALID_AGGREGATE_UNREVEAL;
      }

      bool is_campaign_cell;
      uint8_t phase;
      int ret = extract_campaign_info(
          &is_campaign_cell, &phase, pos, CKB_SOURCE_INPUT
      );
      if (!(ret == CKB_SUCCESS && is_campaign_cell && phase == COMMIT_PHASE)) {
        return ERROR_INVALID_AGGREGATE_UNREVEAL;
      }
    }
  }

  mol_seg_t reveals_seg = MolReader_Summary_get_reveals(&summary_seg_res.seg);
  for (mol_num_t i = 0, n = MolReader_IndexVec_length(&reveals_seg); i < n; i++) {
    mol_num_t pos = *(mol_num_t*)(MolReader_IndexVec_get(&reveals_seg, i).seg.ptr);
    if (i == 0 || pos > minimal) {
      minimal = pos;
    } else {
      return ERROR_INVALID_AGGREGATE_REVEAL;
    }

    bool is_campaign_cell;
    uint8_t phase;
    int ret = extract_campaign_info(
        &is_campaign_cell, &phase,
        pos, CKB_SOURCE_CELL_DEP
    );
    if (!(ret == CKB_SUCCESS && is_campaign_cell && phase == REVEAL_PHASE)) {
      return ERROR_INVALID_AGGREGATE_REVEAL;
    }
  }

  return CKB_SUCCESS;
}

int verify_start(size_t index, size_t source) {
  int ret = verify_capacity(campaign.deposit, index);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  return verify_campaign_id(index, source);
}

int verify_commit(size_t index, size_t source) {
  int ret;
  ret = verify_commitment(index, source);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  return verify_capacity(campaign.deposit, index);
}

int verify_reveal(size_t index) {
  int ret = verify_capacity(campaign.deposit, index);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  ret = extract_reveal_lock_script(index, CKB_SOURCE_OUTPUT).errno;
  if (ret != MOL_OK) {
    return ret;
  }

  // TODO verify commitment == hash(reveal)
  return verify_reveal_witness(index);
}

int verify_aggregate(size_t index, size_t source) {
  return verify_summary(index, source);
}

int verify_challenge(size_t index) {
  int ret = verify_summary(index, CKB_SOURCE_INPUT);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  uint64_t input_data_size = 0;
  uint64_t output_data_size = 0;
  int ret1 = ckb_load_cell_data(NULL, &input_data_size, 0, index, CKB_SOURCE_INPUT);
  int ret2 = ckb_load_cell_data(NULL, &output_data_size, 0, index, CKB_SOURCE_OUTPUT);
  if (ret1 != CKB_SUCCESS || ret2 != CKB_SUCCESS || input_data_size > output_data_size) {
    return ERROR_INVALID_CHALLENGE;
  }
  if (input_data_size == output_data_size) {
    // TODO Compare the input-summary and output-summary by alphabetical order
  }
  return CKB_SUCCESS;
}

int verify_finalize(size_t index) {
  mol_seg_res_t summary_seg_res = extract_summary(index, CKB_SOURCE_INPUT);
  if (summary_seg_res.errno != MOL_OK) {
    return summary_seg_res.errno;
  }

  mol_seg_t reveals_seg = MolReader_Summary_get_reveals(&summary_seg_res.seg);
  for (mol_num_t i = 0, n = MolReader_IndexVec_length(&reveals_seg); i < n; i++) {
    mol_num_t pos = *(mol_num_t*)(MolReader_IndexVec_get(&reveals_seg, i).seg.ptr);

    // Check that ith-output is corresponding to `pos-th-cell-dep`
    mol_seg_res_t script_seg_res = extract_reveal_lock_script(pos, CKB_SOURCE_CELL_DEP);
    if (script_seg_res.errno != MOL_OK) {
      return script_seg_res.errno;
    }
    // mol_seg_t expected_script_seg = script_seg_res.seg;

    // TODO 分账：0th is for finalizer, 1th is for aggregator, (2+i) is for ith partitioner
    // unsigned char actual_script[SCRIPT_SIZE];
    // uint64_t len = 0;
    // int ret = ckb_load_cell_by_field(
    //     actual_script, &len, 0, i+2, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_LOCK
    // );
    //
    // if (ret != CKB_SUCCESS) {
    // }
  }

  // TODO 分账
  return CKB_SUCCESS;
}

int main() {
  int ret = initialize();
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  for (size_t index = 0; ret == CKB_SUCCESS; index++) {
    bool is_campaign_cell;
    uint8_t phase;
    int ret = extract_campaign_info(
        &is_campaign_cell, &phase,
        index, CKB_SOURCE_OUTPUT
    );
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    } else if (ret != CKB_SUCCESS) {
      ckb_debug("dddddddddd\0");
      return ret;
    } else if (!is_campaign_cell) {
      continue;
    }

    bool input_is_campaign_cell;
    uint8_t input_phase;
    switch (phase) {
      case START_PHASE:
        ret = verify_capacity(campaign.deposit, index);
        if (ret == CKB_SUCCESS) {
          ret = verify_start(index, CKB_SOURCE_OUTPUT);
        }
      case COMMIT_PHASE:
        ret = verify_commit(index, CKB_SOURCE_OUTPUT);
      case REVEAL_PHASE:
        ret = verify_commit(index, CKB_SOURCE_INPUT);
        if (ret == CKB_SUCCESS) {
          ret = verify_reveal(index);
        }
      case AGGREGATE_PHASE:
        ret = extract_campaign_info(
            &input_is_campaign_cell, &input_phase,
            index, CKB_SOURCE_INPUT
        );
        if (ret != CKB_SUCCESS) {
          ckb_debug("bbbbbbbbbb\0");
          return ret;
        }
        if (!input_is_campaign_cell) {
          return ERROR_INVALID_AGGREGATE_INPUT;
        }
        if (phase == START_PHASE) {
          // Normal
          //
          // As for normal AggregateCell, we expect its capacity be equal to
          // StartCell.capacity + campaign.deposit, which can be simplify to
          // 2 * campaign.deposit
          ret = verify_capacity(2 * campaign.deposit, index);
          if (ret == CKB_SUCCESS) {
            ret = verify_start(index, CKB_SOURCE_INPUT);
            if (ret == CKB_SUCCESS) {
              ret = verify_aggregate(index, CKB_SOURCE_OUTPUT);
            }
          }
        } else if (phase == AGGREGATE_PHASE) {
          // Challenge
          // TODO verify capacity
          ret = verify_aggregate(index, CKB_SOURCE_INPUT);
          if (ret == CKB_SUCCESS) {
            ret = verify_challenge(index);
          }
        } else {
          ckb_debug("cccccccccb\0");
          return ERROR_INVALID_AGGREGATE_INPUT;
        }
      case FINALIZE_PHASE:
        ret = verify_aggregate(index, CKB_SOURCE_INPUT);
        if (ret == CKB_SUCCESS) {
          ret = verify_finalize(index);
        }
    }
  }

  return ret;
}
