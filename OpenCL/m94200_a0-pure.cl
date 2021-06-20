/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_rp.h"
#include "inc_rp.cl"
#include "inc_scalar.cl"
#endif

#define READU32(addr) *(u32 *)(addr)

inline u32 Murmur32_Scramble(u32 k) {
    k = (k * 0x16A88000) | ((k * 0xCC9E2D51) >> 17);
    return (k * 0x1B873593);
}

DECLSPEC u32 MurmurHash3_Calc(const u8* data, const u32 size, const u32 seed) {
    u32 checksum = seed;

    if (size >= 4) { //Hash blocks, sizes of 4
        const u32 nBlocks = (size / 4);
        for (u32 i = 0; i < nBlocks; i++) {
            checksum ^= Murmur32_Scramble(READU32(data));
            checksum = (checksum >> 19) | (checksum << 13); //rotateRight(checksum, 19)
            checksum = (checksum * 5) + 0xE6546B64;
            data += 4;
        }
    }
    
    if (size % 4) {
        u32 val = 0;

        switch(size & 3) { //Hash remaining bytes as size isn't always aligned by 4
            case 3: val ^= (data[2] << 16);
            case 2: val ^= (data[1] << 8);
            case 1: val ^= data[0];
                    checksum ^= Murmur32_Scramble(val);
            default: 
                    break;
        };
    }

    checksum ^= size;
    checksum ^= checksum >> 16;
    checksum *= 0x85EBCA6B;
    checksum ^= checksum >> 13;
    checksum *= 0xC2B2AE35;
    return checksum ^ (checksum >> 16);
}

KERNEL_FQ void m94200_mxx (KERN_ATTR_RULES ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  /**
   * base
   */

  COPY_PW (pws[gid]);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    const u32 hash = MurmurHash3_Calc((u8*)tmp.i, tmp.pw_len, 0);

    const u32 r0 = hash;
    const u32 r1 = 0;
    const u32 r2 = 0;
    const u32 r3 = 0;

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m94200_sxx (KERN_ATTR_RULES ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET].digest_buf[DGST_R0],
    0,
    0,
    0
  };

  /**
   * base
   */

  COPY_PW (pws[gid]);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    const u32 hash = MurmurHash3_Calc((u8*)tmp.i, tmp.pw_len, 0);
    //printf("str: \"%s\", hash: %08X, search[0]: %X, search[1]: %X, search[2]: %X, search[3]: %X\n", (char*)tmp.i, hash, search[0], search[1], search[2], search[3]);

    const u32 r0 = hash;
    const u32 r1 = 0;
    const u32 r2 = 0;
    const u32 r3 = 0; 

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
