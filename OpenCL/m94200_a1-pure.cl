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
#include "inc_scalar.cl"
#endif

#define READU32(addr) *(u32 *)(addr)

inline u32 Murmur32_Scramble(u32 k) {
    k = (k * 0x16A88000) | ((k * 0xCC9E2D51) >> 17);
    return (k * 0x1B873593);
}

DECLSPEC u32 MurmurHash3_Calc(GLOBAL_AS const u8* data, const u32 size, const u32 seed) {
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

KERNEL_FQ void m94200_mxx (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    /**
     * concat password candidate
     */

    const u32 pw_len = (pws[gid].pw_len + combs_buf[il_pos].pw_len) & 255;

    u8 pword[256] = { 0 };
    const u8* buf1;
    const u8* buf2;
    u32 len1;

    if (combs_mode == COMBINATOR_MODE_BASE_LEFT) {
      buf1 = (u8*)pws[gid].i;
      buf2 = (u8*)combs_buf[il_pos].i;
      len1 = pws[gid].pw_len;
    }
    else {
      buf1 = (u8*)combs_buf[il_pos].i;
      buf2 = (u8*)pws[gid].i;
      len1 = combs_buf[il_pos].pw_len;
    }

    u32 i;
    for (i = 0; i < len1; i++) {
      pword[i] = buf1[i];
    }
    for (u32 j = 0; j < (pw_len - len1); j++) {
      pword[i+j] = buf2[i];
    }

    u32 hash = MurmurHash3_Calc(pword, pw_len, 0);

    const u32x r0 = hash;
    const u32x r1 = 0;
    const u32x r2 = 0;
    const u32x r3 = 0;

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m94200_sxx (KERN_ATTR_BASIC ())
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
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    /**
     * concat password candidate
     */

    const u32 pw_len = (pws[gid].pw_len + combs_buf[il_pos].pw_len) & 255;

    u8 pword[256] = { 0 };
    const u8* buf1;
    const u8* buf2;
    u32 len1;

    if (combs_mode == COMBINATOR_MODE_BASE_LEFT) {
      buf1 = (u8*)pws[gid].i;
      buf2 = (u8*)combs_buf[il_pos].i;
      len1 = pws[gid].pw_len;
    }
    else {
      buf1 = (u8*)combs_buf[il_pos].i;
      buf2 = (u8*)pws[gid].i;
      len1 = combs_buf[il_pos].pw_len;
    }

    u32 i;
    for (i = 0; i < len1; i++) {
      pword[i] = buf1[i];
    }

    for (u32 j = 0; j < (pw_len - len1); j++) {
      pword[i+j] = buf2[j];
    }

    u32 hash = MurmurHash3_Calc(pword, pw_len, 0);

    const u32x r0 = hash;
    const u32x r1 = 0;
    const u32x r2 = 0;
    const u32x r3 = 0;

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
