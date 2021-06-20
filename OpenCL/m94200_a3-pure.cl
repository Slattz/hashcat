/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_simd.cl"
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

KERNEL_FQ void m94200_mxx (KERN_ATTR_VECTOR ())
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

  const u32 pw_len = pws[gid].pw_len;

  u32 w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  /**
   * loop
   */

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;
    //w[0] = w0;

    u32 hash = MurmurHash3_Calc((const u8*)w, pw_len, 0);

    const u32x r0 = hash;
    const u32x r1 = 0;
    const u32x r2 = 0;
    const u32x r3 = 0;

    COMPARE_M_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m94200_sxx (KERN_ATTR_VECTOR ())
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

  const u32 pw_len = pws[gid].pw_len;

  u32 w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  /**
   * loop
   */

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;
    w[0] = w0;
    //printf("str: %s, w0: %X\n", (char*)w, w0);

    u32 hash = MurmurHash3_Calc((const u8*)w, pw_len, 0);

    const u32x r0 = hash;
    const u32x r1 = 0;
    const u32x r2 = 0;
    const u32x r3 = 0;

    COMPARE_S_SIMD (r0, r1, r2, r3);
  }
}
