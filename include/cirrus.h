#pragma once

#ifdef __cplusplus
extern "C" {
#endif

void clgd54xx_init(void);

// Modeset API (best-effort). Returns 0 on success, negative on failure.
int clgd54xx_set_mode(unsigned int width, unsigned int height, unsigned int bpp);
int clgd54xx_set_best_mode(void); // pick highest from built-in table that is likely to work

#ifdef __cplusplus
}
#endif


