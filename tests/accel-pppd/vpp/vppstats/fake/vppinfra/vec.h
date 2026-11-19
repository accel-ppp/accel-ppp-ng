/* The part of the VPP vector API that vppstats.c uses, for tests without VPP */
#ifndef FAKE_VEC_H
#define FAKE_VEC_H
#include <stdint.h>

typedef uint8_t u8;
typedef uint32_t u32;

void *fake_vec_grow(void *v, unsigned elem);
unsigned fake_vec_len(void *v);
void fake_vec_free(void *v);

#define vec_len(V) ((V) ? fake_vec_len(V) : 0)
#define vec_free(V)                                                                                                    \
	do {                                                                                                           \
		fake_vec_free(V);                                                                                      \
		(V) = 0;                                                                                               \
	} while (0)
#define vec_add1(V, E)                                                                                                 \
	do {                                                                                                           \
		(V) = fake_vec_grow((V), sizeof(*(V)));                                                                \
		(V)[fake_vec_len(V) - 1] = (E);                                                                        \
	} while (0)

#endif
