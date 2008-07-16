#ifndef _SPEED_TEST_
#define _SPEED_TEST_

#pragma pack (push, 1)

typedef struct _speed_test {
	u32 data_size;
	u64 enc_time;
	u64 dec_time;
	u64 cpu_freq;

} speed_test;

#pragma pack (pop)

int dc_k_speed_test(speed_test *test);

#endif