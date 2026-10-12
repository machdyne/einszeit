/*
 * ez_entropy.c -- see ez_entropy.h. SEC-ENTROPY-002, SEC-ENTROPY-004, §2.3.
 */
#include "ez_entropy.h"

#include <string.h>

#include "ez_secure.h"

/* ===================================================================== */
/* Online monitor                                                        */
/* ===================================================================== */

#define MON_HALF        2048u
#define MON_TOL         200u
#define MON_LONGEST     44u
#define MON_LAGS        16

void ez_mon_init(ez_monitor_t *m) { memset(m, 0, sizeof *m); }

void ez_mon_clear(ez_monitor_t *m) { ez_secure_zero(m, sizeof *m); }

static uint32_t absdiff(uint32_t a, uint32_t b) { return a > b ? a - b : b - a; }

static void mon_window_end(ez_monitor_t *m)
{
	if (absdiff(m->ones, MON_HALF) > MON_TOL)
		m->fail |= EZ_EF_MON_MONOBIT;
	/* runs*2 vs n+1 (expected 2048.5), compared doubled to stay integral */
	if (absdiff(2u * m->runs, EZ_MON_WINDOW_BITS + 1u) > 2u * MON_TOL ||
	    m->longest >= MON_LONGEST)
		m->fail |= EZ_EF_MON_RUNS;
	for (int l = 0; l < MON_LAGS; l++)
		if (absdiff(2u * m->agree[l], m->pairs[l]) > 2u * MON_TOL)
			m->fail |= EZ_EF_MON_AUTOCORR;
	m->windows++;
	m->bits = m->ones = m->runs = 0;
	m->longest = m->run_len;     /* a run may continue into the next window */
	memset(m->agree, 0, sizeof m->agree);
	memset(m->pairs, 0, sizeof m->pairs);
}

uint8_t ez_mon_feed(ez_monitor_t *m, const uint8_t *p, uint32_t n)
{
	for (uint32_t i = 0; i < n; i++) {
		for (int k = 7; k >= 0; k--) {
			uint32_t b = (p[i] >> k) & 1u;
			m->ones += b;
			bool change = m->total_bits == 0 || b != (m->hist & 1u);
			m->run_len = change ? 1u : m->run_len + 1u;
			if (change || m->bits == 0)
				m->runs++;               /* runs are counted within the window */
			if (m->run_len > m->longest) m->longest = m->run_len;
			for (int l = 0; l < MON_LAGS; l++) {
				if (m->total_bits > (uint32_t)l) {
					m->pairs[l]++;
					m->agree[l] += (((uint32_t)m->hist >> l) & 1u) == b ? 1u : 0u;
				}
			}
			m->hist = (uint16_t)(((uint32_t)m->hist << 1) | b);
			m->total_bits++;
			if (++m->bits == EZ_MON_WINDOW_BITS)
				mon_window_end(m);
		}
	}
	return m->fail;
}

/* ===================================================================== */
/* Acceptance tests                                                      */
/* ===================================================================== */

/* lam_max[k-1] = largest Poisson mean (x 1e9) for which P(X >= k) <= 1e-9.
 * Computed with scipy.stats.poisson (see docs/einszeit-entropy-thresholds.md). */
static const uint64_t lam_max_nano[64] = {
	1ull, 44722ull, 1817946ull, 12477753ull,
	41576137ull, 95977984ull, 179023812ull, 291565708ull,
	433032058ull, 602134838ull, 797279717ull, 1016789172ull,
	1259018035ull, 1522409365ull, 1805517893ull, 2107016185ull,
	2425691920ull, 2760440872ull, 3110258115ull, 3474228809ull,
	3851519246ull, 4241368505ull, 4643080852ull, 5056018906ull,
	5479597546ull, 5913278513ull, 6356565622ull, 6809000541ull,
	7270159047ull, 7739647727ull, 8217101045ull, 8702178747ull,
	9194563555ull, 9693959108ull, 10200088135ull, 10712690817ull,
	11231523319ull, 11756356474ull, 12286974604ull, 12823174448ull,
	13364764206ull, 13911562665ull, 14463398412ull, 15020109117ull,
	15581540884ull, 16147547655ull, 16717990671ull, 17292737977ull,
	17871663966ull, 18454648968ull, 19041578867ull, 19632344748ull,
	20226842577ull, 20824972899ull, 21426640567ull, 22031754487ull,
	22640227377ull, 23251975556ull, 23866918737ull, 24484979837ull,
	25106084806ull, 25730162462ull, 26357144339ull, 26986964542ull,};

uint32_t ez_acc_reject_threshold(uint32_t blocks, uint32_t ppm)
{
	uint64_t lam = (uint64_t)blocks * ppm * 1000u;     /* x 1e9 */
	for (uint32_t k = 1; k <= 64; k++)
		if (lam <= lam_max_nano[k - 1])
			return k;
	/* Beyond the table: callers limit key size so this is unreachable
	 * (EZ_KEYGEN_MAX_LEN). Fail safe: never accept on this path. */
	return 0;
}

static const uint32_t runs_lo[6] = { 2315, 1114, 527, 240, 103, 103 };
static const uint32_t runs_hi[6] = { 2685, 1386, 723, 384, 209, 209 };

void ez_acc_init(ez_accept_t *a)
{
	memset(a, 0, sizeof *a);
	a->cur = -1;
}

static void acc_end_run(ez_accept_t *a)
{
	if (a->cur < 0) return;
	uint32_t l = a->run_len >= 6 ? 5 : a->run_len - 1;
	a->runs[a->cur][l]++;
	if (a->run_len >= 26) a->longrun = true;
}

static void acc_block_end(ez_accept_t *a)
{
	acc_end_run(a);
	/* FIPS 140-2 §4.9.1: pass iff 9725 < X < 10275 */
	if (a->ones <= 9725u || a->ones >= 10275u) a->fails[0]++;
	/* poker: X = 16/5000 * sum(f^2) - 5000; pass iff 2.16 < X < 46.17,
	 * i.e. 10800 < 16*sum(f^2) - 25,000,000 < 230850 */
	uint64_t s = 0;
	for (int i = 0; i < 16; i++) s += (uint64_t)a->nib[i] * a->nib[i];
	int64_t x = (int64_t)(16u * s) - 25000000;
	if (x <= 10800 || x >= 230850) a->fails[1]++;
	bool rf = false;
	for (int v = 0; v < 2; v++)
		for (int i = 0; i < 6; i++)
			if (a->runs[v][i] < runs_lo[i] || a->runs[v][i] > runs_hi[i]) rf = true;
	if (rf) a->fails[2]++;
	if (a->longrun) a->fails[3]++;
	a->blocks++;
	a->bits = a->ones = 0;
	memset(a->nib, 0, sizeof a->nib);
	a->nibv = a->nibn = 0;
	a->cur = -1;
	a->run_len = 0;
	memset(a->runs, 0, sizeof a->runs);
	a->longrun = false;
}

void ez_acc_feed(ez_accept_t *a, const uint8_t *p, uint32_t n)
{
	for (uint32_t i = 0; i < n; i++) {
		a->bytefreq[p[i]]++;
		for (int k = 7; k >= 0; k--) {
			uint32_t b = (p[i] >> k) & 1u;
			a->ones += b;
			a->total_ones += b;
			a->total_bits++;
			a->nibv = (uint8_t)(((uint32_t)a->nibv << 1) | b);
			if (++a->nibn == 4) {
				a->nib[a->nibv & 0xF]++;
				a->nibv = a->nibn = 0;
			}
			if ((int)b != a->cur) {
				acc_end_run(a);
				a->cur = (int)b;
				a->run_len = 1;
			} else {
				a->run_len++;
			}
			if (++a->bits == EZ_FIPS_BLOCK_BITS)
				acc_block_end(a);
		}
	}
}

static uint64_t isqrt64(uint64_t v)
{
	uint64_t r = 0, bit = (uint64_t)1 << 62;
	while (bit > v) bit >>= 2;
	while (bit) {
		if (v >= r + bit) { v -= r + bit; r = (r >> 1) + bit; }
		else r >>= 1;
		bit >>= 2;
	}
	return r;
}

uint8_t ez_acc_finish(ez_accept_t *a)
{
	uint8_t f = 0;
	static const uint32_t ppm[4] = { EZ_FIPS_PPM_MONOBIT, EZ_FIPS_PPM_POKER,
	                                 EZ_FIPS_PPM_RUNS, EZ_FIPS_PPM_LONGRUN };
	static const uint8_t bit[4] = { EZ_EF_ACC_MONOBIT, EZ_EF_ACC_POKER,
	                                EZ_EF_ACC_RUNS, EZ_EF_ACC_RUNS };
	for (int t = 0; t < 4; t++) {
		uint32_t thr = ez_acc_reject_threshold(a->blocks, ppm[t]);
		if (thr == 0 || a->fails[t] >= thr) f |= bit[t];
	}
	/* Whole-key monobit: |2*ones - n| <= 7*sqrt(n) */
	uint64_t n = a->total_bits, two = 2u * a->total_ones;
	uint64_t d = two > n ? two - n : n - two;
	if (n == 0 || d > 7u * isqrt64(n) + 7u) f |= EZ_EF_ACC_WHOLE;
	/* Byte-frequency chi-square, only where every cell expects >= 5.
	 * With N bytes and counts c_i, e = N/256 and
	 *     chi2 = sum((c_i - e)^2) / e = sum((256 c_i - N)^2) / (256 N),
	 * so the bounds are compared exactly in integers. */
	uint64_t nbytes = n / 8;
	if (nbytes >= 1280u) {
		uint64_t hi = 426u * 256u * nbytes, lo = 136u * 256u * nbytes, s = 0;
		bool over = false;
		for (int i = 0; i < 256; i++) {
			uint64_t c = (uint64_t)a->bytefreq[i] * 256u;
			uint64_t dd = c > nbytes ? c - nbytes : nbytes - c;
			if (dd > ((uint64_t)1 << 31)) { over = true; break; }   /* saturate */
			s += dd * dd;
			if (s >= hi) { over = true; break; }
		}
		if (over || s <= lo) f |= EZ_EF_ACC_WHOLE;
	}
	ez_secure_zero(a, sizeof *a);
	return f;
}
