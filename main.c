#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>


// basic operations
#define ROTL(x, n)	((x << n) | (x >> (sizeof(x)*8 - n)))
#define ROTR(x, n)	((x >> n) | (x << (sizeof(x)*8 - n)))

// SHA-224256 functions
#define Ch(x, y, z)		((x & y) ^ ((~x) & z))
#define Maj(x, y, z)	((x & y) ^ (x & z) ^ (y & z))
#define Epsilon_0(x)	(ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define Epsilon_1(x)	(ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define Sigma_0(x)		(ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3))
#define Sigma_1(x)		(ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10))


// SHA-224/256 constants
const uint32_t K[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

// SHA-256 initial hash value
const uint32_t H_0[8] = {
	0x6a09e667,
	0xbb67ae85,
	0x3c6ef372,
	0xa54ff53a,
	0x510e527f,
	0x9b05688c,
	0x1f83d9ab,
	0x5be0cd19,
};


void sha256_print_hash(uint32_t *H, const char *title) {
	printf("-----------------------------------------------------------------------------------------\n");
	printf("| %-85s |\n", title);
	printf("-----------------------------------------------------------------------------------------\n");
	printf("|   H[0]   |   H[1]   |   H[2]   |   H[3]   |   H[4]   |   H[5]   |   H[6]   |   H[7]   |\n");
	printf("| %08x | %08x | %08x | %08x | %08x | %08x | %08x | %08x |\n", H[0], H[1], H[2], H[3], H[4], H[5], H[6], H[7]);
	printf("-----------------------------------------------------------------------------------------\n");
}


// initialize hash value
void sha256_init(uint32_t *H) {
	H[0] = 0x6a09e667;
	H[1] = 0xbb67ae85;
	H[2] = 0x3c6ef372;
	H[3] = 0xa54ff53a;
	H[4] = 0x510e527f;
	H[5] = 0x9b05688c;
	H[6] = 0x1f83d9ab;
	H[7] = 0x5be0cd19;
}

// process block of data (M is in little endian !!!)
void sha256_process_block(uint32_t *H, unsigned char *m) {
	uint32_t a, b, c, d, e, f, g, h;
	uint32_t T1, T2;
	uint32_t W[64];
	
	unsigned int i;

	// prepare W
	for (i = 0; i < 16; i++) {
		W[i] = m[i*4 + 3] | (m[i*4 + 2] << 8) | (m[i*4 + 1] << 16) | (m[i*4 + 0] << 24);
	}
	for (i = 16; i < 64; i++) {
		W[i] = Sigma_1(W[i-2]) + W[i-7] + Sigma_0(W[i-15]) + W[i-16];
	}

	a = H[0];
	b = H[1];
	c = H[2];
	d = H[3];
	e = H[4];
	f = H[5];
	g = H[6];
	h = H[7];

	for (i = 0; i < 64; i++) {
		T1 = h + Epsilon_1(e) + Ch(e, f, g) + K[i] + W[i];
		T2 = Epsilon_0(a) + Maj(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;
	}

	// compute intermediate hash
	H[0] = a + H[0];
	H[1] = b + H[1];
	H[2] = c + H[2];
	H[3] = d + H[3];
	H[4] = e + H[4];
	H[5] = f + H[5];
	H[6] = g + H[6];
	H[7] = h + H[7];
}


int main(int argc, char **argv) {
	unsigned int i;

	// check arguments
	if (argc != 2) {
		printf("Usage: %s <input file>\n", argv[0]);
		return -1;
	}

	// open input file
	FILE *fp = fopen(argv[1], "r");
	if (!fp) {
		printf("Error opening file '%s' for reading.\n", argv[1]);
		return -1;
	}

	// initialize hash value
	uint32_t H[8];
	memcpy(H, H_0, 8*4);

	// read file and calculate hash
	uint64_t bits = 0;
	unsigned char buffer[64];
	size_t len;
	while (len = fread(buffer, 1, sizeof(buffer), fp)) {
		bits += len * 8;

		// preserve value of len by breaking on end of file (or error)
		if (len < 64) {
			break;
		}

		sha256_process_block(H, buffer);
	}

	// add padding
	if (len < 56) {
		// padd current block to 56 byte
		buffer[len] = 0x80;
		i = len + 1;
	} else {
		// fill up current block and update hash
		buffer[len] = 0x80;
		for (i = len + 1; i < 64; i++) {
			buffer[i] = 0x00;
		}
		sha256_process_block(H, buffer);

		// add (almost) one block of zero bytes
		i = 0;
	}
	for (; i < 56; i++) {
		buffer[i] = 0x00;
	}

	// add message length in bits in big endian
	for (i = 0; i < 8; i++) {
		buffer[63 - i] = bits >> (i * 8);
	}
	sha256_process_block(H, buffer);

	// print hash
	sha256_print_hash(H, "Final Hash");

	// convert hash to char array (in correct order)
	for (i = 0; i < 8; i++) {
		buffer[i*4 + 0] = H[i] >> 24;
		buffer[i*4 + 1] = H[i] >> 16;
		buffer[i*4 + 2] = H[i] >>  8;
		buffer[i*4 + 3] = H[i];
	}

	// print hash
	printf("Hash:\t");
	for (i = 0; i < 32; i++) {
		printf("%02x", buffer[i]);
	}
	printf("\n");

	return 0;
}

