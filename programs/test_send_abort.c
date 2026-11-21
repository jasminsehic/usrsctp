#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

/*
 * Copyright (C) 2026 Jasmin Sehic
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.      IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdint.h>
#include <stdio.h>
#include <usrsctp.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <time.h>
#endif

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
extern int sctp_test_abort_next_send;
extern int sctp_test_abort_reached;

int
main(void)
{
	/* Initiate a connection, complete the handshake, and send user data. */
	static const uint8_t input[] = {0x07, 0, 0, 0, 0};
	unsigned int i;

	sctp_test_abort_next_send = 1;
	LLVMFuzzerTestOneInput(input, sizeof(input));
	if (!sctp_test_abort_reached) {
		fprintf(stderr, "The pending-send abort path was not exercised\n");
		return 1;
	}

	usrsctp_deregister_address((void *)1);
	for (i = 0; i < 3000; i++) {
		if (usrsctp_finish() == 0)
			return 0;
#ifdef _WIN32
		Sleep(10);
#else
		const struct timespec pause = {0, 10000000};
		nanosleep(&pause, NULL);
#endif
	}

	fprintf(stderr, "SCTP cleanup timed out\n");
	return 1;
}
