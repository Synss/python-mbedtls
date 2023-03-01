# SPDX-License-Identifier: MIT
# Copyright (c) 2018, Mathias Laurin

cdef extern from "mbedtls/timing.h" nogil:
    # This provides callbacks for DTLS with blocking IO.

    ctypedef struct mbedtls_timing_hr_time:
        pass

    ctypedef struct mbedtls_timing_delay_context:
        mbedtls_timing_hr_time timer
        int int_ms
        int fin_ms

    # extern volatile int mbedtls_timing_alarmed

    # unsigned long mbedtls_timing_hardclock()
    # unsigned long mbedtls_timing_get_timer(
    #     mbedtls_timing_hr_time *,
    #     int reset,
    # )
    # void mbedtls_set_alarm(int seconds)

    # mbedtls_ssl_set_timer_t callback
    void mbedtls_timing_set_delay(void *data, int int_ms, int fin_ms)
    # mbedtls_ssl_get_timer_t callback
    int mbedtls_timing_get_delay(void *data)
