# This file is editable for custom configurations

TIME_OUT_MILLI_SEC = 5
WAITING_RESPONSES_GC_SECS = TIME_OUT_MILLI_SEC*2
PING_WINDOW = 17
PING_MILLI_SEC_REDUNDANCIES = [
    (20, 2),
    (80, 4),
    (150, 8),
    (1000, 10),
]
PING_CALC_TRIM_RATIO = 0.12