#!/usr/bin/python
import atheris
import numpy as np
from regress_exponential import get_coeffs
from fuzzhelper import cleanstring

with atheris.instrument_imports():
    import regex
    import sys

MAXLEN = 28000
MYREGEX = regex.compile(r".*,.*,.*\(.*:.*:.*\)")


@atheris.instrument_func
def get_trend(x_values, y_values, point):
    if not isinstance(x_values, np.ndarray):
        x_values = np.array(x_values)
    if not isinstance(y_values, np.ndarray):
        y_values = np.array(y_values)
    # fit lin/quad/cubic
    poly_coeffs1 = np.polyfit(x_values, y_values, 1)
    poly_coeffs2 = np.polyfit(x_values, y_values, 2)
    poly_coeffs3 = np.polyfit(x_values, y_values, 3)
    if poly_coeffs1[0] < 0:
        poly_coeffs1[0] = 0
    if poly_coeffs2[0] < 0:
        poly_coeffs2 = [0] + poly_coeffs1
    if poly_coeffs3[0] < 0:
        poly_coeffs3 = [0] + poly_coeffs2
    y_poly1 = np.polyval(poly_coeffs1, x_values)
    y_poly2 = np.polyval(poly_coeffs2, x_values)
    y_poly3 = np.polyval(poly_coeffs3, x_values)
    ssq_poly1 = np.sum((y_poly1 - y_values) ** 2)
    ssq_poly2 = np.sum((y_poly2 - y_values) ** 2)
    ssq_poly3 = np.sum((y_poly3 - y_values) ** 2)
    # fit exp
    e_a, e_b, e_c = get_coeffs(x_values, y_values)
    e_c = min(3, e_c)
    y_exp = e_a + np.exp(e_b * x_values) * e_c
    ssq_exp = np.sum((y_values - y_exp) ** 2)
    if ssq_exp < ssq_poly1 and ssq_exp < ssq_poly2 and ssq_exp < ssq_poly3:
        estimate = e_a + np.exp(e_b * point) * e_c
        trend_type = 0
    else:
        trend_type = np.argmin([ssq_poly1, ssq_poly2, ssq_poly3])
        estimate = np.polyval([poly_coeffs1, poly_coeffs2, poly_coeffs3][trend_type], point)
        trend_type += 1
    return np.log(estimate), trend_type


@atheris.instrument_func
def runbench(lhs: str, mid: str, rhs: str):
    maxpump = (MAXLEN - (len(lhs) + len(rhs))) // len(mid)
    if maxpump < 40:
        return -1
    x_values = np.array(range(1, 40))
    y_values = []
    for pump in x_values:
        string = lhs + mid * pump + rhs
        y_values.append(MYREGEX.scanner(string).bench()[-1])
    estimate, tt = get_trend(x_values, y_values, maxpump)
    if estimate >= 32:
        raise ValueError(f"BOOM! <{estimate}> [[[{lhs!r}][{mid!r}][{rhs!r}]]] <trend:{['exp', 'lin', 'sqr', 'cub'][tt]}> !BOOM")
    # rolled for loop doesn't work properly with atheris because it's not considered as indivudual branches
    if estimate >= (31): return estimate  # noqa: E701
    if estimate >= (30): return estimate  # noqa: E701
    if estimate >= (29): return estimate  # noqa: E701
    if estimate >= (28): return estimate  # noqa: E701
    if estimate >= (27): return estimate  # noqa: E701
    if estimate >= (26): return estimate  # noqa: E701
    if estimate >= (25): return estimate  # noqa: E701
    if estimate >= (24): return estimate  # noqa: E701
    if estimate >= (23): return estimate  # noqa: E701
    if estimate >= (22): return estimate  # noqa: E701
    if estimate >= (21): return estimate  # noqa: E701
    if estimate >= (20): return estimate  # noqa: E701
    if estimate >= (19): return estimate  # noqa: E701
    if estimate >= (18): return estimate  # noqa: E701
    if estimate >= (17): return estimate  # noqa: E701
    if estimate >= (16): return estimate  # noqa: E701
    if estimate >= (15): return estimate  # noqa: E701
    if estimate >= (14): return estimate  # noqa: E701
    if estimate >= (13): return estimate  # noqa: E701
    if estimate >= (12): return estimate  # noqa: E701
    if estimate >= (11): return estimate  # noqa: E701
    if estimate >= (10): return estimate  # noqa: E701
    if estimate >= (9): return estimate  # noqa: E701
    if estimate >= (8): return estimate  # noqa: E701
    if estimate >= (7): return estimate  # noqa: E701
    if estimate >= (6): return estimate  # noqa: E701
    if estimate >= (5): return estimate  # noqa: E701
    if estimate >= (4): return estimate  # noqa: E701
    if estimate >= (3): return estimate  # noqa: E701
    if estimate >= (2): return estimate  # noqa: E701
    if estimate >= (1): return estimate  # noqa: E701


@atheris.instrument_func
def test_all_watched_keywords(data: bytes):
    # Check each REGEX one by one, recording how long data takes
    # find out which took the longest, and print it

    if len(data) < 8:
        return

    fdp = atheris.FuzzedDataProvider(data)

    split1 = fdp.ConsumeUInt(2)
    split2 = fdp.ConsumeUInt(2)

    string = cleanstring(fdp.ConsumeUnicodeNoSurrogates(MAXLEN))

    mystringlen = len(string)

    if mystringlen < 3:
        return

    split1 %= (mystringlen + 1)

    split2 %= mystringlen

    split2 = (split1 + split2 + 1) % (mystringlen + 1)

    if split2 < split1:
        split2, split1 = split1, split2

    string_args = string[:split1], string[split1:split2], string[split2:]

    runbench(*string_args)


if __name__ == '__main__':
    atheris.Setup(sys.argv, test_all_watched_keywords)
    atheris.Fuzz()
