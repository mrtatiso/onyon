import os
import secrets
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import onyon  # noqa: E402

SYVOX = "67137111632918228090.03198478452534193697.85614958450118272798.55305506750949179189"
REAL = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"


def band():
    n = str(secrets.randbelow(10 ** 80)).zfill(80)
    return ".".join(n[i:i + 20] for i in range(0, 80, 20))


def random_onion():
    return onyon.address(onyon._encode(onyon._mul(secrets.randbelow(onyon.L - 1) + 1, onyon.B)))


class TestOnion(unittest.TestCase):
    def test_parses_real_onion(self):
        self.assertEqual(onyon.address(onyon._encode(onyon.parse(REAL))), REAL)

    def test_rejects_bad_onions(self):
        bad = REAL[:10] + ("a" if REAL[10] != "a" else "b") + REAL[11:]
        for s in (bad, "abc.onion", REAL.replace("d.onion", "e.onion"), ""):
            with self.assertRaises(ValueError):
                onyon.parse(s)


class TestOnyon(unittest.TestCase):
    def test_roundtrip(self):
        for _ in range(5):
            s, o = band(), random_onion()
            self.assertEqual(onyon.open_(s, onyon.seal(s, o)), o)

    def test_fixed_answer(self):
        # v1 must always give this: any implementation, any language
        self.assertEqual(onyon.seal(SYVOX, REAL), FIXED)

    def test_every_syvox_gives_valid_distinct_onion(self):
        stored = onyon.seal(SYVOX, REAL)
        outs = {onyon.open_(band(), stored) for _ in range(12)}
        for o in outs:
            onyon.parse(o)
        self.assertEqual(len(outs), 12)
        self.assertNotIn(REAL, outs)

    def test_grouping_does_not_matter(self):
        s810 = ".".join(SYVOX.replace(".", "")[i:i + 10] for i in range(0, 80, 10))
        self.assertEqual(onyon.seal(SYVOX, REAL), onyon.seal(s810, REAL))

    def test_bad_syvox(self):
        with self.assertRaises(ValueError):
            onyon.seal("123", REAL)


FIXED = "kpxhhvfuuinz7yhmkvz27fctc2lpjvrhhch2kcg2umfvkf7odej2mdad.onion"

if __name__ == "__main__":
    unittest.main()
