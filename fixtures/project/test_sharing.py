import unittest

from sharing import can_reshare


class ReshareTests(unittest.TestCase):
    def test_guest_cannot_reshare(self):
        self.assertFalse(can_reshare("guest"))

    def test_member_can_reshare(self):
        self.assertTrue(can_reshare("member"))


if __name__ == "__main__":
    unittest.main()
