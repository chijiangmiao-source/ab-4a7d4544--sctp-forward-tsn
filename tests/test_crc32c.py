import unittest

from app.crc32c import crc32c


class Crc32cTest(unittest.TestCase):
    def test_standard_vector(self):
        # CRC-32C("123456789") 的标准校验值
        self.assertEqual(crc32c(b"123456789"), 0xE3069283)

    def test_incremental(self):
        self.assertEqual(crc32c(b"123456789"),
                         crc32c(b"456789", crc32c(b"123")))

    def test_empty(self):
        self.assertEqual(crc32c(b""), 0x00000000)


if __name__ == "__main__":
    unittest.main()
