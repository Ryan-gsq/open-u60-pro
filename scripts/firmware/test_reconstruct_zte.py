"""Decoder checks against a small member of the archived official package."""
import struct
import unittest
from pathlib import Path
from reconstruct_zte import reconstruct

class DecoderChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        package = Path('firmware/official/CN_ZTE_MU5250V1.0.0B31/firmware.bin').read_bytes()
        for i in range(struct.unpack_from('<I', package, 4)[0]):
            name, size, offset = struct.unpack_from('<32sII', package, 16+40*i)
            if name.split(b'\0')[0] == b'apdp.mld':
                cls.member = package[offset:offset+size]
                return
        raise AssertionError('Fixture member missing')

    def test_valid_literal_payload(self):
        raw, count = reconstruct(self.member)
        self.assertEqual(len(raw), 12088)
        self.assertEqual(raw[:4], b'\x7fELF')
        self.assertEqual(count, 1)

    def test_reject_corrupt_compressed_stream(self):
        chunk = bytearray(self.member)
        chunk[-1] ^= 1
        with self.assertRaisesRegex(ValueError, 'Compressed stream CRC'):
            reconstruct(chunk)

    def test_reject_corrupt_header(self):
        chunk = bytearray(self.member)
        chunk[100] ^= 1
        with self.assertRaisesRegex(ValueError, 'Inner header CRC'):
            reconstruct(chunk)

    def test_reject_truncation(self):
        with self.assertRaisesRegex(ValueError, 'Member length'):
            reconstruct(self.member[:-1])

if __name__ == '__main__':
    unittest.main()
