#!/usr/bin/env python3
"""Offline reconstruction of the observed ZDF02.07 literal-block package variant.
Never executes package scripts, writes devices, or invokes a firmware updater.
Unsupported record layouts fail closed; this is not a general ZDF decoder.
"""
import argparse
import gzip
import hashlib
import json
import lzma
import struct
import zlib
from pathlib import Path


def require(condition, message):
    if not condition:
        raise ValueError(message)


def reconstruct(chunk):
    require(chunk[:8] == b'ZDF02.07' and chunk[16:24] == b'NORMDIFF', 'Unsupported ZDF header')
    require(struct.unpack_from('<Q', chunk, 32)[0] == len(chunk), 'Member length mismatch')
    require(struct.unpack_from('<Q', chunk, 40)[0] == 80 and chunk[80:84] == b'ZDFU', 'Unsupported inner header')
    require(zlib.crc32(chunk[80:120]) == struct.unpack_from('>I', chunk, 120)[0], 'Inner header CRC mismatch')
    require(zlib.crc32(chunk[124:]) == struct.unpack_from('>I', chunk, 116)[0], 'Compressed stream CRC mismatch')
    target_size = struct.unpack_from('<Q', chunk, 72)[0]
    table_size = struct.unpack_from('>I', chunk, 92)[0]
    declared_decoded = struct.unpack_from('>I', chunk, 108)[0]
    require(0 < target_size <= 2**31 and table_size % 28 == 0, 'Invalid target/table size')
    props = chunk[124]
    lc, rem = props % 9, props // 9
    lp, pb = rem % 5, rem // 5
    dictionary = struct.unpack_from('<I', chunk, 125)[0]
    require(pb <= 4 and dictionary <= 64*1024*1024, 'Unsupported LZMA properties')
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=[dict(id=lzma.FILTER_LZMA1, dict_size=dictionary, lc=lc, lp=lp, pb=pb)])
    decoded = decoder.decompress(chunk[129:], max_length=declared_decoded+2)
    # The observed streams have no end marker; some emit one trailing zero pad byte.
    require(len(decoded) == declared_decoded or
            (len(decoded) == declared_decoded+1 and decoded[-1:] == b'\0'), 'Decoded length mismatch')
    decoded = decoded[:declared_decoded]
    position = table_size
    output = bytearray()
    previous_length = 0
    for index in range(table_size // 28):
        flags, stride, length, reserved, crc, block_index, count = struct.unpack_from('>7I', decoded, index*28)
        require(flags == 65536 and reserved == 0 and block_index == index and count == 1, 'Unsupported block table')
        require(stride == previous_length, 'Unsupported block stride')
        previous_length = length
        require(0 < length <= 131072, 'Unsupported block size')
        one, zero1, zero2, instruction_size, literal_size = struct.unpack_from('>5I', decoded, position)
        require((one, zero1, zero2) == (1, 0, 0) and literal_size == length, 'Unsupported literal record')
        require(instruction_size in (2,3,4), 'Unsupported literal instruction length')
        start = position + 20 + instruction_size + 1
        block = decoded[start:start+length]
        require(len(block) == length and zlib.crc32(block) == crc, f'Block {index} CRC mismatch')
        output.extend(block)
        position = start + length
    require(position == len(decoded), 'Unconsumed decoded bytes')
    require(len(output) == target_size, 'Target size mismatch')
    return output, table_size // 28


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('package', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    package = args.package.read_bytes()
    require(package[:4] == bytes.fromhex('8855aa55'), 'Unsupported package')
    members = struct.unpack_from('<I', package, 4)[0]
    require(0 < members <= 256, 'Invalid member count')
    args.output.mkdir(parents=True, exist_ok=True)
    manifest = dict(source_sha256=hashlib.sha256(package).hexdigest(), kind='Stock B31 reconstructed partition payloads; not a flashable package', images=[])
    for index in range(members):
        name, size, offset = struct.unpack_from('<32sII', package, 16+index*40)
        name = name.split(b'\0')[0].decode('ascii')
        require(offset >= 16+40*members and offset+size <= len(package), 'Invalid member bounds')
        chunk = package[offset:offset+size]
        if not chunk.startswith(b'ZDF02.07'):
            continue
        require(name.endswith('.mld') and '/' not in name and '..' not in name, 'Unsafe member name')
        print('Reconstructing', name, flush=True)
        raw, blocks = reconstruct(chunk)
        filename = name[:-4]+'.img.gz'
        target = args.output/filename
        partial = args.output/(filename+'.partial')
        with partial.open('wb') as stream, gzip.GzipFile(filename='', mode='wb', fileobj=stream, compresslevel=1, mtime=0) as gz:
            gz.write(raw)
        partial.replace(target)
        item = dict(file=filename, source_member=name, raw_bytes=len(raw), raw_sha256=hashlib.sha256(raw).hexdigest(), validated_block_crcs=blocks, compressed_sha256=hashlib.sha256(target.read_bytes()).hexdigest())
        manifest['images'].append(item)
        (args.output/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
        print('Verified', name, len(raw), 'bytes;', blocks, 'block CRCs', flush=True)
    print('Completed', len(manifest['images']), 'partition payloads', flush=True)

if __name__ == '__main__':
    main()
