import random

import pytest

from packport import (
    PackportError,
    ZCompressor,
    ZDecompressor,
    compress,
    decompress,
    write_z,
)


def text(n: int, seed: int = 1) -> bytes:
    rng = random.Random(seed)
    words = [bytes(rng.choice(b"abcdefghij") for _ in range(rng.randint(2, 8))) for _ in range(2000)]
    out = bytearray()
    while len(out) < n:
        out += rng.choice(words) + b" "
    return bytes(out[:n])


PAYLOADS = {
    "empty": b"",
    "one byte": b"A",
    "two bytes": b"AB",
    "repeat": b"ab" * 5000,
    "zeros": bytes(1_000_000),   # long dictionary strings
    "random": random.Random(3).randbytes(300_000),
    "text": text(600_000),
    "text, then noise, then text": text(400_000) + random.Random(4).randbytes(400_000) + text(400_000, 2),
}


@pytest.mark.parametrize("name", PAYLOADS)
def test_round_trip(name):
    data = PAYLOADS[name]
    z = compress(data)
    assert z[:3] == b"\x1f\x9d\x90"
    assert decompress(z) == data


def test_known_stream():
    # "ABABABA" is A, B, then code 257 ("AB") and 259 ("ABA"), 9 bits each, least significant bit first
    acc = sum(c << (9 * i) for i, c in enumerate([65, 66, 257, 259]))
    assert compress(b"ABABABA") == b"\x1f\x9d\x90" + acc.to_bytes(5, "little")


def test_dictionary_restarts_when_compression_drops():
    c = ZCompressor()
    data = PAYLOADS["text, then noise, then text"]
    z = c.compress(data) + c.flush()
    assert c.clears > 0
    assert decompress(z) == data


def test_code_width_grows_after_256_codes():
    # every pair of neighbours is new, so each byte is one code: 256 codes fit in 9 bits...
    assert len(compress(bytes(range(256)))) == 3 + 256 * 9 // 8
    # ...and the dictionary entry made after the 256th code needs 10 bits for what follows
    data = bytes(range(256)) + b"\x00\x02"
    assert len(compress(data)) == 3 + (256 * 9 + 2 * 10 + 7) // 8
    assert decompress(compress(data)) == data


@pytest.mark.parametrize("bits", [10, 12, 16])
def test_code_widths(bits):
    data = PAYLOADS["text"]
    z = compress(data, bits)
    assert z[2] == 0x80 | bits
    assert decompress(z) == data


def test_streaming_matches_one_shot():
    data = PAYLOADS["text, then noise, then text"]
    whole = compress(data)
    c = ZCompressor()
    rng = random.Random(5)
    parts, pos = [], 0
    while pos < len(data):
        n = rng.randint(0, 70_000)
        parts.append(c.compress(data[pos:pos + n]))
        pos += n
    parts.append(c.flush())
    assert b"".join(parts) == whole
    d = ZDecompressor()
    out, pos = [], 0
    while pos < len(whole):
        n = rng.randint(1, 5000)
        out.append(d.decompress(whole[pos:pos + n]))
        pos += n
    out.append(d.flush())
    assert b"".join(out) == data


def test_write_z_streams_files(tmp_path):
    src = tmp_path / "data.txt"
    src.write_bytes(PAYLOADS["text"] * 3)
    write_z(tmp_path / "data.txt.Z", src)
    assert decompress((tmp_path / "data.txt.Z").read_bytes()) == src.read_bytes()
    with pytest.raises(PackportError, match="single file"):
        write_z(tmp_path / "x.Z", tmp_path)


def test_max_size():
    z = compress(bytes(10_000_000))
    assert len(z) < 30_000
    with pytest.raises(PackportError, match="more than"):
        decompress(z, max_size=1_000_000)
    assert len(decompress(z, max_size=10_000_000)) == 10_000_000


def test_bad_streams():
    for bad in [b"", b"\x1f", b"\x1f\x8b\x08", b"\x1f\x9d\x91", b"\x1f\x9d\xe0", b"\x1f\x9d\x90\xff\xff"]:
        with pytest.raises(PackportError):
            decompress(bad)
    assert decompress(b"\x1f\x9d\x90") == b""
