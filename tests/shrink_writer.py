"""A Shrink (ZIP method 1) encoder, for tests only: the one Shrink archive on hand holds two
80-byte files, which never widen their codes or clear the table, so make_7z_zip.py writes a big
one with this and 7-Zip has to read it back.

It keeps its table exactly as a decoder does: a new string is added when the next code is sent
(the last code plus the first byte of the new one), at the lowest free code above 256. When no
code is free it sends 256, 2 and frees the codes nothing builds on, as the decoder will."""

TOP = 1 << 13


def shrink(data: bytes) -> bytes:
    prefix = [-1] * TOP
    char = list(range(256)) + [0] * (TOP - 256)
    used = [True] * 256 + [False] * (TOP - 256)
    child: dict[tuple[int, int], int] = {}
    width, nxt, prev = 9, 257, -1
    out, acc, n = bytearray(), 0, 0

    def emit(code: int) -> None:
        nonlocal acc, n
        acc |= code << n
        n += width
        while n >= 8:
            out.append(acc & 0xFF)
            acc >>= 8
            n -= 8

    def add(p: int, c: int) -> None:
        nonlocal nxt
        while nxt < TOP and used[nxt]:
            nxt += 1
        if nxt < TOP:
            prefix[nxt], char[nxt], used[nxt] = p, c, True
            child.setdefault((p, c), nxt)  # a freed prefix code can be reused: a pair can repeat

    def clear() -> None:
        nonlocal nxt
        parent = [False] * TOP
        for i in range(257, TOP):
            if used[i]:
                parent[prefix[i]] = True
        for i in range(257, TOP):
            if not parent[i] and used[i]:
                if child.get((prefix[i], char[i])) == i:
                    del child[(prefix[i], char[i])]
                used[i], prefix[i] = False, -1
        nxt = 257

    i = 0
    while i < len(data):
        code, j = data[i], i + 1
        while j < len(data) and (code, data[j]) in child:
            code = child[(code, data[j])]
            j += 1
        while code >= 1 << width:
            emit(256)
            emit(1)
            width += 1
        emit(code)
        if prev >= 0:
            add(prev, data[i])
        prev, i = code, j
        while nxt < TOP and used[nxt]:
            nxt += 1
        if nxt >= TOP:
            emit(256)
            emit(2)
            clear()
    if n:
        out.append(acc & 0xFF)
    return bytes(out)
