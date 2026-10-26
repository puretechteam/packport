"""Runs inside calibre's Python (``calibre-debug -e``), which bundles RARLAB's own unrar library
through ``unrardll``. Prints the headers unrar sees as JSON, then:

    extract ARCHIVE DEST     extract everything, checking each file's CRC
    verify ARCHIVE NAME CRC  have unrar read NAME and check its data against CRC (nothing written)
"""

import json
import sys

import unrardll

mode, archive = sys.argv[1], sys.argv[2]
headers = [{k: v for k, v in h.items() if isinstance(v, (str, int, bool))} for h in unrardll.headers(archive)]
if mode == "extract":
    unrardll.extract(archive, sys.argv[3], verify_data=True)
elif mode == "verify":
    unrardll.verify(archive, {sys.argv[3]: int(sys.argv[4])})
print(json.dumps({"version": unrardll.RARDLL_VERSION, "headers": headers}))
