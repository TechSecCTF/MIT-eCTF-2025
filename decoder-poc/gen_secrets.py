import json
import sys
from pathlib import Path

def gen_int_arr(a):
    return "{ " + ", ".join(map(hex, a)) + " }"

with open(sys.argv[1], "r") as f:
    secrets = json.load(f)

channels = secrets["channels"]

secrets_h = f"""
extern int channels[{len(channels)}];
"""

secrets_c = f"""
#include "secrets.h"

int channels[{len(channels)}] = {gen_int_arr(channels)};
"""

src = Path(__file__).parent / "src"

with open(src / "secrets.h", "w") as f:
    f.write(secrets_h)

with open(src / "secrets.c", "w") as f:
    f.write(secrets_c)
