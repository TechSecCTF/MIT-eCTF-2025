import struct
import sys

from ectf25_design import cryptosystem
from ectf25_design import gen_subscription


def main():
  if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <channel>", file=sys.stderr)
    sys.exit(1)
  
  channel = int(sys.argv[1])

  with open("secrets.json", "r") as f:
    secrets = cryptosystem.Secrets.parse(f.read())
  
  tree = secrets.get_tree(channel)
  start = 0
  end = 5
  subtree = tree.minimal_tree(start, end)

  subscription = subtree.get_subscription()
  subscription = struct.pack("<IQQ", channel, start, end) + subscription

  print("subscription:")
  print(subscription.hex())
  print("key for frame 0:")
  print(subtree.frame_key(0).hex())

if __name__ == "__main__":
  main()
