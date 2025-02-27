import struct

from ectf25_design import cryptosystem
from ectf25_design import gen_subscription


def main():
  with open("secrets.json", "r") as f:
    secrets = cryptosystem.Secrets.parse(f.read())
  
  channel = 1
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
