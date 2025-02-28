#!/usr/bin/env python3

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import builtins
import hashlib
import os
import json
import random
import struct
import sys
import time

ENCRYPTION_ALG = AESGCM
HASH_ALG = hashlib.sha256
HASH_LEN = 32
KEY_LEN = 16
NONCE_LEN = 12
AUTHTAG_LEN = 16
SIG_LEN = 64
DEPTH = 64

hash = lambda m: HASH_ALG(m).digest()


def split_hash(message):
    digest = hash(message)
    return digest[:KEY_LEN], digest[KEY_LEN : 2 * KEY_LEN]


left_hash = lambda m: split_hash(m)[0] if m is not None else None
right_hash = lambda m: split_hash(m)[1] if m is not None else None


def random_bytes(n):
    return os.urandom(n)


def gen_root_key() -> bytes:
    return random_bytes(KEY_LEN)


def gen_ed25519_key() -> bytes:
    return Ed25519PrivateKey.generate().private_bytes_raw()


def get_ed25519_pubkey(key) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(key).public_key().public_bytes_raw()


def get_nonce() -> bytes:
    return random_bytes(NONCE_LEN)


class Secrets:
    __slots__ = ("channels", "channel_keys", "shared_key_root", "signing_key")
    channels: list
    channel_keys: dict[str, bytes]
    shared_key_root: bytes
    signing_key: bytes

    def __init__(self, channels, channel_keys, shared_key_root, signing_key):
        self.channels = channels
        self.channel_keys = channel_keys
        self.shared_key_root = shared_key_root
        self.signing_key = signing_key

    @classmethod
    def parse(cls, data):
        data = json.loads(data)
        channels = data["channels"]
        channel_keys = {int(k): bytes.fromhex(v) for k, v in data["root_keys"].items()}
        shared_key_root = bytes.fromhex(data["shared_key_root"])
        signing_key = bytes.fromhex(data["signing_key"])
        return cls(
            channels=channels,
            channel_keys=channel_keys,
            shared_key_root=shared_key_root,
            signing_key=signing_key,
        )

    def root_key(self, channel_id):
        return self.channel_keys[channel_id]

    def get_tree(self, channel_id):
        return Tree(root_key=self.root_key(channel_id))


def encrypt(key, nonce, data, aad):
    cipher = ENCRYPTION_ALG(key)
    ciphertext = cipher.encrypt(nonce, data, aad)
    ciphertext, tag = ciphertext[:-AUTHTAG_LEN], ciphertext[-AUTHTAG_LEN:]
    return ciphertext, tag


def sign(key, data):
    priv_key = Ed25519PrivateKey.from_private_bytes(key)
    signature = priv_key.sign(data)
    return signature


class Tree:
    """
    Tree stores a collection of Nodes to generate key material.
    """

    def __init__(self, make_root=True, root_key=None, depth=DEPTH):
        """
        :param make_root: whether to generate the root Node or not.
        :param root_key: optional key material for the root_key
        :param depth: depth of the tree, i.e. #bits in timestamp
        """
        self.nodes = []
        self.depth = depth

        if make_root:
            root_key = gen_root_key() if root_key is None else root_key
            self.add(Node(0, 0, root_key))

    def add(self, node):
        self.nodes.append(node)

    def get_node(self, level, index):
        """
        Find the node at the given position (level, index).

        Returns None if the node cannot be found in this tree.
        """
        for node in self.nodes:
            if node.contains(level, index):
                while node.level != level:
                    left, right = node.left(), node.right()
                    node = left if left.contains(level, index) else right
                return node
        return None

    def frame_key(self, timestamp):
        """
        Find the frame key associated with a given timestamp.

        Returns None if nodes in tree cannot generate the given timestamp.
        """
        node = self.get_node(self.depth, timestamp)
        return node.key if node is not None else None

    def minimal_positions(self, start, end):
        """
        Return a list of (level, index) node positions that cover [start, end].
        """

        def helper(start, end):
            """
            Returns un-keyed nodes covering [start, end].
            """
            n = Node(self.depth, start, depth=self.depth)

            if start == end:
                return [n]

            prev = n
            while n.level >= 0:
                prev, n = n, n.upper()
                if n.start() < start or n.end() > end:
                    return [prev] + helper(prev.end() + 1, end)
                elif n.end() == end:
                    return [n]

            return None

        return [(n.level, n.index) for n in helper(start, end)]

    def minimal_tree(self, start, end):
        """
        Return a new Tree containing minimal set of nodes to cover [start, end].

        NOTE: This is wonky, assumes self has the root node.
        """
        tree = Tree(make_root=False)
        for level, index in self.minimal_positions(start, end):
            tree.add(self.get_node(level, index))

        return tree if tree.nodes else None

    def _alt_minimal_tree(self, start, end):
        """
        Return a new Tree containing minimal set of nodes to cover [start, end]

        Alternative implementation, showing that we probably implement our
        algorithm correctly by doing it two different ways :)

        NOTE: This is wonky, assumes self has the root node.
        """
        tree = Tree(make_root=False)

        while tree.range() != (start, end):
            # Either start at start, or the end of the current tree coverage
            curr_start = start if tree.range() is None else tree.range()[1] + 1

            # Find the first node where start == curr_start
            node = self.get_node(0, 0)
            while node.start() != curr_start:
                left, right = node.left(), node.right()
                if curr_start in left:
                    node = left
                elif curr_start in right:
                    node = right
                else:
                    raise Exception("Node does not contain start")

            # Descend left until we find a node with an end <= desired end
            while node.end() > end:
                node = node.left()
            tree.add(node)
        return tree

    def range(self):
        """
        Returns the range of timestamps covered by this tree.

        NOTE: Does not check for contiguity.
        """
        if not self.nodes:
            return None

        return (
            min(self.nodes, key=lambda x: x.start()).start(),
            max(self.nodes, key=lambda x: x.end()).end(),
        )

    def get_subscription(self):
        """
        Returns (n_keys, byte_array) suitable for sending to a decoder.
        """
        n_keys = len(self)
        subscription = n_keys.to_bytes()
        for node in self.nodes:
            subscription += struct.pack(
                f"<BQ{KEY_LEN}s", node.level, node.index, node.key
            )
        return subscription

    @staticmethod
    def from_subscription(subscription: bytes):
        """
        Constructs a Tree from the subscription update file.
        """
        t = Tree(make_root=False)
        for level, index, key in struct.iter_unpack(f"<BQ{KEY_LEN}s", subscription[1:]):
            t.add(Node(level, index, key))
        return t

    def __eq__(self, other):
        """
        Return if other contains the set of self's nodes.

        NOTE: Not a perfect equality test.
        """
        for n in self.nodes:
            found = False
            for on in other.nodes:
                if (n.level, n.index, n.key) == (on.level, on.index, on.key):
                    found = True
                    break
            if not found:
                return False
        if set(self.nodes) != set(other.nodes):
            return False
        if len(self.nodes) != len(other.nodes):
            return False
        if len(set(self.nodes)) != len(self.nodes):
            return False
        return True

    def __len__(self):
        return len(self.nodes)

    def __str__(self):
        rep = f"Tree covering {self.range()}:\n"
        for node in self.nodes:
            rep += f"  {node}\n"
        return rep[:-1]

    def __repr__(self):
        # Not correct, just convenient :)
        return str(self)


class Node:
    """
    Represents an individual node in the tree.

    Optionally includes key material, as sometimes we want to use this class
    without keys, i.e. for simply navigating upwards.
    """

    def __init__(self, level, index, key=None, depth=DEPTH):
        self.level = level
        self.index = index
        self.key = key
        self.depth = depth

    def start(self, depth=None):
        """
        Returns the minimal index this node can reach at a given depth.

        When `depth` is None, this returns the earliest timestamp this node can reach.
        """
        depth = self.depth if depth is None else depth
        return self.index * 2 ** (depth - self.level)

    def end(self, depth=None):
        """
        Returns the maximum index this node can reach at a given depth.

        When `depth` is None, this returns the latest timestamp this node can reach.
        """
        depth = self.depth if depth is None else depth
        return ((self.index + 1) * 2 ** (depth - self.level)) - 1

    def range(self, depth=None):
        return (self.start(depth), self.end(depth))

    def left(self):
        """
        Returns the node obtained by descending left in the tree.
        """
        return Node(self.level + 1, self.index * 2, left_hash(self.key))

    def right(self):
        """
        Returns the node obtained by descending right in the tree.
        """
        return Node(self.level + 1, self.index * 2 + 1, right_hash(self.key))

    def upper(self):
        """
        Returns the node above this node.

        NOTE: above node is unkeyed, as we can't derive keys of nodes above us.
        """
        return Node(self.level - 1, self.index // 2, None)

    def contains(self, level, index):
        """
        Helper for determining if this node can reach another given node.
        """
        return self.start(level) <= index and index <= self.end(level)

    def __contains__(self, timestamp):
        """
        Special case to conveniently check if we can reach a given timestamp.
        """
        return self.contains(self.depth, timestamp)

    def __eq__(self, other):
        return (
            self.level == other.level
            and self.index == other.index
            and self.key == other.key
            and self.depth == other.depth
        )

    def __hash__(self):
        return builtins.hash((self.level, self.index, self.key, self.depth))

    def __repr__(self):
        return f"Node({self.level}, {self.index}, 0x{self.key.hex()})"


def bench(n=1000):
    total = 0
    for _ in range(n):
        t = Tree()
        ts = random.randint(0, 2**DEPTH - 1)
        start = time.time()
        t.frame_key(ts)
        end = time.time()
        total += end - start
    return total / n


def test_same_frame_keys(N=100):
    print(f"running test_same_frame_keys({N})")
    for n in range(N):
        if N > 100 and n % 100 == 0:
            print(f"  iter {n}")
        t = Tree()  # Generate a tree with a random root key.
        start = random.randint(0, 2**DEPTH - 1)
        end = random.randint(start, 2**DEPTH - 1)
        mt = t.minimal_tree(start, end)  # Generate a tree covering only [start, end]
        amt = t._alt_minimal_tree(start, end)
        for n in range(N):
            # Assert a random sampling of their frame keys are the same.
            r = random.randint(start, end)
            assert t.frame_key(r) == mt.frame_key(r)
            assert t.frame_key(r) == amt.frame_key(r)


def test_subscription(N=1000):
    print(f"running test_subscription({N})")
    for n in range(N):
        if N > 1000 and n % 1000 == 0:
            print(f"  iter {n}")
        t = Tree()
        start = random.randint(0, 2**DEPTH - 1)
        end = random.randint(start, 2**DEPTH - 1)
        mt = t.minimal_tree(start, end)
        amt = t._alt_minimal_tree(start, end)
        omt = Tree.from_subscription(mt.get_subscription())
        assert mt == omt
        oatm = Tree.from_subscription(amt.get_subscription())
        assert amt == oatm


def test_minimal_tree(N=1000):
    print(f"running test_minimal_tree({N})")
    for n in range(N):
        if N > 1000 and n % 1000 == 0:
            print(f"  iter {n}")
        t = Tree()
        start = random.randint(0, 2**DEPTH - 1)
        end = random.randint(start, 2**DEPTH - 1)
        mt = t.minimal_tree(start, end)
        amt = t._alt_minimal_tree(start, end)
        assert mt == amt
        assert mt.range() == (start, end)
        assert amt.range() == (start, end)
        assert mt.frame_key(start) == amt.frame_key(start)
        assert mt.frame_key(start - 1) is None
        assert amt.frame_key(start - 1) is None
        assert mt.frame_key(end) == amt.frame_key(end)
        assert mt.frame_key(end + 1) is None
        assert amt.frame_key(end + 1) is None


if __name__ == "__main__":
    test_same_frame_keys()
    test_subscription()
    test_minimal_tree()
    pass
