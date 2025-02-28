#!/usr/bin/env python3

import argparse
import sys
from loguru import logger

import random
from ectf25.utils.decoder import DecoderIntf, DecoderError
from ectf25_design import cryptosystem
from ectf25_design.encoder import Encoder
from ectf25_design.gen_subscription import gen_subscription

logger.remove()
logger.add(sys.stdout, level="INFO")


def expect_error(encoder, decoder, subscription, n=None):
    prefix = str(n) + ": " if n else ""
    try:
        decoder.subscribe(subscription)
    except DecoderError:
        logger.info(f"{prefix}Got expected DecoderError for subscription")
    else:
        raise Exception(f"{prefix}Decoder did not raise a DecoderError on subscription")


def expect_success(encoder, decoder, subscription, n=None):
    prefix = str(n) + ": " if n else ""
    try:
        decoder.subscribe(subscription)
    except DecoderError:
        raise Exception(
            f"{prefix}Decoder unexpectedly raised a DecoderError on subscription"
        )
    logger.info(f"{prefix}Successfully subscribed")


def parse_args():
    parser = argparse.ArgumentParser(prog="ectf25_design.encoder")
    parser.add_argument(
        "secrets_file", type=argparse.FileType("rb"), help="Path to the secrets file"
    )
    parser.add_argument(
        "device_id", type=lambda x: int(x, 0), help="Device ID of the update recipient."
    )
    parser.add_argument(
        "--port",
        default="/dev/ttyACM0",
        help="Serial port to the Decoder",
    )
    parser.add_argument(
        "-n",
        "--num-subscriptions",
        type=int,
        default=1000,
        help="Number of subscriptions in each segment to test",
    )
    return parser.parse_args()


def main(args):
    logger.info(f"Starting valid subscriptions test!")
    secrets_data = args.secrets_file.read()
    secrets = cryptosystem.Secrets.parse(secrets_data)
    encoder = Encoder(secrets_data)
    decoder = DecoderIntf(args.port)
    N = args.num_subscriptions

    # Test N random valid subscriptions!
    logger.info("Testing N random valid subscriptions")
    for n in range(N):
        # Generate a random subscription
        start = random.randint(0, 2**64 - 1)
        end = random.randint(start, 2**64 - 1)
        channel = random.choice(
            secrets.channels[1:]
        )  # pick a random channel besides ch0
        subscription = gen_subscription(
            secrets_data, args.device_id, start, end, channel
        )
        expect_success(encoder, decoder, subscription, n)

    # Test N random subscriptions for channel 0
    logger.info("Testing N random subscriptions for channel 0")
    for n in range(N):
        # Generate a random subscription
        start = random.randint(0, 2**64 - 1)
        end = random.randint(start, 2**64 - 1)
        channel = 0
        subscription = gen_subscription(
            secrets_data, args.device_id, start, end, channel
        )
        expect_error(encoder, decoder, subscription, n)

    # Test N random subscriptions meant for another decoder!
    logger.info("Testing N random subscriptions meant for another decoder")
    for n in range(N):
        start = random.randint(0, 2**64 - 1)
        end = random.randint(start, 2**64 - 1)
        channel = random.choice(
            secrets.channels[1:]
        )  # pick a random channel besides ch0
        device_id = random.randint(0, 2**32 - 1)
        while device_id == args.device_id:
            device_id = random.randint(0, 2**32 - 1)
        subscription = gen_subscription(secrets_data, device_id, start, end, channel)
        expect_error(encoder, decoder, subscription, n)

    # Test N random valid subscriptions with some extra bytes added at the end...
    logger.info(
        "Testing N random valid subscriptions with some extra bytes added at the end"
    )
    for n in range(N):
        # Generate a random subscription
        start = random.randint(0, 2**64 - 1)
        end = random.randint(start, 2**64 - 1)
        channel = random.choice(
            secrets.channels[1:]
        )  # pick a random channel besides ch0
        subscription = gen_subscription(
            secrets_data, args.device_id, start, end, channel
        )
        subscription += random.randbytes(random.randint(1, 8192 - len(subscription)))
        expect_error(encoder, decoder, subscription, n)

    # Test N random valid subscriptions with some bytes modified...
    logger.info("Testing N random valid subscriptions with some bytes modified")
    for n in range(N):
        # Generate a random subscription
        start = random.randint(0, 2**64 - 1)
        end = random.randint(start, 2**64 - 1)
        channel = random.choice(
            secrets.channels[1:]
        )  # pick a random channel besides ch0
        subscription = gen_subscription(
            secrets_data, args.device_id, start, end, channel
        )
        modified_subscription = subscription
        while modified_subscription == subscription:
            for _ in range(random.randint(1, 10)):
                idx = random.randint(0, len(subscription) - 1)
                modified_subscription = (
                    modified_subscription[:idx]
                    + random.randbytes(1)
                    + modified_subscription[idx + 1 :]
                )
        expect_error(encoder, decoder, modified_subscription, n)

    # Test N random valid subscriptions with some bytes removed...
    logger.info("Testing N random valid subscriptions with some bytes removed")
    for n in range(N):
        start = random.randint(0, 2**64 - 1)
        end = random.randint(start, 2**64 - 1)
        channel = random.choice(
            secrets.channels[1:]
        )  # pick a random channel besides ch0
        subscription = gen_subscription(
            secrets_data, args.device_id, start, end, channel
        )
        subscription = subscription[: random.randint(0, len(subscription) - 1)]
        expect_error(encoder, decoder, subscription, n)

    logger.info("Valid subscriptions test passed yippee!")


if __name__ == "__main__":
    args = parse_args()
    main(args)
