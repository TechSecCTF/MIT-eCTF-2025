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


def expect_error(encoder, decoder, channel, timestamp, start, end, n=None):
    prefix = str(n) + ": " if n else ""
    frame = random.randbytes(random.randint(1, 64))
    encoded_frame = encoder.encode(channel, frame, timestamp)
    try:
        decoded_frame = decoder.decode(encoded_frame)
    except DecoderError:
        logger.info(
            f"{prefix}Got expected DecoderError with {channel=} {timestamp=}, range {start=} {end=}"
        )
    else:
        if decoded_frame == frame:
            raise Exception(
                f"{prefix}Decoder erroneously decoded frame with {channel=}{timestamp=}, range {start=} {end=}"
            )
        raise Exception(
            f"{prefix}Decoder did not successfully decode frame but did error with {channel=} {timestamp=}, range {start=} {end=}"
        )


def expect_success(encoder, decoder, channel, timestamp, start, end, n=None):
    prefix = str(n) + ": " if n else ""
    frame = random.randbytes(random.randint(1, 64))
    encoded_frame = encoder.encode(channel, frame, timestamp)
    try:
        decoded_frame = decoder.decode(encoded_frame)
    except DecoderError:
        raise Exception(
            f"{prefix}Decoder unexpectedly raised a DecoderError with {channel=} {timestamp=}, range {start=} {end=}"
        )
    assert decoded_frame == frame
    logger.info(
        f"{prefix}Successfully decoded frame with {channel=} {timestamp=}, range {start=} {end=}"
    )


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
        "--num-frames",
        type=int,
        default=1000,
        help="Number of frames to test overall",
    )
    return parser.parse_args()


def main(args):
    logger.info(f"Starting valid subscriptions test!")
    secrets_data = args.secrets_file.read()
    secrets = cryptosystem.Secrets.parse(secrets_data)
    encoder = Encoder(secrets_data)
    decoder = DecoderIntf(args.port)
    N = args.num_frames

    # Generate a few subscriptions with the same window for convenience
    channels = list(set(random.choice(secrets.channels[1:]) for _ in range(5)))
    logger.info(f"Generating subscriptions for {channels=}")
    start = random.randint(0, 2**64 - 1)
    end = random.randint(start, 2**64 - 1)
    for channel in channels:
        subscription = gen_subscription(
            secrets_data, args.device_id, start, end, channel
        )
        decoder.subscribe(subscription)

    # Test ch0 doesn't decode ts=0 multiple times
    expect_success(encoder, decoder, 0, 0, 0, 2**64 - 1)
    expect_error(encoder, decoder, 0, 0, 0, 2**64 - 1)
    expect_error(encoder, decoder, 0, 0, 0, 2**64 - 1)
    expect_success(encoder, decoder, 0, 2, 0, 2**64 - 1)
    expect_error(encoder, decoder, 0, 1, 0, 2**64 - 1)
    expect_error(encoder, decoder, 0, 2, 0, 2**64 - 1)

    # Test N frames with some misordering
    logger.info("Testing N frames with some misordering")
    timestamp = start - 500
    expect_success(encoder, decoder, 0, timestamp, start, end)
    for n in range(N):
        # Test a misordered frame 1/3 of the time.
        offset = (
            random.randint(-100, 0)
            if random.random() < 0.33
            else random.randint(1, 100)
        )
        channel = random.choice([0] + channels)  # pick a random channel incl. ch0

        if (
            channel != 0 and (timestamp + offset < start or timestamp + offset > end)
        ) or offset <= 0:
            expect_error(encoder, decoder, channel, timestamp + offset, start, end, n)
        else:
            expect_success(encoder, decoder, channel, timestamp + offset, start, end, n)

        timestamp = max(timestamp, timestamp + offset)

    logger.info("Misordered frames test passed yippee!")


if __name__ == "__main__":
    args = parse_args()
    main(args)
