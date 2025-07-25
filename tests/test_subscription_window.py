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
        decoder.decode(encoded_frame)
    except DecoderError:
        logger.info(
            f"{prefix}Got expected DecoderError with {timestamp=}, range {start=} {end=}"
        )
    else:
        raise Exception(
            f"{prefix}Decoder did not raise a DecoderError with {timestamp=}, range {start=} {end=}"
        )


def expect_success(encoder, decoder, channel, timestamp, start, end, n=None):
    prefix = str(n) + ": " if n else ""
    frame = random.randbytes(random.randint(1, 64))
    encoded_frame = encoder.encode(channel, frame, timestamp)
    try:
        decoded_frame = decoder.decode(encoded_frame)
    except DecoderError:
        raise Exception(
            f"{prefix}Decoder unexpectedly raised a DecoderError with {timestamp=}, range {start=} {end=}"
        )
    assert decoded_frame == frame
    logger.info(
        f"{prefix}Successfully decoded frame with {timestamp=}, range {start=} {end=}"
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
        help="Number of frames in each segment to test",
    )
    return parser.parse_args()


def main(args):
    logger.info(f"Starting subscription window test!")
    secrets_data = args.secrets_file.read()
    secrets = cryptosystem.Secrets.parse(secrets_data)
    encoder = Encoder(secrets_data)
    decoder = DecoderIntf(args.port)
    N = args.num_frames

    # Generate a random subscription
    start = random.randint(0, 2**64 - 1)
    end = random.randint(start, 2**64 - 1)
    channel = random.choice(secrets.channels[1:])  # pick a random channel besides ch0
    subscription = gen_subscription(secrets_data, args.device_id, start, end, channel)

    logger.info(f"Generated subscription for {start=} {end=} {channel=}")

    # Subscribe, will raise an exception if subscribing fails
    decoder.subscribe(subscription)

    # Test N random frames below the subscription window, and assert they all raise a DecoderError
    logger.info(f"Testing {N} frames below the subscription window")
    for n in range(N):
        # Always test timestamp=0 first, then randomly select N monotonically increasing timestamps below the subscription window
        # Keeping track of last timestamp not important yet, as timestamps below the subscription window are not decoded
        timestamp = 0 if n == 0 else random.randint(0, start - 2)
        expect_error(encoder, decoder, channel, timestamp, start, end, n)

    # Test start-1 and start
    expect_error(encoder, decoder, channel, start - 1, start, end)
    expect_success(encoder, decoder, channel, start, start, end)

    # Test N random frames monotonically increasing frames inside the subscription window
    logger.info(f"Testing ~{N} frames inside the subscription window")
    timestamps = sorted(list(set(random.randint(start + 1, end) for _ in range(N))))
    for n, timestamp in enumerate(timestamps):
        expect_success(encoder, decoder, channel, timestamp, start, end, n)

    # Test end and end+1
    expect_success(encoder, decoder, channel, end, start, end)
    expect_error(encoder, decoder, channel, end + 1, start, end)

    # Test N random frames above the subscription window, and assert they all raise a DecoderError
    logger.info(f"Testing {N} frames above the subscription window")
    for n in range(N):
        timestamp = end + 1 if n == 0 else +random.randint(end + 1, 2**64 - 1)
        expect_error(encoder, decoder, channel, timestamp, start, end, n)

    logger.info("Subscription window test passed, yippee!")


if __name__ == "__main__":
    args = parse_args()
    main(args)
