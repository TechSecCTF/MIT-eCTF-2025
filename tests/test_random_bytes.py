#!/usr/bin/env python3

import argparse
import sys
from loguru import logger

import random
from ectf25.utils.decoder import DecoderIntf, DecoderError, Opcode, Message
from ectf25_design import cryptosystem
from ectf25_design.encoder import Encoder
from ectf25_design.gen_subscription import gen_subscription

logger.remove()
logger.add(sys.stdout, level="INFO")


def expect_error(encoder, decoder, opcode, data, n=None):
    prefix = str(n) + ": " if n else ""
    decoder.send_msg(Message(opcode, data))
    try:
        resp = decoder.get_msg()
    except DecoderError:
        logger.info(f"{prefix}Got expected DecoderError for opcode {opcode}")
        return
    raise Exception(
        f"{prefix}Decoder returned unexpected opcode {resp.opcode} for {opcode}"
    )


def expect_success(encoder, decoder, opcode, data, n=None):
    prefix = str(n) + ": " if n else ""
    decoder.send_msg(Message(opcode, data))
    try:
        resp = decoder.get_msg()
    except DecoderError:
        raise Exception(
            f"{prefix}Decoder returned unexpected DecoderError for opcode {opcode}"
        )
    if resp.opcode == opcode:
        logger.info(f"{prefix}Got expected response for opcode {opcode}")
    else:
        raise Exception(
            f"{prefix}Decoder returned unexpected opcode {resp.opcode} for {opcode}"
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

    # Test small decode messages
    logger.info("Testing small random decode messages")
    for n in range(256):
        expect_error(encoder, decoder, Opcode.DECODE, random.randbytes(n), n)

    # Test N random bytes greater than sig len for decoder
    logger.info("Testing large random decode messages")
    for n in range(256, 512):
        expect_error(encoder, decoder, Opcode.DECODE, random.randbytes(n), n)

    for n in range(4096, 4122):
        expect_error(encoder, decoder, Opcode.DECODE, random.randbytes(n), n)

    for n in range(65530, 65536):
        expect_error(encoder, decoder, Opcode.DECODE, random.randbytes(n), n)

    logger.info("Valid random bytes test passed yippee!")


if __name__ == "__main__":
    args = parse_args()
    main(args)
