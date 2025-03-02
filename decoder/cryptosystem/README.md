### Decoder key-derivation system

Included is the key-derivation functions for our Decoder.
Additionally included is a proof-of-concept wrapper for the decoder that was used during the testing process. 
It can be used to test the C cryptosystem implementation separately from the firmware environment.
Included is a `Makefile` to build a proof-of-concept executable, as well as a `tests.py` that interfaces with the python encoder implementation.
Below is a command session describing the usage: 

```bash
# from within the python virtual environment (see below for details)

cd decoder/
# download wolfssl (taken from Dockerfile)
wget https://github.com/wolfSSL/wolfssl/archive/refs/tags/v5.7.6-stable.zip && \
    unzip v5.7.6-stable.zip && \
    rm -f v5.7.6-stable.zip
mv wolfssl-5.7.6-stable wolfssl

cd cryptosystem/
# makefile and tests.py expect `secrets.json` to exist
python3 -m ectf25_design.gen_secrets secrets.json 0 1 3 4 # or any list of channels
make
./decoder
# => Usage: ./decoder <channel> <subscription hex>

# generate a subscription update to test the decoder against
python3 tests.py 1 # or any channel number
# ...copy hexlified subscription update from output

# run ./decoder with same channel number and hexlified subscription
./decoder 1 <hex subscription, copied from tests.py output>
# verify that derived frame 0 key is the same
```
