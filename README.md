# Einszeit

Einszeit is an open-source security device that can theoretically provide perfect quantum-proof encryption between two paired devices over any communications medium.

![Einszeit](https://github.com/machdyne/einszeit/blob/42f7534c930817e6dd1db8ed6618d3658704d32c/einszeit.png)

This repo contains schematics, PCB layouts, a 3D-printable case, firmware and documentation.

Find more information on the [Einszeit product page](https://machdyne.com/product/einszeit-security-device/).

*This is a very early release of the firmware intended for developers and other interested parties, it is not yet intended for actual use.*

## Limitations

Some of the limitations may be improved through firmware updates.

  * Message generation is limited to ~2MB after each pairing.
  * Initial key generation takes several hours.
  * Paired devices must be distributed in person.
  * Crypto IC configuration is factory locked to enable RNG output.
  * Key is temporarily stored on your computer during pairing.
  * Device is limited to ~400K lifetime metadata updates.
  * Must copy key to one device at a time.
  * Lacks fundamental error checking.

## Usage

The `ez` utility can be used to configure the device identity, to generate and copy keys, and to read or write messages. It stores the key pointer on the device, incrementing it each time a message is written.

### Set device identity

This command initializes the device metadata and sets the device identity.

Each device in the pair is identified as either alice or bob. The metadata is stored in EEPROM. The device must be erased to change its identity.

If the identity is alice, this command will also generate both the alice and bob keys and save them as `ez.key` (this will take several hours).

```
$ ez -i <alice|bob>
```

### Copy keys

This command copies the key data to the connected device.

```
$ ez -c
```

### Write a message

The write command generates an encrypted base64-encoded message. The message will only be generated after the key pointer has been successfully incremented.

```
$ ez -w << plain.txt
```

or

```
$ ez -w
Type your message here.
^D
```

### Read a message

Use this command to read an encrypted base64-encoded message that was previously generated using the write command with a paired device.

```
$ ez -r << cipher.txt
```

or

```
$ ez -r
Paste the base64-encoded message here.
^D
```

Note: You can use `-v` to verify a message that you've written.

### Erase device

This peforms a factory reset by erasing the keys and metadata.

```
ez -E
```

### Random data

This command will generate 32 bytes of random data, it can be used to test the quality of the hardware randomn number generator with testrand.sh.

```
ez -R
```

## Implementation Details

### Metadata

The metadata is 32-bytes and is stored in one of 16 EEPROM data slots:

	magic[2] = 0x455a
    sequence[4] = highest value indiciates current slot
	send_ptr[4] = offset of next unused key location
	boot_cnt[4] = incremented each time the device is powered on
	identity[1] = (0x00 = alice, 0x01 = bob)
    reserved[16]
	crc[1] = crc8(metadata)

All metadata slots are scanned to find the latest valid slot, then written to (latest\_slot + 1) % 16 on update.

### Key Storage

The alice key is stored in flash at 0x000000 and the bob key is stored at 0x200000.

### Message Format

Messages are generated in the following format:

```
base64 ( [ <key_ptr:32> <msg_len:32> <ciphertext:n> ] <crc32:32> )
```

Note that the key offset and message length are not encrypted.

## LLM-generated code

To the extent that there is LLM-generated code in this repo, it should be space indented. Any space indented code should be carefully audited and then converted to tabs (eventually).

## License

The contents of this repo are released under the [Lone Dynamics Open License](LICENSE.md), with the following exceptions:

  * The ch32fun library is MIT licensed.
  * The hidapi library is BSD licensed.

Note: You can use these designs for commercial purposes but we ask that instead of producing exact clones, that you either replace our trademarks and logos with your own or add your own next to ours.
