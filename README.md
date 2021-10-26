# crypto-mnemonic

[![Build Status](https://travis-ci.org/SushiChain/crypto-mnemonic.svg?branch=master)](https://travis-ci.org/SushiChain/crypto-mnemonic)

Crypto-mnemonic creates random pass phrases or (hexadecimal UIDS) of specified strength which are human readable and rememberable. It is compatible with the javascript version: [mnemonic.js](https://github.com/modulesio/mnemonic.js/blob/master/mnemonic.js) which we use for our crypto wallet.

## Installation

Add this to your application's `shard.yml`:

```yaml
dependencies:
  crypto-mnemonic:
    github: SushiChain/crypto-mnemonic
```

## Usage

```crystal
require "crypto-mnemonic"
```

You can generate a 96-bit mnemonic, i.e. 9 words or 3 random 32-bit unsigned integers:

```
m = Mnemonic.new(96)
m.to_words
["grey", "climb", "demon", "snap", "shove", "fruit", "grasp", "hum", "self"]
```

You can also obtain the random sequence or the 96-bit number in hexadecimal notation as follows:

```
m.seed
[174975897_u32, 171815469_u32, 1859322123_u32]

m.to_hex
"0a6deb990a3db22d6ed3010b"
```

Finally, from a list of words or a hex string it is possible to recreate the mnemonic that generated them:

```
m = Mnemonic.from_words(["grey", "climb", "demon", "snap", "shove", "fruit", "grasp", "hum", "self"]);
m.to_hex;
"0a6deb990a3db22d6ed3010b"

m = Mnemonic.from_hex("0a6deb990a3db22d6ed3010b")
m.to_words
["grey", "climb", "demon", "snap", "shove", "fruit", "grasp", "hum", "self"]
```

When working with `Mnemonic` you must use either 32/64/96/128/256 etc for the bit strengths. 96 is the default.

## Contributing

1. Fork it ( https://github.com/SushiChain/crypto-mnemonic/fork )
2. Create your feature branch (git checkout -b my-new-feature)
3. Commit your changes (git commit -am 'Add some feature')
4. Push to the branch (git push origin my-new-feature)
5. Create a new Pull Request

## Contributors

- [kingsleyh](https://github.com/kingsleyh): Kingsley Hendrickse - creator and  maintainer
- [q9f](https://github.com/q9f): Afri Schoedon - BIP-0039 support
