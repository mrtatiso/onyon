# onyon

syvox + onion → another onion, always the same for the same pair.

```
$ echo holamundo | vox 25018599682202377746.87783789576741058797.28832678037307446403.33471880386520197097 \
    | onyon seal duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion
kpxhhvfuuinz7yhmkvz27fctc2lpjvrhhch2kcg2umfvkf7odej2mdad.onion

$ echo holamundo | vox 2501…0097 | onyon open kpxhhvfuuinz7yhmkvz27fctc2lpjvrhhch2kcg2umfvkf7odej2mdad.onion
duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion

$ echo pedro | vox 2501…0097 | onyon open kpxhhvfuuinz7yhmkvz27fctc2lpjvrhhch2kcg2umfvkf7odej2mdad.onion
g6khbhbbkdopdust76jdhipffhdompd6ptz7lpvcc4st662rxezahjqd.onion
```

No dependencies. Two functions. Nothing stored.

## Install

```
pip install git+https://github.com/mrtatiso/onyon
```

## Use

### Terminal

```
onyon seal <onion>    the onion to store
onyon open <onion>    the onion it hides
```

The syvox always comes through stdin, never as an argument, so it does not end up in the shell history. It usually comes straight from [vox](https://github.com/mrtatiso/vox):

```
echo clave | vox <salt> | onyon seal <real.onion>
echo clave | vox <salt> | onyon open <stored.onion>
```

### Python

```python
from onyon import seal, open_

stored = seal(syvox, real)       # the onion to store
open_(syvox, stored) == real     # True
```

Both raise `ValueError` if the syvox does not have exactly 80 digits or the onion is not a valid v3 onion.

## What it does

- **Any syvox works.** There is no wrong one: every syvox opens every stored onion into a valid v3 onion, with the right checksum, version 3 and a public key that is a real ed25519 point of prime order, the kind Tor accepts. A wrong syvox gives an onion that cannot be told apart from any other.
- **seal and open undo each other** for the same syvox. Nothing is random and nothing is stored.
- **onyon never sees a key or a salt.** It receives a syvox, usually from vox, which already mixed the salt and the key. Who calls onyon decides where the syvox comes from.
- **The syvox goes through its own label** (`onyon1|`) before it is used, so the same syvox gives something unrelated in any other tool.

## One syvox per onion

Never seal two onions with the same syvox. The stored onion is the real one plus a fixed shift that comes from the syvox: whoever knows one real onion and its stored onion can work out that shift and open every other onion sealed with the same syvox. Give each onion its own salt, and so its own syvox.

## v1

| | |
|---|---|
| syvox | any 80 digits; separators are ignored |
| shift | k = shake_256(`onyon1|` + the 80 digits), 64 bytes, little-endian, mod ℓ |
| seal | stored point = real point + k·B |
| open | real point = stored point − k·B |
| curve | ed25519 (RFC 8032), B its base point, ℓ the order of B |
| address | onion v3: base32(public key + checksum + version 3), checksum = sha3_256(`.onion checksum` + key + 3), first 2 bytes |

These never change within v1. Changing any of them changes every onion, so it would be v2. The tests include a fixed answer that any implementation of v1, in any language, must reproduce.

## Test

```
python -m unittest discover test
```

## Verify

```
sha256sum onyon.py
```

v1.0.0:

```
1bfd794c53085815d0b01f46bab0fae4f4716c3d23fac753bc34445f19acbbf9
```
