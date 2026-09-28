# EncFS Filename Test Specification

These test cases document the real EncFS fixtures in `encfs-tests`. Each case includes its configuration, decoded/plaintext paths, encrypted paths on disk, and the recorded generation or mount commands. The files in the fixture trees are empty: these tests cover names and directory structure, not file contents.

The historical reference is EncFS 1.9.5. Mount commands require Unix and FUSE. The external password program `encfs-pwd` prints the test password `test`:

```sh
#! /bin/sh
echo "test"
```

Run commands from `encfs-tests/`. The manifests include the root entry `.`. Compare path sets, not traversal order. The recorded direct-nochain `encfsctl` output omits `.` even though its manifest includes it; normalize the root entry before comparing. For the historical `find reverse/` output, remove the `reverse/` prefix before comparison.

## Test ID: DIRECT-NOCHAIN

**Purpose:** Decode the encrypted tree without filename-IV chaining and compare the resulting paths with `ref.lst`.

**Configuration file:** `direct-nochain/.encfs6.xml`

- `uniqueIV=0`
- `chainedNameIV=0`
- `externalIVChaining=0`
- `nameio/block` 3.0, AES 256-bit key, 1024-byte blocks
- Password: `test`, provided by `encfs-pwd`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE boost_serialization>
<boost_serialization signature="serialization::archive" version="7">
    <cfg class_id="0" tracking_level="0" version="20">
        <version>20100713</version>
        <creator>EncFS 1.9.5</creator>
        <cipherAlg class_id="1" tracking_level="0" version="0">
            <name>ssl/aes</name>
            <major>3</major>
            <minor>0</minor>
        </cipherAlg>
        <nameAlg>
            <name>nameio/block</name>
            <major>3</major>
            <minor>0</minor>
        </nameAlg>
        <keySize>256</keySize>
        <blockSize>1024</blockSize>
        <plainData>0</plainData>
        <uniqueIV>0</uniqueIV>
        <chainedNameIV>0</chainedNameIV>
        <externalIVChaining>0</externalIVChaining>
        <blockMACBytes>0</blockMACBytes>
        <blockMACRandBytes>0</blockMACRandBytes>
        <allowHoles>1</allowHoles>
        <encodedKeySize>52</encodedKeySize>
        <encodedKeyData>
qdS+nnbALzcKU6nJrOsNIdKXC1lm+zftCHCZ/i9MEIEAo2rKSFBAALFf4p/OZIjpDMCAdg==
</encodedKeyData>
        <saltLen>20</saltLen>
        <saltData>
fuqUHOx2jyzWULuGyXZlPzDQU8k=
</saltData>
        <kdfIterations>810947</kdfIterations>
        <desiredKDFDuration>500</desiredKDFDuration>
    </cfg>
</boost_serialization>
```

**Decoded/plaintext paths (`ref.lst`):**

```text
.
./file_2
./dir_1
./dir_1/file_2
./dir_1/subdir_1_2
./dir_1/file_1
./dir_1/file_1_1
./dir_1/subdir_1_1
./dir_1/subdir_1_1/subdir_1_1_1
./dir_1/subdir_1_1/subdir_1_1_1/file_1_1_1_1
./dir_1/subdir_1_1/subdir_1_1_1/file_1_1_1_2
./dir_2
./dir_2/file_2_2
./dir_2/file_2_1
./file_1
./file_3
```

**Encrypted paths on disk (`direct-nochain.lst`):**

```text
.
./w3kY9smoitBQoQpRpJ,0XN97
./,lDmZbEm6cqEVV8hKXR19O,B
./,lDmZbEm6cqEVV8hKXR19O,B/w3kY9smoitBQoQpRpJ,0XN97
./,lDmZbEm6cqEVV8hKXR19O,B/dPxqvp7oMmRSiuVz2eQFR8tU
./,lDmZbEm6cqEVV8hKXR19O,B/ESzVuXGQ3EIW5hi2mIwHGuBs
./,lDmZbEm6cqEVV8hKXR19O,B/cydQSpoD8vtPevSmGedy9On0
./,lDmZbEm6cqEVV8hKXR19O,B/,FF,30Mu2LER,Sq-GdZbhz8p
./,lDmZbEm6cqEVV8hKXR19O,B/,FF,30Mu2LER,Sq-GdZbhz8p/-REGwkZheaqGgZQGcGU6lLu-
./,lDmZbEm6cqEVV8hKXR19O,B/,FF,30Mu2LER,Sq-GdZbhz8p/-REGwkZheaqGgZQGcGU6lLu-/vlVnA87O3AvdeQ5tU5A2T,Sb
./,lDmZbEm6cqEVV8hKXR19O,B/,FF,30Mu2LER,Sq-GdZbhz8p/-REGwkZheaqGgZQGcGU6lLu-/bTJcT8GT4qM0inUEttegNX8Q
./oQB,A4aBVkLvJHqlG,MHKqIe
./oQB,A4aBVkLvJHqlG,MHKqIe/0PW2cDl2ym8RDqMWrcQtKQGQ
./oQB,A4aBVkLvJHqlG,MHKqIe/jk1gJgg-E31WaHnFCfvbBdFd
./ESzVuXGQ3EIW5hi2mIwHGuBs
./80Fpbiw9r5dq1DEXv-DlMUR7
```

**Fixture generation and comparison:**

```sh
encfsctl encode --extpass="./encfs-pwd" direct-nochain/ $(cat ref.lst)
```

The output should match `direct-nochain.lst` as a set of paths.

**Recorded mount command:**

```sh
ENCFS_TESTS_BASE=$(pwd)
printf '%s\n' 'test' | encfs --stdin "$ENCFS_TESTS_BASE/direct-nochain" "$ENCFS_TESTS_BASE/mnt"
(cd "$ENCFS_TESTS_BASE/mnt" && find .)
fusermount -u "$ENCFS_TESTS_BASE/mnt"
```

The listing under `mnt/` should match the decoded/plaintext paths above. This normalizes the historical script, which assigned `PWD="test"` before sending it to `encfs --stdin`.

## Test ID: DIRECT-CHAIN

**Purpose:** Decode the encrypted tree with filename-IV chaining and compare the resulting paths with `ref.lst`.

**Configuration file:** `direct-chain/.encfs6.xml`

- `uniqueIV=1`
- `chainedNameIV=1`
- `externalIVChaining=0`
- `nameio/block` 3.0, AES 256-bit key, 1024-byte blocks
- Password: `test`, provided by `encfs-pwd`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE boost_serialization>
<boost_serialization signature="serialization::archive" version="7">
    <cfg class_id="0" tracking_level="0" version="20">
        <version>20100713</version>
        <creator>EncFS 1.9.5</creator>
        <cipherAlg class_id="1" tracking_level="0" version="0">
            <name>ssl/aes</name>
            <major>3</major>
            <minor>0</minor>
        </cipherAlg>
        <nameAlg>
            <name>nameio/block</name>
            <major>3</major>
            <minor>0</minor>
        </nameAlg>
        <keySize>256</keySize>
        <blockSize>1024</blockSize>
        <plainData>0</plainData>
        <uniqueIV>1</uniqueIV>
        <chainedNameIV>1</chainedNameIV>
        <externalIVChaining>0</externalIVChaining>
        <blockMACBytes>0</blockMACBytes>
        <blockMACRandBytes>0</blockMACRandBytes>
        <allowHoles>1</allowHoles>
        <encodedKeySize>52</encodedKeySize>
        <encodedKeyData>
qdS+nnbALzcKU6nJrOsNIdKXC1lm+zftCHCZ/i9MEIEAo2rKSFBAALFf4p/OZIjpDMCAdg==
</encodedKeyData>
        <saltLen>20</saltLen>
        <saltData>
fuqUHOx2jyzWULuGyXZlPzDQU8k=
</saltData>
        <kdfIterations>810947</kdfIterations>
        <desiredKDFDuration>500</desiredKDFDuration>
    </cfg>
</boost_serialization>
```

**Decoded/plaintext paths (`ref.lst`):**

```text
.
./file_2
./dir_1
./dir_1/file_2
./dir_1/subdir_1_2
./dir_1/file_1
./dir_1/file_1_1
./dir_1/subdir_1_1
./dir_1/subdir_1_1/subdir_1_1_1
./dir_1/subdir_1_1/subdir_1_1_1/file_1_1_1_1
./dir_1/subdir_1_1/subdir_1_1_1/file_1_1_1_2
./dir_2
./dir_2/file_2_2
./dir_2/file_2_1
./file_1
./file_3
```

**Encrypted paths on disk (`direct-chain.lst`):**

```text
.
./1QpokPhaq2sP9fqnVyHb63oP
./vlPAQlbHW8iyvhh4gs8eppL-
./vlPAQlbHW8iyvhh4gs8eppL-/u8BrrTBO3bLAq9fWdRV4QIAO
./vlPAQlbHW8iyvhh4gs8eppL-/hPbwFgbFfJNGJSsTqYKdhUiR
./vlPAQlbHW8iyvhh4gs8eppL-/a7zrejjvtPS8paPw1UFWYxRr
./vlPAQlbHW8iyvhh4gs8eppL-/RdDFrgOrF0yFV6QUYBTnVO66
./vlPAQlbHW8iyvhh4gs8eppL-/oOZ9j3QL4lRswpEVQGf6Ny1c
./vlPAQlbHW8iyvhh4gs8eppL-/oOZ9j3QL4lRswpEVQGf6Ny1c/cLDtXt1Ufws-0INnwfML59C2
./vlPAQlbHW8iyvhh4gs8eppL-/oOZ9j3QL4lRswpEVQGf6Ny1c/cLDtXt1Ufws-0INnwfML59C2/sgOS7jx30HFsP16qRQuw7nyH
./vlPAQlbHW8iyvhh4gs8eppL-/oOZ9j3QL4lRswpEVQGf6Ny1c/cLDtXt1Ufws-0INnwfML59C2/MDUS7lr0z6jXs9wdOtf9H70j
./IWBtJmkSxVFDvHJXigwaZ4b5
./IWBtJmkSxVFDvHJXigwaZ4b5/b4HDvevyCa0jZth5Dfx4LSwW
./IWBtJmkSxVFDvHJXigwaZ4b5/KxiZ-oknjKjvfVSMkdgz2tts
./Yt5Y4c5cTbKGjFhsIclgUtWR
./aK9lzQ-BuSOwugqXbTa0Dw5h
```

**Fixture generation and comparison:**

```sh
encfsctl encode --extpass="./encfs-pwd" direct-chain/ $(cat ref.lst)
```

The output should match `direct-chain.lst`. The historical record does not show a mount command used to create this fixture; it shows generation with `encfsctl encode`. To verify the decoded view by mounting, use a test copy and an empty `mnt/` directory:

```sh
ENCFS_TESTS_BASE=$(pwd)
printf '%s\n' 'test' | encfs --stdin "$ENCFS_TESTS_BASE/direct-chain" "$ENCFS_TESTS_BASE/mnt"
(cd "$ENCFS_TESTS_BASE/mnt" && find .)
fusermount -u "$ENCFS_TESTS_BASE/mnt"
```

The mounted listing should match `ref.lst`. This is a verification procedure, not an attested historical fixture-generation command.

## Test ID: REVERSE

**Purpose:** Convert plaintext names in `ref/` to encrypted names in the reverse view, then verify the mapping back to plaintext.

**Configuration file:** `reverse.encfs6.xml`

- `uniqueIV=0`
- `chainedNameIV=0`
- `externalIVChaining=0`
- `nameio/block` 4.0, AES 256-bit key, 1024-byte blocks
- Password: `test`, provided by `encfs-pwd`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE boost_serialization>
<boost_serialization signature="serialization::archive" version="7">
    <cfg class_id="0" tracking_level="0" version="20">
        <version>20100713</version>
        <creator>EncFS 1.9.5</creator>
        <cipherAlg class_id="1" tracking_level="0" version="0">
            <name>ssl/aes</name>
            <major>3</major>
            <minor>0</minor>
        </cipherAlg>
        <nameAlg>
            <name>nameio/block</name>
            <major>4</major>
            <minor>0</minor>
        </nameAlg>
        <keySize>256</keySize>
        <blockSize>1024</blockSize>
        <plainData>0</plainData>
        <uniqueIV>0</uniqueIV>
        <chainedNameIV>0</chainedNameIV>
        <externalIVChaining>0</externalIVChaining>
        <blockMACBytes>0</blockMACBytes>
        <blockMACRandBytes>0</blockMACRandBytes>
        <allowHoles>1</allowHoles>
        <encodedKeySize>52</encodedKeySize>
        <encodedKeyData>
KyGZY7/Kea/2xJHkU9N3OA6cjlrrRHbmtm7jsH37Q9n0AyW/5SuYL47UU0AV5npdkWLvLQ==
</encodedKeyData>
        <saltLen>20</saltLen>
        <saltData>
NfzU6ZHGwVhw3ak07AKuJkitWjE=
</saltData>
        <kdfIterations>864129</kdfIterations>
        <desiredKDFDuration>500</desiredKDFDuration>
    </cfg>
</boost_serialization>
```

**Decoded/plaintext paths (`ref.lst`):**

```text
.
./file_2
./dir_1
./dir_1/file_2
./dir_1/subdir_1_2
./dir_1/file_1
./dir_1/file_1_1
./dir_1/subdir_1_1
./dir_1/subdir_1_1/subdir_1_1_1
./dir_1/subdir_1_1/subdir_1_1_1/file_1_1_1_1
./dir_1/subdir_1_1/subdir_1_1_1/file_1_1_1_2
./dir_2
./dir_2/file_2_2
./dir_2/file_2_1
./file_1
./file_3
```

**Encrypted paths on disk and in the reverse view (`reverse.lst`):**

```text
.
./lZjTqL,V48jPmGK8WGR3ZMtg
./JUcVTLvBsEArt6cdvIMtB7mW
./H66ILBYrJBLqbX0bEDXoX29J
./H66ILBYrJBLqbX0bEDXoX29J/Cgk,2cTpQ41JHuaUaa51kS4l
./H66ILBYrJBLqbX0bEDXoX29J/sx8E,cmpqGv2X45TM004kXMS
./2D2lKBPbMQlkpfXjtKmTk03q
./2D2lKBPbMQlkpfXjtKmTk03q/JUcVTLvBsEArt6cdvIMtB7mW
./2D2lKBPbMQlkpfXjtKmTk03q/,EaGQELVnclL2U3F-0mrqX1R
./2D2lKBPbMQlkpfXjtKmTk03q/3ELM9Bw,T9a7fAo5BXqwFI6P
./2D2lKBPbMQlkpfXjtKmTk03q/3ELM9Bw,T9a7fAo5BXqwFI6P/MzGZCZlzPnRo6g19vlbajgzN
./2D2lKBPbMQlkpfXjtKmTk03q/3ELM9Bw,T9a7fAo5BXqwFI6P/MzGZCZlzPnRo6g19vlbajgzN/Z1L9YYRCuQ895Ve9IWjd2haM
./2D2lKBPbMQlkpfXjtKmTk03q/3ELM9Bw,T9a7fAo5BXqwFI6P/MzGZCZlzPnRo6g19vlbajgzN/wS8aDYK8gpnKd9J3y-Q1OZn5
./2D2lKBPbMQlkpfXjtKmTk03q/,tHdYiRaKrNBrOlYf1RSvnth
./2D2lKBPbMQlkpfXjtKmTk03q/umN7xtBFP7Ip5kYz0PL3MvlX
./umN7xtBFP7Ip5kYz0PL3MvlX
```

**Fixture generation and round trip:**

```sh
ENCFS6_CONFIG="$PWD/reverse.encfs6.xml" encfsctl decode --extpass="./encfs-pwd" --reverse ref/ $(cat ref.lst)
ENCFS6_CONFIG="$PWD/reverse.encfs6.xml" encfsctl encode --extpass="./encfs-pwd" --reverse ref/ $(cd reverse && find .)
```

The first command should produce `reverse.lst`; the second should reproduce `ref.lst`.

**Historical mount command:**

```sh
ENCFS6_CONFIG=~/encfs-tests/reverse.encfs6.xml encfs --reverse ~/encfs-tests/ref ~/encfs-tests/
```

The historical record then runs `find reverse/`, whose output is `reverse.lst`. This command mounts over the non-empty test root; do not rerun it as written. For a safe mount check, use an empty mount point:

```sh
ENCFS6_CONFIG="$PWD/reverse.encfs6.xml" encfs --reverse "$PWD/ref" "$PWD/mnt"
(cd mnt && find .)
fusermount -u "$PWD/mnt"
```

The listing under `mnt/` should match `reverse.lst`.


# Versions issues

Tests must be done with 1.9.5 implementation. 2.0 version is for now behaving differently.
Copilot has spotted some differences ibetween C++ and Rust version described in ./encfs-rust-cpp-differences.md

## Version 1.9.5 (match real filesystem test)

remi@novo:~/encfs-tests$ encfsctl --version
encfsctl version 1.9.5
remi@novo:~/encfs-tests$ encfsctl encode --extpass="./encfs-pwd" direct-nochain/ ./file_2
./w3kY9smoitBQoQpRpJ,0XN97

## Version master for 2.0 (built for windows by removing fuse dependancies)

PS D:\Dev\encfs\encfsnames> cd .\encfs-src\ ; git branch --show-current ; cd ..
master
PS D:\Dev\encfs\encfsnames> encfs-src\target\debug\encfsctl encode --extpass="./encfs-tests/encfs-pwd.exe" .\encfs-tests\direct-nochain\ ./file_2
1QpokPhaq2sP9fqnVyHb63oP
