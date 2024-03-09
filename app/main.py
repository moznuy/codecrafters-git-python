import datetime
import hashlib
import sys
import os
import urllib.request
import zlib
from typing import Iterator


def init():
    os.mkdir(".git")
    os.mkdir(".git/objects")
    os.mkdir(".git/refs")
    with open(".git/HEAD", "w") as f:
        f.write("ref: refs/heads/main\n")
    print("Initialized git directory")


def cat_file():
    p = sys.argv[2]
    revision = sys.argv[3]
    assert p == "-p"

    folder, file = revision[:2], revision[2:]
    with open(f".git/objects/{folder}/{file}", "rb") as f:
        compressed = f.read()
    raw_content = zlib.decompress(compressed)

    header: bytes
    content: bytes
    header, content = raw_content.split(b"\0", maxsplit=1)

    file_type: str
    size_raw: str
    file_type, size_raw = header.decode().split(maxsplit=1)
    size = int(size_raw)
    assert file_type == "blob"
    assert size == len(content)

    # Raw bytes output:
    sys.stdout.buffer.write(content)
    sys.stdout.flush()


def hash_object(filename: str = None) -> str:
    if filename is None:
        w = sys.argv[2]
        filename = sys.argv[3]
        assert w == "-w"

    with open(filename, "rb") as f:
        content = f.read()

    size = len(content)
    header = f"blob {size}".encode()
    raw_content = header + b"\0" + content
    digest = hashlib.sha1(raw_content).hexdigest()
    compressed = zlib.compress(raw_content)

    folder, file = digest[:2], digest[2:]

    os.makedirs(f".git/objects/{folder}", exist_ok=True)
    with open(f".git/objects/{folder}/{file}", "wb") as f:
        f.write(compressed)
    return digest


def ls_tree():
    # TODO: same code
    no = sys.argv[2]
    revision = sys.argv[3]
    assert no == "--name-only"

    folder, file = revision[:2], revision[2:]
    with open(f".git/objects/{folder}/{file}", "rb") as f:
        compressed = f.read()
    raw_content = zlib.decompress(compressed)

    header: bytes
    content: bytes
    header, content = raw_content.split(b"\0", maxsplit=1)

    file_type: str
    size_raw: str
    file_type, size_raw = header.decode().split(maxsplit=1)
    size = int(size_raw)
    assert file_type == "tree"
    assert size == len(content)

    while True:
        if not content:
            break
        file_header: bytes
        rest: bytes
        file_sha: bytes
        file_header, rest = content.split(b"\0", maxsplit=1)
        file_sha, content = rest[:20], rest[20:]
        mode, filename = file_header.decode().split()
        hex_digest = file_sha.hex()
        # print(mode, filename, hex_digest)
        print(filename)


def write_tree(path: str) -> str:
    entries: dict[str, bytes] = {}
    for entry in os.scandir(path):
        if entry.name == ".git":
            continue

        # digest: str = ''
        # name: str = ''
        # mode: str = ''

        if entry.is_file():
            digest = hash_object(os.path.join(path, entry.name))
            name = entry.name
            #          1   0   0   6   4   4
            mode = 0b001_000_000_110_100_100
            # mode = '100644'
        else:
            digest = write_tree(os.path.join(path, entry.name))
            name = entry.name
            # TODO: not '040000' for some reason
            # TODO: octal format
            #          0   4   0   0   0   0
            mode = 0b000_100_000_000_000_000
            # mode = '40000'

        entries[name] = f"{mode:o} {name}".encode() + b"\0" + bytes.fromhex(digest)

    content: bytes
    result = [value for key, value in sorted(entries.items())]
    content = b"".join(result)

    # Same code
    size = len(content)
    header = f"tree {size}".encode()
    raw_content = header + b"\0" + content

    digest = hashlib.sha1(raw_content).hexdigest()
    compressed = zlib.compress(raw_content)

    folder, file = digest[:2], digest[2:]

    os.makedirs(f".git/objects/{folder}", exist_ok=True)
    with open(f".git/objects/{folder}/{file}", "wb") as f:
        f.write(compressed)
    return digest


def commit_tree():
    tree = sys.argv[2]
    p = sys.argv[3]
    parent = sys.argv[4]
    m = sys.argv[5]
    message = sys.argv[6]
    assert p == "-p"
    assert m == "-m"
    author = "Serhii Charykov <laammaar@gmail.com>"
    timestamp = datetime.datetime.now(tz=datetime.UTC).timestamp()
    # TODO: get proper offset
    tz_offset = "+0000"

    content: bytes = b""
    content += f"tree {tree}\n".encode()
    content += f"parent {parent}\n".encode()
    content += f"author {author} {timestamp} {tz_offset}\n".encode()
    content += f"committer {author} {timestamp} {tz_offset}\n".encode()
    content += f"\n".encode()
    content += message.encode()
    content += f"\n".encode()

    # Same code
    size = len(content)
    header = f"commit {size}".encode()
    raw_content = header + b"\0" + content

    digest = hashlib.sha1(raw_content).hexdigest()
    compressed = zlib.compress(raw_content)

    folder, file = digest[:2], digest[2:]

    os.makedirs(f".git/objects/{folder}", exist_ok=True)
    with open(f".git/objects/{folder}/{file}", "wb") as f:
        f.write(compressed)

    return digest


def parse_lines(data: bytes) -> Iterator[bytes]:
    while True:
        if not data:
            break

        if data.startswith(b'PACK'):
            yield data
            # TODO: what if something after data
            break

        length_raw: bytes
        length_raw, data = data[:4], data[4:]
        length = int.from_bytes(bytes.fromhex(length_raw.decode()))

        if length == 0:
            yield b''
            continue

        length -= 4
        assert length > 0
        assert length <= 2**32
        line, data = data[:length], data[length:]
        yield line.rstrip()


def read_length(data: bytes) -> tuple[int, int, bytes]:
    length_raw = ''
    data_type: int = 0
    while True:
        byte, data = data[0], data[1:]

        if not data_type:
            data_type = (byte & 0b0111_0000) >> 4
            length_raw = format(byte & 0b0000_1111, '04b')
        else:
            tmp = format(byte & 0b0111_1111, '07b')
            length_raw = tmp + length_raw

        if not byte & 0b1000_0000:
            break
    result = int(length_raw, 2)
    return result, data_type, data


def read_size(data: bytes) -> tuple[int, bytes]:
    length_raw = ''
    while True:
        byte, data = data[0], data[1:]

        tmp = format(byte & 0b0111_1111, '07b')
        length_raw = tmp + length_raw

        if not byte & 0b1000_0000:
            break
    result = int(length_raw, 2)
    return result, data


types = {
    1: 'commit',
    2: 'tree',
    3: 'blob',
    4: 'tag',
    6: "ofs_delta",
    7: "ref_delta",
}

def parse_data(data: bytes):
    signature, data = data[:4], data[4:]
    assert signature == b'PACK'

    version_raw, data = data[:4], data[4:]
    version = int.from_bytes(version_raw)
    assert version == 2

    object_count_raw, data = data[:4], data[4:]
    object_count = int.from_bytes(object_count_raw)
    print(f"{object_count=}")

    for object_index in range(object_count):
        # print(f"{object_index} {len(data)=}")
        length, data_type, data = read_length(data)
        assert data_type in types, f"Unexpected type {data_type}"

        print(types[data_type], end=' ')

        # not delta
        ref_to = ''
        if data_type > 5:
            ref_to_raw, data = data[:20], data[20:]
            ref_to = ref_to_raw.hex()

        dec = zlib.decompressobj()
        decompressed = b''
        while True:
            decompressed += dec.decompress(data)
            if dec.eof:
                data = dec.unused_data
                break
        assert len(decompressed) == length
        print(ref_to, length, decompressed)

        # original_data = data
        #
        # dec = zlib.decompressobj()
        # dec.decompress(data)
        #
        # length1, data = read_size(data)
        # length2, data = read_size(data)
        # print(length1, length2)
        # data = original_data[lengt0:]
        # # delta format
        # name, data = data[:20], data[20:]
        # delta_raw, data = data[:length-20], data[length-20:]





def prepare_line(s: str) -> bytes:
    if not s:
        return b'0000'
    s += '\n'
    raw = s.encode()
    length = len(raw) + 4
    raw_length = length.to_bytes(2).hex().encode()
    return raw_length + raw


def clone():
    url = sys.argv[2]
    folder = sys.argv[3]

    refs_url = f'{url}/info/refs?service=git-upload-pack'
    # with urllib.request.urlopen(refs_url) as f:
    #     data = f.read()

    capabilities = b''

    with open('tmp', 'rb') as f:
        data = f.read()

    refs: dict[str, str] = {}
    for line in parse_lines(data):
        if not line:
            continue
        if line.startswith(b'#'):
            continue
        ref: bytes
        digest: bytes
        rest: bytes
        digest, rest = line.split(b' ', maxsplit=1)
        if not capabilities:
            ref, capabilities = rest.split(b'\0')
            # print(capabilities)
        else:
            ref = rest
        refs[ref.decode()] = digest.decode()

    head_ref = refs['HEAD']
    data = b''
    data += prepare_line(f'want {head_ref}')
    data += prepare_line('')
    data += prepare_line('done')

    data_url = f'{url}/git-upload-pack'

    # with urllib.request.urlopen(data_url, data) as f:
    #     data = f.read()

    with open('tmp2', 'rb') as f:
        data = f.read()

    lines = list(parse_lines(data))
    assert lines[0] == b'NAK'
    assert lines[1].startswith(b'PACK')
    assert len(lines) == 2

    packed_data = lines[1]
    parse_data(packed_data)


def main():
    command = sys.argv[1]
    if command == "init":
        init()
    elif command == "cat-file":
        cat_file()
    elif command == "hash-object":
        print(hash_object())
    elif command == "ls-tree":
        ls_tree()
    elif command == "write-tree":
        print(write_tree("."))
    elif command == "commit-tree":
        print(commit_tree())
    elif command == "clone":
        clone()
    else:
        raise RuntimeError(f"Unknown command #{command}")


if __name__ == "__main__":
    main()
