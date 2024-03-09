import datetime
import hashlib
import sys
import os
import zlib


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


def clone():
    url = sys.argv[2]
    folder = sys.argv[3]
    print(url)
    print(folder)


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
