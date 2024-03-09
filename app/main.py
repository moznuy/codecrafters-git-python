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
    header, content = raw_content.split(b'\0', maxsplit=1)

    file_type: str
    size_raw: str
    file_type, size_raw = header.decode().split(maxsplit=1)
    size = int(size_raw)
    assert file_type == 'blob'
    assert size == len(content)

    # Raw bytes output:
    sys.stdout.buffer.write(content)
    sys.stdout.flush()


def hash_object():
    w = sys.argv[2]
    filename = sys.argv[3]
    assert w == "-w"

    with open(filename, "rb") as f:
        content = f.read()

    size = len(content)
    header = f"blob {size}".encode()
    raw_content = header + b'\0' + content
    digest = hashlib.sha1(raw_content).hexdigest()
    compressed = zlib.compress(raw_content)

    folder, file = digest[:2], digest[2:]

    os.makedirs(f".git/objects/{folder}", exist_ok=True)
    with open(f".git/objects/{folder}/{file}", 'wb') as f:
        f.write(compressed)
    print(digest)


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
    header, content = raw_content.split(b'\0', maxsplit=1)

    file_type: str
    size_raw: str
    file_type, size_raw = header.decode().split(maxsplit=1)
    size = int(size_raw)
    assert file_type == 'tree'
    assert size == len(content)

    while True:
        if not content:
            break
        file_header: bytes
        rest: bytes
        file_sha: bytes
        file_header, rest = content.split(b'\0', maxsplit=1)
        file_sha, content = rest[:20], rest[20:]
        mode, filename = file_header.decode().split()
        hex_digest = file_sha.hex()
        # print(mode, filename, hex_digest)
        print(filename)



def main():
    command = sys.argv[1]
    if command == "init":
        init()
    elif command == "cat-file":
        cat_file()
    elif command == "hash-object":
        hash_object()
    elif command == "ls-tree":
        ls_tree()
    else:
        raise RuntimeError(f"Unknown command #{command}")


if __name__ == "__main__":
    main()
