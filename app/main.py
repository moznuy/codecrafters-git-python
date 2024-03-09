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
    # Raw bytes output:
    sys.stdout.buffer.write(content)
    sys.stdout.flush()


def main():
    command = sys.argv[1]
    if command == "init":
        init()
    elif command == "cat-file":
        cat_file()
    else:
        raise RuntimeError(f"Unknown command #{command}")


if __name__ == "__main__":
    main()
