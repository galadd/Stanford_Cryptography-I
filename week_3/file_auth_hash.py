import os
from Crypto.Hash import SHA256

def main():
    block_size = 1024
    file_path1 = "week_3/6.1.intro.mp4"
    file_path2 = "week_3/6.2.birthday.mp4"
    expected_hash = "03c08f4ee0b576fe319338139c045c89c3e8e9409633bea29442e21425006ea8"

    # Calculate hash of file_path2 and compare with expected hash
    actual_hash = calculate_file_hash(file_path2, block_size)
    if actual_hash == expected_hash:
        print("Birthday hash matches hash check")
    else:
        print("Hash check failed")

    # Calculate hash of file_path1
    intro_hash = calculate_file_hash(file_path1, block_size)
    print(f"Intro Hash: {intro_hash}")


def calculate_file_hash(file_path, block_size):
    file_size = os.path.getsize(file_path)
    last_block_size = file_size % block_size

    with open(file_path, 'rb') as file:
        last_hash = b''
        for chunk in read_reversed_chunks(file, file_size, last_block_size, block_size):
            sha256 = SHA256.new()
            sha256.update(chunk)
            if last_hash:
                sha256.update(last_hash)
            last_hash = sha256.digest()

    return last_hash.hex()


def read_reversed_chunks(file_object, file_size, last_chunk_size, chunk_size):
    iter_count = 0
    last_pos = file_size
    while last_pos > 0:
        size = chunk_size if iter_count > 0 else last_chunk_size
        file_object.seek(last_pos - size)
        data = file_object.read(chunk_size)
        if not data:
            break
        iter_count += 1
        last_pos -= size
        yield data





if __name__ == '__main__':
    main()
