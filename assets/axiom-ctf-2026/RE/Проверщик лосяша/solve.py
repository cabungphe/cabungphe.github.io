import hashlib
import string
import itertools
import time
import sys
import logging
from multiprocessing import Pool, cpu_count

# Cấu hình logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Mảng chứa 128 ký tự hex gốc từ IDA/Ghidra
TARGET_HASHES = [
    "519ef2c4dc55d3556abf0c41eb1e3c6fdb8f96590a9fcdae9940a17ba9dfc3664ec4de37feeb485f772f6589cdf44201ec92997bd254c1755bf812761f992435",
    "730a5983f1d3af2ca2dedc3ed87fdb0dce96bcc3356cc195658ac10b299ab00364b8a0e2e103c93a703dc9d1fe6e3d186e1a071a290d09e9c67ba5891a2e6188",
    "d8e14db2e6f41ba7e45e1ade2a62174af59bf3a943c7116d364142b240b9908ac9e88b6298a5f7ea6a082f7fd52668d46cd23cf085635e78a8500c48f3dbf6a8",
    "efd0214ac40851fbc4e203eac495f768c918c1d2708dda246442f507b3d05f36c6817aa2b61a5d29d33c3caa76acc69a7b8f48066117750808ff28eb8329b4fc",
    "34f501ced23a6b807cdd375dbe31ead23f2091011614f74ee44361e4cb2730523b91982bad19f6942b3a1505340224b3370ef4848db4f4dcbda32017769270be",
    "01de645a8cf584aaae8ff6d2e264fd5193a8aec19d30c935344a84885b250c81c9858de3be220e659f04586ffba90f8cab978e551306835abdabed7eca9a1803",
    "c4a653abc68a83d636faaa85496122aa54f6152cff1659183bafd39c2fbc5ffde7f66b142a718089d8600ec1f9a3b1854ddbbd33c923d2d9087284e2d275e7c0",
    "02857289f5ae4501a7d50c2615a2e1b8182a937c723ea2fa071e9e34bf86866b5a51902d726d1bbe7c824ea2873e8d3ef227e34bbe62c7b826288e9ec42092b6"
]

SALTS = ["faCT", "paX6", "eMGP", "ts4k", "vtfD", "PETQ", "kNxY", "Zoa8"]

# Bộ ký tự chuẩn thường gặp trong CTF
CHARSET = string.ascii_letters + string.digits + "{}_-!@#?"

def crack_chunk(args):
    chunk_index, target_hash, salt = args
    logger.info(f"[*] Đang xử lý Chunk {chunk_index + 1}/8 (Salt: {salt})...")

    target_prefix = target_hash[:64]

    for combo in itertools.product(CHARSET, repeat=4):
        guess = "".join(combo)
        test_string = guess + salt

        hashed = hashlib.sha3_512(test_string.encode('utf-8')).hexdigest()

        if hashed[:64] == target_prefix:
            logger.info(f"[+] TÌM THẤY: '{guess}'")
            return guess

    logger.warning("[-] Thất bại! Không tìm thấy kết quả phù hợp.")
    return None

def main():
    logger.info("=== BẮT ĐẦU CHƯƠNG TRÌNH KHÔI PHỤC FLAG (SHA3-512) ===")
    start_time = time.time()

    with Pool(processes=cpu_count()) as pool:
        args = [(i, TARGET_HASHES[i], SALTS[i]) for i in range(8)]
        results = pool.map(crack_chunk, args)

    if None in results:
        logger.error("\n!!! Có lỗi xảy ra, không tìm thấy chuỗi khớp.")
        sys.exit(1)

    recovered_flag = "".join(results)
    end_time = time.time()

    logger.info("\n" + "="*50)
    logger.info(f"🎉 FLAG HOÀN CHỈNH: {recovered_flag}")
    logger.info(f"⏱️ Thời gian thực thi: {round(end_time - start_time, 2)} giây")
    logger.info("="*50)

if __name__ == "__main__":
    main()