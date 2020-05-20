import math
import os

from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from time import perf_counter

import ursa_bbs as bbs


def log(msg: str, *vals):
    print(msg, *vals)
    print()


tot_1 = 0.0
tot_2 = 0.0


def random_cred(message, count, dpk, sk):
    global tot_1, tot_2
    messages = [message] * count

    start = perf_counter()
    pk = dpk.to_public_key(len(messages))
    tot_1 += perf_counter() - start
    start = perf_counter()

    signature = bbs.sign_messages(messages, sk, pk)
    tot_2 += perf_counter() - start
    return signature


def make_many_creds(rounds: int, msg_len: int = 100, msg_count: int = 10):
    dpk, sk = bbs.generate_bls_keypair()
    message = os.urandom(msg_len)

    workers = 16
    executor = ThreadPoolExecutor(workers)
    start = perf_counter()
    futures = [
        executor.submit(random_cred, message, msg_count, dpk, sk)
        for i in range(min(rounds, workers))
    ]
    sent = len(futures)
    while futures:
        (done, not_done) = wait(futures, timeout=None, return_when=FIRST_COMPLETED)
        for check in done:
            check.result()
        add = min(rounds - sent, workers - len(not_done))
        if add:
            futures = list(not_done) + list(
                executor.submit(random_cred, message, msg_count, dpk, sk)
                for i in range(add)
            )
            prev = sent
            sent += add
            if math.floor(prev / 100) != math.floor(sent / 100):
                print(sent)
        else:
            futures = not_done
    end = perf_counter()
    per_sec = rounds / (end - start)
    print(end - start, "avg:", 1 / per_sec, " per sec: ", per_sec)

    print("key total time:", tot_1)
    print("sig total time:", tot_2)


if __name__ == "__main__":
    make_many_creds(10000, 100, 10)
