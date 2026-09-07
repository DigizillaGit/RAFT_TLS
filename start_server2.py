#!/usr/bin/env python
from raft import RaftNode
import json
import time

address_book_fname = 'address_book.json'

if __name__ == '__main__':
    s0 = RaftNode(address_book_fname, 'node2', 'follower')

    s0.start()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        s0.stop()