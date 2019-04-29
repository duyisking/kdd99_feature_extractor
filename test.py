#!/usr/bin/python
import mmap
import os

count = 0
with open('/tmp/kdd99extractor_connection_queue.bin', 'r+b') as file:
    mm = mmap.mmap(file.fileno(), 0)
    try:
        while True:
            try:
                flag = mm.read(1)
                if flag[0] != 0:
                    mm.seek(-1, os.SEEK_CUR)
                    mm.write_byte(0)
                    data = mm.read(255)
                    count += 1
                    # print(data.decode('unicode_escape'))
                else:
                    mm.seek(-1, os.SEEK_CUR)
            except IndexError:
                mm.seek(0)
    except KeyboardInterrupt:
        print(count)
    mm.close()
