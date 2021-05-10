# TODO: this is a test, refactor me into a program or a notebook
import hashlib
import os
import time
import matplotlib.pyplot as plt
import base64

collision = 0
for _ in range(1000):
    lookup_table = {}
    for _ in range(16):
        random_binary = os.urandom(16)
        result = hashlib.md5(random_binary).digest()
        result = result[:1]
        if result not in lookup_table:
            lookup_table[result] = random_binary
        else:
            collision += 1
            break

def dict_size(size):
    start = time.time()
    dict = {}
    for i in range(size):
        if i in dict:
            print("HIT")
        else:
            dict[i] = 0

    return time.time() - start

def main(bit_range):
    start = time.time()
    collision_count = 0
    # Each space_size counts for 4 bits, hence we have
    space_size = bit_range//4
    for _ in range(100):
        lookup_table = {}
        # Searching half the sqrt of the space for collision
        # sqrt(2**bit_range) = 2**(bit_range//2)
        for _ in range(2**(bit_range//2)):
            random_binary = os.urandom(16)
            result = hashlib.md5(random_binary).hexdigest()
            result = result[:space_size]
            if result in lookup_table:
                collision_count += 1
                break
            else:
                lookup_table[result] = random_binary

    return time.time() - start, collision_count


x = []
y = []
y1 = []
y2 = []
for i in range(0, 2**20, 2**12):
    performance = dict_size(i)
    x.append(i)
    y.append(performance)

plt.scatter(x, y, alpha=0.1)
plt.xlabel("Size")
plt.ylabel("Time (sec)")
plt.show()

_, ax1 = plt.subplots()
plt.xlabel("Size")
plt.ylabel("Time (sec)")
ax1.scatter(x, y1)
ax2 = ax1.twinx()
ax2.bar(x, y2, align='center', alpha=0.5, color='red')
ax2.set_ylabel("Collision rate (%)", color='red')
ax2.set_ylim([0, 100])

plt.show()

def get_uid(text):
    result = hashlib.md5(text.encode()).digest()
    result = base64.b64encode(result)
    return result[:4]


uid = get_uid("my text")
print(uid)

for _ in range(4096):
    text = os.urandom(16)
    uid = get_uid(text)
    if uid in lookup_table:
        print("Collision detected")
    else:
        lookup_table[uid] = text