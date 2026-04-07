# Motivation
The core problem is the massive speed difference between the **CPU** and **Main Memory (DRAM)**. The CPU is incredibly fast, while DRAM is relatively slow. This gap, often called the "Memory Wall," would cause the CPU to constantly wait for data, wasting its potential.

**Cache** is the solution. It's a small, extremely fast, and expensive type of memory (SRAM) that acts as a buffer between the CPU and DRAM. It stores copies of recently or frequently accessed data and instructions.

The goal is to bridge the speed gap by keeping the data the CPU is likely to need next in this fast cache, making memory access appear much faster on average.

![[Pasted image 20250609184803.png|800]]
# Principle of Locality
Caches are effective because programs exhibit the **principle of locality**: they tend to access a small portion of their address space at any given time.
## Temporal Locality (Locality in Time)
If a memory location is accessed, it is likely to be accessed again in the near future.
**Example:** Variables in a loop, instructions in a loop.
## Spatial Locality (Locality in Space)
If a memory location is accessed, memory locations nearby are likely to be accessed soon.
**Example:** Iterating through an array (`a[i]`, `a[i+1]`, etc.), executing sequential instructions.
# Cache Mechanics: Hits, Misses, and Blocks
## How it Works
* Memory is conceptually divided into fixed-size chunks called **blocks**.
* The cache is organized into **lines**, where each line can hold exactly one memory block.
* When the CPU requests data from an address, the cache hardware checks if the block containing that address is already in one of its lines.

![[Pasted image 20250609195200.png|800]]

![[Pasted image 20250609195036.png|800]]

![[Pasted image 20250609195315.png|800]]
## Cache Hit
The requested data is found in the cache. This is the desired outcome and is very fast. The time taken is the **Hit Time**.
## Cache Miss
The requested data is *not* in the cache. This is slow. The system must:
1.  Stall the CPU.
2.  Fetch the entire block containing the data from the slower main memory.
3.  Place this new block into a cache line (possibly evicting an existing block).
4.  Deliver the requested data to the CPU.

The extra time required for this process is called the **Miss Penalty**.
# Organization
The way memory blocks are mapped to cache lines is crucial. This is defined by the cache's architecture. To understand this, we must first understand how a memory address is interpreted by the cache.
## Address Splitting: Tag, Index, Offset
A memory address is broken down into three parts:

* **Offset:** Identifies the specific byte *within* a block. The number of offset bits is `log₂(Block Size)`.
* **Index:** Identifies the specific cache line (or set of lines) where the block *might* be stored.
* **Tag:** The remaining bits of the address. Used to verify if the block stored at a given index is the correct one we're looking for.

`|-- TAG --|-- INDEX --|-- OFFSET --|`
## Fully Associative
Any memory block can be stored in **any** cache line. This is the most flexible model.

* **Address Split:** `|-- TAG --|-- OFFSET --|` (No index bits).
* **Lookup Process:** To find a block, the hardware must check the tag of **every single line in the cache** simultaneously.
* **Pros:**
    * Highest possible hit rate because it's the most flexible. Eliminates conflict misses.
    * Allows for advanced replacement strategies (like perfect LRU).
* **Cons:**
    * Extremely expensive and complex hardware. Requires one comparator for every cache line.
    * Doesn't scale well to large caches.

![[Pasted image 20250609200008.png|600]]

![[Pasted image 20250609200022.png|600]]

## Direct-Mapped
Each memory block can only be stored in **one specific** cache line. The mapping is fixed.

* **Mapping Formula:** `Cache Line = (Block Number) mod (Total Number of Cache Lines)`.
* **Address Split:** `|-- TAG --|-- INDEX --|-- OFFSET --|`. The index bits directly determine the one and only line to check.
* **Lookup Process:** Use the index bits to go to a single cache line. Compare the address tag with the tag stored in that line.
* **Pros:**
    * Very simple, fast, and cheap hardware (needs only one comparator).
* **Cons:**
    * Suffers from **conflict misses**. If a program frequently accesses two different blocks that map to the same cache line, they will constantly evict each other, causing many misses even if the rest of the cache is empty.

![[Pasted image 20250609200221.png|600]]

![[Pasted image 20250609200933.png|600]]

![[Pasted image 20250609200336.png|600]]
## N-Way Set-Associative
A compromise between the other two models, and the most common architecture used today.

* **Concept:** The cache is divided into **sets**, and each set contains **N** lines. A memory block can be stored in **any of the N lines** within its assigned set.
    * Direct-mapped is a special case where N=1.
    * Fully associative is a special case where there is only one set (N = total number of lines).
* **Mapping Formula:** `Set = (Block Number) mod (Total Number of Sets)`.
* **Address Split:** `|-- TAG --|-- INDEX --|-- OFFSET --|`. The index selects the set.
* **Lookup Process:** Use the index bits to select a set. Then, compare the address tag with the tags of all **N lines** within that set simultaneously.
* **Pros:**
    * Drastically reduces conflict misses compared to direct-mapped.
    * A good balance between performance and hardware cost.
* **Cons:**
    * More complex than direct-mapped (requires N comparators).

![[Pasted image 20250609200909.png|600]]

![[Pasted image 20250609200852.png|600]]

![[Pasted image 20250609200831.png|600]]
## Comparison
![[Pasted image 20250609201904.png|800]]
# Performance & Misses
## Metrics
### Hit Rate
The **hit rate** is the fraction of memory references that are successfully found in the cache.

$hit\_rate = \frac{nr\_of\_hits}{nr\_of\_accesses}$.
### Miss Rate
The **miss rate** is the fraction of memory references that are not found in the cache. It can be calculated as:

$miss\_rate = \frac{nr\_of\_misses}{nr\_of\_accesses}$.

$miss\_rate = 1 - hit\_rate$.
### Average Memory Access Time (AMAT)
The average memory access time is the effective time to access data, accounting for both hits and misses. It is calculated using the **hit time** (time to deliver a block from the cache) and the **miss penalty** (additional time required to fetch data from memory after a miss ). The formula is:

$AMAT = (Hit \ Time) + (Miss \ Rate \times Miss \ Penalty)$.
### Example
A high cache hit rate is crucial for performance. A system with a 99% hit rate can be twice as fast as one with a 97% hit rate.

**Given:**
* **Cache hit time**: 1 processor cycle.
* **Miss penalty**: 100 processor cycles.

**Calculations:**
* **Average access time with 97% hits** (3% miss rate):
    * $1 \ cycle + (0.03 \times 100 \ cycles) = 4 \ cycles$.
* **Average access time with 99% hits** (1% miss rate):
    * $1 \ cycle + (0.01 \times 100 \ cycles) = 2 \ cycles$.
## Cache Misses
### Cold (Compulsory) Miss
The very first access to a block. These are unavoidable; the block has to be loaded once.
### Capacity Miss
Occurs because the cache is not large enough to hold all the data required by the program's "working set". The working set is larger than the cache.
### Conflict Miss
Occurs when two or more blocks that are in use map to the same cache line (in direct-mapped) or set (in set-associative). The blocks evict each other. This would not happen in a fully associative cache of the same size.
# Management Policies
## Replacement Strategies (for N-Way and Fully Associative)
When a miss occurs and the target set is full, a line must be chosen for eviction.
* **LRU (Least Recently Used):** Evict the block that has been unused for the longest time. Offers great performance but requires complex hardware to track usage.
* **FIFO (First-In, First-Out):** Evict the block that has been in the cache the longest. Simple to implement with a queue.
* **Random:** Evict a randomly chosen line. Very simple and surprisingly effective, avoiding pathological cases that can trick LRU or FIFO.
### Write Strategies
This handles what happens when the CPU writes to memory.
### On Write Hit
* **Write-Through:** Update the cache line AND the main memory immediately.
    * **Pro:** Simple. Main memory is always consistent.
    * **Con:** Slow, as every write must wait for slow DRAM.
* **Write-Back:** Update only the cache line and mark it as "dirty" (using a *dirty bit*). The data is written back to main memory only when the dirty line is evicted.
    * **Pro:** Very fast. Multiple writes to the same block only require one final write to DRAM.
    * **Con:** More complex. Main memory can be out of date (inconsistent).
### On Write Miss
* **Write-Allocate:** Fetch the block from memory into the cache, then perform the write (turning it into a write hit). This is almost always paired with **Write-Back**. It leverages spatial locality for subsequent writes.
* **No-Write-Allocate (Write-Around):** Write the data directly to main memory, bypassing the cache entirely. This is almost always paired with **Write-Through**.
# Programmer's Perspective
You can significantly improve performance by writing **cache-friendly code**. The goal is to maximize locality.

* **Focus on Spatial Locality:** Access memory sequentially.
* **Example: 2D Array Traversal:** In C/C++/Java, arrays are stored in **row-major order**. This means elements in the same row are contiguous in memory.
    * `array[i][j]` and `array[i][j+1]` are right next to each other.
    * `array[i][j]` and `array[i+1][j]` can be thousands of bytes apart.
## Bad Code (poor spatial locality)
```c
// Jumps through memory, causing a cache miss on almost every access.
for (int j = 0; j < COLS; j++) {
    for (int i = 0; i < ROWS; i++) {
        array[i][j] = ...;
    }
}
    ```
## Good Code (excellent spatial locality)
```c
// Moves sequentially through memory, maximizing cache hits.
for (int i = 0; i < ROWS; i++) {
    for (int j = 0; j < COLS; j++) {
        array[i][j] = ...;
    }
}
    ```