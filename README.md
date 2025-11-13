# CS 1501 — Assignment 4: PittGuard: Vulnerability Traversal and Patch Reach

> ⚙️ *Note:* This assignment was developed with the help of **OpenAI ChatGPT** to brainstorm and generate parts of the scaffolding and documentation files to speed up prototyping.

## 🔐 Security Context

In cybersecurity, malware propagation refers to the way malicious software spreads across a network by exploiting weak or vulnerable hosts—machines with unpatched software, poor access control, or weak encryption. Once a single vulnerable node is compromised, malware can traverse connected vulnerable systems, causing rapid infection and network-wide disruption. Conversely, patching represents the defensive counterpart: the timely deployment of security updates from trusted servers to seal vulnerabilities and prevent further spread. In this assignment, BFS traversal models how quickly malware could move through an unprotected network, while the Dijkstra's-based patching model captures how efficiently security updates can be distributed to mitigate those vulnerabilities. Together, they highlight the critical race between attack and defense in maintaining a resilient, well-protected system.

## 📘 Objective

In this assignment, you will implement a lightweight network analysis tool, **PittGuard**, to explore how vulnerabilities affect communication and patch distribution within a computer network. Using two complementary graph algorithms, you will analyze:

1. 🦠 How malware can propagate **only through vulnerable machines** using **Breadth-First Search (BFS)**
2. 🩹 How efficiently a designated **patch server** can reach all vulnerable machines using **Dijkstra’s algorithm**, with effective edge costs based on **latency** and **encryption strength**

Together, these components model the dual challenge of understanding how weaknesses spread and how quickly a secure patch can be deployed.
The goal is to practice **graph traversal** and **shortest-path computation** under realistic network constraints, reinforcing your ability to design algorithmic solutions with clear performance guarantees and meaningful security interpretations.

> 💡 **Tip:** You may reuse parts of your **BFS** and **Dijkstra’s Lab code**.

---

# 🧠 Task 1 — Simulating Malware Propagation

## 🧾 Overview

Implement a BFS that explores **only nodes whose vulnerability flag is `true`**, as defined in the **common file format** (see *Graph File Format* below).
Before running BFS, **filter** the graph so that:

* ✅ You **keep a vertex** only if its vulnerability flag is `true`.
* 🔗 You **keep an edge** only if **both endpoints** are vulnerable (for directed graphs, keep an arc only if both endpoints are vulnerable and preserve the original direction).

The program outputs a **single integer**: the minimum number of **hops** (edges) from `--src` to `--dst` after filtering, or `-1` if no such path exists.

---

## 💻 Command-Line Interface

Run the program as:

```bash
java PittGuard --mode infect \
  --input <TestFiles/graph.txt> \
  --src <NODE> \
  --dst <NODE> \
  [--directed]
```

### ⚙️ Required Flags

* `--mode infect` → selects malware propagation simulation
* `--input <file>` → path to graph file (common file format)
* `--src <NODE>` and `--dst <NODE>` → start and target nodes for traversal

### ⚙️ Optional Flag

* `--directed` → interpret edges as directed (default: undirected)

---

## 🧾 Output Format

Print **exactly one line** with a single integer:

* `0` → if `src == dst` and both are vulnerable
* Positive integer → number of edges on the shortest vulnerable-only path from `src` to `dst`
* `-1` → if `dst` unreachable or either endpoint is non-vulnerable

The program must return **exit code 0** for all valid inputs (even when printing `-1`).
For malformed inputs (e.g., unknown node or incorrect file format), exit **non-zero** and print a clear error message to `stderr`.

---

## 🧪 Examples (CLI + Outputs)

Input file `sample.txt`:

```
5
# Nodes (format: node vulnerable?)
A false
B false
C true
D false
E true

# Edges (format: node1 node2 latency encryption_level)
A B 4 3
A C 2 2
B D 3 2
C D 1 3
D E 5 1
C E 7 3
```

### ✅ Example 1 — Destination reachable

```bash
java PittGuard --mode infect --input TestFiles/sample.txt --src C --dst E
```

**Output:**

```
1
```

### ⚠️ Example 2 — Non-vulnerable endpoint

```bash
java PittGuard --mode infect --input TestFiles/sample.txt --src C --dst D
```

**Output:**

```
-1
```

### 🔁 Example 3 — Same node

```bash
java PittGuard --mode infect --input TestFiles/sample.txt --src C --dst C
```

**Output:**

```
0
```

---

# ⚡ Task 2 — Simulating Patching of Vulnerable Nodes

## 🧾 Overview

Compute how quickly a designated **patch server** can reach all vulnerable machines using **Dijkstra’s Shortest Paths** algorithm, with effective edge costs modeling latency and encryption strength.
The task outputs a **single numeric value**: the **maximum shortest-path cost (radius)** from the server to every vulnerable node.
If any vulnerable node is unreachable under the relay rules, return `INF`.

---

## 🔒 Effective Edge Cost

```
effective_cost(e) = latency(e) * (1 + (3 - encryption_level) / 10)
```

---

## 💻 Command-Line Interface

```bash
java PittGuard --mode patch \
  --input <TestFiles/graph.txt> \
  --server <NODE> \
  [--directed]
```

### ⚙️ Required Flags

* `--mode patch` — selects Task 2
* `--input <file>` — graph file using the common file format
* `--server <NODE>` — patch server (must **not** be vulnerable)

### ⚙️ Optional Flag

* `--directed` — treat edges as directed (default undirected)

---

## 🧾 Output Format

* One line with numeric radius (one decimal) or `INF`
* If any vulnerable node unreachable → `INF`
* Invalid inputs or vulnerable server → print error to `stderr` and exit non-zero

---

## 🧮 Example (using `sample.txt`)

Command:

```bash
java PittGuard --mode patch --input TestFiles/sample.txt --server A
```

**Expected output:**

```
9.2
```

### 🔍 Shortest Path Explanations (Effective Costs)

```
effective_cost(e) = latency(e) * (1 + (3 - encryption_level) / 10)
```

Edge Costs:

* **A–B** = 4 × (1 + (3−3)/10) = 4.0
* **A–C** = 2 × (1 + (3−2)/10) = 2.2
* **B–D** = 3 × (1 + (3−2)/10) = 3.3
* **C–D** = 1 × (1 + (3−3)/10) = 1.0
* **D–E** = 5 × (1 + (3−1)/10) = 6.0
* **C–E** = 7 × (1 + (3−3)/10) = 7.0

**A → C**

* Direct A–C = 2.2
* Alternate A–B–D–C = 4.0 + 3.3 + 1.0 = 8.3
  → **Shortest = 2.2**

**A → E**

* A–C–E = 2.2 + 7.0 = 9.2
* A–C–D–E = 2.2 + 1.0 + 6.0 = 9.2
* A–B–D–E = 4.0 + 3.3 + 6.0 = 13.3
  → **Shortest = 9.2 (via A–C–E or A–C–D–E)**

---

# 🧱 Graph File Format

## 🗂️ Structure

Each input file used by **PittGuard** begins with the total number of nodes, followed by:

1. **Vertex List**
2. **Edge List**

### 1️⃣ Header — Number of Nodes

```
<num_nodes>
```

Example:

```
5
```

### 2️⃣ Vertex List

Each of the next `<num_nodes>` lines defines a node and its vulnerability:

```
node_id vulnerable
```

* `node_id` — unique ID (no spaces)
* `vulnerable` — `true` or `false`

Example:

```
A false
B false
C true
D false
E true
```

### 3️⃣ Edge List

Each subsequent line defines a weighted connection:

```
node1 node2 latency encryption_level
```

* **latency** — positive number (time or cost)
* **encryption_level (1–3):**

  * 🔴 1 = Weak encryption (fast but least secure)
  * 🟠 2 = Medium encryption
  * 🟢 3 = Strong encryption (secure but adds latency)

### 💡 Effective Edge Cost

```
effective_cost(e) = latency(e) * (1 + (3 - encryption_level) / 10)
```

* Level 3 → × 1.0 (no penalty)
* Level 2 → × 1.1 (+10%)
* Level 1 → × 1.2 (+20%)

### 📄 Example File

```
5
# Nodes
A false
B false
C true
D false
E true

# Edges
A B 4 3
A C 2 2
B D 3 2
C D 1 3
D E 5 1
C E 7 3
```

**Interpretation:**

* Total nodes: 5
* Vulnerable: C, E
* Non-vulnerable: A, B, D
* Stronger encryption → lower latency penalty

---

## 📂 Folder Structure

```
TestFiles/            # Graph files of varying sizes
PittGuard.java        # Main class (only file to modify)
README.md
```

---

## 🚀 Deliverable

Submit your completed Java project to **Gradescope**.
Only the following file is submitted:

```
PittGuard.java
```

---

## 📊 Grading Rubric

| Item                                | Points |
| ----------------------------------- | :----: |
| ✅ Autograder Tests                  |   90   |
| 🧱 Code Style, Comments, Modularity |   10   |

### 💡 Grading Guidelines

* Test cases include both visible and hidden scenarios to assess correctness and edge handling.
* If autograder < 60%, code reviewed manually for partial credit (max 60% of autograder points).
* Code style includes:

  * Meaningful names
  * Proper indentation
  * Helper methods for reuse
  * Inline comments for clarity
  * Java naming conventions

---