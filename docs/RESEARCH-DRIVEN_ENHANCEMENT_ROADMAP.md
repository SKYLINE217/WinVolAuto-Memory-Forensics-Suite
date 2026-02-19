# Research-Driven Enhancement Roadmap

Based on the deep analysis of 5 key research papers, this roadmap outlines the strategic enhancement of the "Automate volatility" project.

## Phase 1: Performance & Foundation (Weeks 1-4)
**Goal:** Optimize the core engine without changing code logic, leveraging JIT compilation findings.

### 1.1 Integrate PyPy Support (High Impact, Low Effort)
*Source: Gharaibeh et al. (2024)*
- **Objective:** Achieve ~20% speedup on scan-intensive tasks.
- **Tasks:**
    - [ ] Create a Dockerfile compatible with PyPy3.
    - [ ] Verify `volatility3` and project dependencies install correctly under PyPy.
    - [ ] Benchmark standard scan (e.g., `windows.psscan`) CPython vs PyPy.
    - [ ] Update documentation to recommend PyPy for large dumps.

### 1.2 Profile "Smart-Fallback" System (Medium Impact, Medium Effort)
*Source: Oliveri et al. (2025)*
- **Objective:** Reduce failure rate when exact kernel profiles are missing.
- **Tasks:**
    - [ ] Implement version distance logic (e.g., if `5.4.0-123` missing, try `5.4.0-122`).
    - [ ] For Windows: Fallback to highest patch version of the same build.
    - [ ] For Linux: Fallback to nearest lower minor version.
    - [ ] Add warning system: "Using heuristic profile match (Confidence: Medium)".

## Phase 2: GPU Forensics Expansion (Weeks 5-8)
**Goal:** Address the "blind spot" of GPU-assisted malware and VRAM usage.

### 2.1 NVIDIA Driver Reconnaissance
*Source: Bowen et al. (2024)*
- **Objective:** Detect presence and version of NVIDIA drivers in memory images.
- **Tasks:**
    - [ ] Create `CheckNvidia` plugin/script to grep for `nvidia`, `nvidia_uvm` modules in lsmod/modules list.
    - [ ] Extract driver version string to determine open vs. closed source profile requirement.

### 2.2 NVOC Structure Scanning
*Source: Bowen et al. (2024)*
- **Objective:** Map kernel memory to GPU objects.
- **Tasks:**
    - [ ] Implement `NVOC_CLASS_DEF` scanner to find GPU class definitions in RAM.
    - [ ] Implement reverse-lookup to find instantiated GPU objects (e.g., `GpuAccounting`).
    - [ ] **Deliverable:** Report showing active GPU contexts/processes from RAM artifacts.

## Phase 3: Application-Specific Forensics (Weeks 9-12)
**Goal:** Move beyond OS artifacts to high-value application data (Databases).

### 3.1 DBMS Artifact Scanner
*Source: Wagner et al. (2023)*
- **Objective:** Extract SQL query fragments from process memory.
- **Tasks:**
    - [ ] Identify `oracle` or `mysqld` processes.
    - [ ] Implement pattern matching for SQL keywords in their heap/stack regions.
    - [ ] Visualize "recovered queries" vs "logged queries" (if log file provided).

### 3.2 Automated "Ghost Query" Detection
- **Objective:** Flag potential log tampering.
- **Tasks:**
    - [ ] Input: Memory Dump + Audit Log File.
    - [ ] Logic: If Query X found in Memory but NOT in Log -> Alert "Potential Tampering".

## Phase 4: Advanced Acquisition (Future)
**Goal:** Support hardware-based acquisition for stealth and speed.

### 4.1 FPGA/DMA Acquisition Support
*Source: Turicu & Oniga (2026)*
- **Objective:** Support PCILeech/FPGA streams.
- **Tasks:**
    - [ ] Add interface to read from DMA device streams instead of just file paths.
    - [ ] Implement "Live Analysis" mode where analysis starts during acquisition (piping).

## Summary of Priorities

| Priority | Feature | Justification |
| :--- | :--- | :--- |
| **P0** | **PyPy Integration** | Immediate, free performance boost (15-20%) backed by benchmarks. |
| **P1** | **NVIDIA Module Detection** | GPU malware is an emerging threat; currently ignored by most tools. |
| **P2** | **Profile Heuristics** | Fixes the common user frustration of "Profile Not Found". |
| **P3** | **DBMS Analysis** | High value for enterprise investigations (data exfiltration/insider threat). |
