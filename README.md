# Peregrine

Peregrine is an malicious traffic detection system that leverages the programmable data plane to execute a subset of the overall intrusion detection pipeline.
Specifically, it performs traffic feature extraction and the calculation of statistics entirely on the data plane switches.
The subsequent machine learning-based classification is performed at the control plane level.

This repository contains data plane implementations for the Tofino Native Architecture: Tofino 1 (TNA) and Tofino 2 (TNA2).
