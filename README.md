# CTI YARA Rules

Welcome to my Threat Intelligence repository. This space contains custom YARA rules engineered during my independent malware analysis and reverse engineering research.

## Overview
The rules provided here are designed to detect specific behaviors, packers, and in-memory artifacts of commodity malware families. They are written based on dynamic memory analysis and static reverse engineering of live samples.

## Rules Inventory
* **RedLine_Koi.yar**: Detects the reflective loading mechanism (Koi module) of RedLine Stealer variants packed with ConfuserEx. Created after manually unpacking the stage-2 payload from memory.

## About the Author
**Svetoslav Angelov**
Threat Intelligence Analyst | Reverse Engineering Enthusiast
* **Medium Blog:** [https://medium.com/@svetli80]
* **LinkedIn:** [https://linkedin.com/in/svet-angelov-cybersec]

## Disclaimer
These rules are provided for educational and defensive purposes. While tested to minimise false positives against standard Windows binaries, please validate them in your own environment before deploying to production.
