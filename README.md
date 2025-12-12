# Insider Log Poisoning Attack on IoT–SIEM Pipeline via Compromised Aggregation Database

This repository contains the implementation and scripts for the project *"Insider Log Poisoning Attack on IoT–SIEM Pipeline via Compromised Aggregation Database"*, demonstrating an insider threat targeting the aggregation layer using the CICIoTDIAD2024 dataset and enterprise-grade components.

## Overview of the Project

The project simulates an IoT-SIEM pipeline with an ggregation database (Parsed-Indexed Store) using MinIO. It first demonstrates clean detection of 7 attack categories, then shows how insider poisoning at the aggregation layer reduces detection effectiveness in Kibana.

## 📁 Project Structure

| File/Folder                  | Description                                                                 |
|------------------------------|-----------------------------------------------------------------------------|
| `poisoned_script.py`         | Generates poisoned logs and injects them into the pipeline                  |
| `minio-to-es.conf`      | configuration for Logstash                |
| `Block_diagram.png`          | System architecture diagram                                                |
| `README.md`                  | This file                                                                   |

## 🔧 Tools & Technologies Used

| Category          | Tool/Technology                  | Description                                           |
|-------------------|----------------------------------|-------------------------------------------------------|
| **Dataset**       | CICIoTDIAD2024                   | IoT attack dataset with 7 categories                  |
| **Environment**   | WSL (Windows Subsystem for Linux)| For running scripts and connections                   |
| **Storage**       | MinIO                            | Simulates aggregation database               |
| **Visualization** | Kibana (Elastic Stack)  | Dashboards to view detection and poisoning impact     |
| **Scripting**     | Python / Bash                    | Log processing and MinIO interactions                 |

## Usage
## Architecture
![Block Diagram](Block_diagram.jpg)

### Prerequisites

- Windows Subsystem for Linux (WSL) installed
- MinIO server running:  
  ```bash
  MINIO_ROOT_USER=minioadmin MINIO_ROOT_PASSWORD=minioadmin \
  minio server /home/preet/minio-data --console-address ":9001"
  ```
- Kibana/Elasticsearch set up and connected to the parsed index
- CICIoTDIAD2024 dataset downloaded and placed in a suitable directory
- MinIO client (`mc`) installed in WSL:  
  ```bash
  mc alias set local http://localhost:9000 minioadmin minioadmin
  ```
### Part 1: Clean Detection Pipeline

This flow demonstrates normal operation with high detection rates.

1. Send logs to Parsed-Indexed Store in MinIO.
   ```bash
   mc cp --recursive ~/datasets/CICDIAD2024/json_logs/*.json local/parsed-indexed/
   ```
2. Establish connection from WSL to MinIO and Logstash. Also sends Logs to Logstash.    
via:
   ```bash
   ./bin/logstash -f minio-to-es.conf
   ```
3. View dashboard in Kibana — attacks are Displayed.

### Part 2: Insider Log Poisoning Attack

This flow injects poisoned logs and shows reduced detection.

4. Using evasion techniques, generate poisoned logs mixed with benign traffic (treated as 8th category).
   using the script Poisoned_script.py
   ```bash
   python3 Poisoned_script.py 
   ```
5. Inject poisoned logs into Parsed-Indexed Store.
   ```bash
   mc cp --recursive /home/preet/datasets/CICDIAD2024/json_logs/benign.json local/parsed-indexed
   ```
6. Re-establish connection from WSL to MinIO and Logstash. Also sends Logs to Logstash.
   ```bash
   ./bin/logstash -f minio-to-es.conf
   ```
7. View dashboards in Kibana — detection rate is significantly reduced due to poisoning.
