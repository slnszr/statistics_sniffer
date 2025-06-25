# Network Traffic Sniffer & Analyzer

A minimal Python-based toolkit for **capturing, logging and visualising TCP traffic** that passes through a proxy (e.g. *mitmproxy*).  
Ideal for internship-scale experiments in **HTTP/HTTPS interception**, **packet logging**, and **basic traffic analytics** such as *packet-size distribution*.

---

## 1. Features

| Module             | What it does                                                                                      |
|--------------------|---------------------------------------------------------------------------------------------------|
| **sniffer.py**     | • Starts Scapy sniffer on `tcp` filter. <br> • Logs each packet to `trafik_log.csv`.              |
| **analyse.py**     | • Loads the CSV using `pandas`. <br> • Plots packet-size distribution using `matplotlib`.         |
| **Proxy integration** | Works with **mitmproxy** to capture traffic from **external devices**.                         |
| **TUSIPI / UTIPI hooks** | Can be extended to classify traffic (encrypted vs unencrypted) based on protocol/layer.     |

---

## 2. Quick Start

### 2.1 Clone the Repository & Install Requirements

```bash
git clone https://github.com/<your-username>/<repo>.git
cd <repo>

# Optional: create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
# or
pip install scapy pandas matplotlib
