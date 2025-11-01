# Codex Prototype

Codex Prototype is a modular Python system for detecting, analyzing, and correlating suspicious activity in system, network, and DNS logs. It features:
- Data collection detection
- Threat enrichment using Cyber Threat Intelligence (CTI)
- Early exfiltration warnings
- HTTP/HTTPS and DNS exfiltration detection
- Cross-tactic event correlation
- Dashboard GUI for interactive analysis

## Project Structure
```
codex_data_collection.py   # Data collection detection logic
codex_exfiltration.py      # Exfiltration detection logic (HTTP/HTTPS, DNS, early warnings)
codex_correlation.py       # Event correlation logic
codex_cti.py               # CTI feed and enrichment logic
codex_utils.py             # Utility functions (e.g., entropy)
codex_core.py              # Central import/export for all logic
codex_gui.py               # Dashboard GUI
main.py                    # Script entry point
```

## Setup
1. Clone the repository:
	 ```sh
	 git clone https://github.com/Onkar-K-Mane/codex_prototype.git
	 cd codex_prototype
	 ```
2. Install dependencies:
	 ```sh
	 pip install -r requirements.txt
	 ```
	 *(If `requirements.txt` is missing, install: pandas, scikit-learn, tkinter)*

## Usage
- **Run the main analysis script:**
	```sh
	python main.py
	```
- **Launch the dashboard GUI:**
	```sh
	python codex_gui.py
	```

## Features
- **Data Collection Detection:** Identifies processes accessing many files or with suspicious read/write ratios.
- **CTI Enrichment:** Flags alerts using threat intelligence feeds.
- **Exfiltration Detection:** Uses anomaly detection to find suspicious network and DNS activity.
- **Correlation:** Links related events for high-confidence incident detection.
- **Dashboard:** Interactive GUI for log selection and report review.

## Contributing
Pull requests and suggestions are welcome!

# codex_prototype