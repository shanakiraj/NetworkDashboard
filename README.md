# Network Monitoring Dashboard

## Overview

This application is designed to monitor and visualize network traffic in real-time. It utilizes Python libraries such as Dash, Plotly, Scapy, and geoip2 to capture network packets, perform traceroutes, and map traffic geographically.

## Key Features

- **Real-Time Traffic Monitoring**: Captures and displays network packets with detailed information.
- **Traceroute Analysis**: Identifies and analyzes packet routing to detect potential anomalies.
- **Geolocation Mapping**: Visualizes geographical origins of network traffic using the GeoIP database.
- **Alert System**: Generates alerts for suspicious traffic patterns and network activities.

## Installation

Ensure Python is installed and run the following command to install necessary packages:

```bash
pip install dash pandas plotly scapy geoip2
```

## Additional Analysis Notebooks

- **Neural Network Analysis**: `neural_net_analysis.ipynb` provides a deep learning approach to predict and classify network behavior.
- **Random Forest Analysis**: `random_forest_analysis.ipynb` uses a machine learning model to analyze network traffic and detect anomalies.
