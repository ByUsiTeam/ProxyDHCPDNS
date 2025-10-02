# DHCP-Proxy

This is a tool combining DHCP and DNS proxy functionalities, capable of forwarding DHCP requests and handling DNS request hijacking.

## Features

- **DHCP Proxy**: Intercept and process client DHCP requests, acting as a proxy between the client and the actual DHCP server.
- **DNS Hijacking**: Intercept DNS queries and allow custom domain name resolution rules.
- **Logging**: Record detailed packet information for analysis and debugging.
- **Dynamic Configuration**: Support loading rules from configuration files and dynamically adjusting proxy behavior.

## Component Description

- `dhcp_proxy.py`: Core logic for implementing DHCP proxy, including packet parsing, forwarding, and proxy server setup.
- `dns_proxy.py`: Provides DNS proxy functionality, parsing DNS queries and constructing responses.
- `config.json`: Main configuration file used to define proxy rules and server settings.
- `dnsconfig.json`: DNS hijacking configuration file, specifying domains to intercept and their corresponding IP addresses.
- `run.py`: Program entry point for starting DHCP and DNS proxy services.
- `run.sh`: Startup script for conveniently running the entire proxy system.

## Usage Instructions

1. **Configuration Setup**: Edit the `config.json` and `dnsconfig.json` files to set DHCP and DNS proxy rules as needed.
2. **Start Service**: Run the `run.sh` script or directly execute the `run.py` file to start the proxy service.
3. **View Logs**: During proxy operation, log files will record detailed network interaction information for monitoring and debugging.

## Dependencies

- Python 3.8 or higher
- Root privileges are required to monitor network interfaces

## Open Source License

This project is licensed under the MIT License. Please refer to the project license file for details.