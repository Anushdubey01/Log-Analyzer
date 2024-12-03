# Log Analyzer 📊🔍

This project provides an advanced log file analysis tool to parse, analyze, and report web server logs. It identifies key metrics like the most accessed endpoints and detects suspicious activities, such as failed login attempts, to enhance security monitoring.

---

## Features 🚀

- **Structured Log Parsing:** Uses a data class (`LogEntry`) for type-safe and structured log parsing.
- **Detailed Metrics:**
  - Counts total requests per IP address.
  - Identifies the most frequently accessed endpoint.
  - Detects IP addresses with excessive failed login attempts (configurable threshold).
- **Robust Logging:** Comprehensive logging for better monitoring and debugging.
- **CSV Export:** Analysis results are exportable to CSV for further use or reporting.
- **Error Handling:** Advanced error handling ensures the tool is resilient against malformed logs or file access issues.

---

## Requirements 🛠️

- Python 3.8 or higher
- Libraries: `re`, `csv`, `sys`, `logging`, `pathlib`, `dataclasses`, and `collections` (all part of the Python standard library)

---

## Installation 💻

1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/log-analyzer.git
   cd log-analyzer
   ```

2. Ensure you have Python 3 installed. Verify with:
   ```bash
   python3 --version
   ```

---

## Usage 📘

1. **Prepare your log file:** Place the web server log file (e.g., `sample.log`) in the project directory.

2. **Run the analyzer:**
   ```bash
   python3 log_analyzer.py
   ```

3. **View Results:** The output will display in the console, and a CSV report (`log_analysis_results.csv`) will be generated in the project directory.

---

## Configuration ⚙️

You can customize key parameters in the `main()` function:

```python
log_file_path = Path('sample.log')   # Path to your log file
failed_login_threshold = 10          # Number of failed logins to flag as suspicious
```

You can also adjust the logging verbosity:
```python
log_level = logging.INFO             # Options: DEBUG, INFO, WARNING, ERROR, CRITICAL
```

---

## Log Format Expectations 📄

The analyzer expects log entries to follow this general format:
```
<IP Address> - - [Date] "<HTTP Method> <Endpoint> HTTP/1.1" <Status Code> <Optional Message>
```
Example:
```
192.168.1.1 - - [12/Mar/2023:15:45:23 +0000] "GET /home HTTP/1.1" 200 "-"
192.168.1.2 - - [12/Mar/2023:16:02:11 +0000] "POST /login HTTP/1.1" 401 "Invalid credentials"
```

---

## Output Explanation 📊

- **IP Request Counts:** Displays the number of requests made by each IP address.
- **Most Accessed Endpoint:** Shows the endpoint with the highest access count.
- **Suspicious Activities:** Lists IPs exceeding the failed login threshold.

---

## Contributing 🤝

Contributions are welcome! To get started:

1. Fork this repository.
2. Create a new branch:
   ```bash
   git checkout -b feature-branch-name
   ```
3. Make changes and commit:
   ```bash
   git commit -m "Your detailed description of the change"
   ```
4. Push your branch and create a Pull Request.

---

## License 📜

This project is licensed under the MIT License. See the LICENSE file for details.

---

## Contact 📬

For any questions or suggestions, feel free to open an issue or reach out at [anushdubey881@gmail.com](mailto:anushdubey881.com).
