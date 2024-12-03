# Log Analysis Script 📊

This Python script processes web server log files to extract and analyze key information, providing insights into network activity, such as request counts, frequently accessed endpoints, and potential suspicious activities. The script is useful for cybersecurity-related tasks like identifying brute-force login attempts and understanding web traffic patterns.

---

## **Objective**

The goal of this script is to:
1. **Count Requests per IP Address**
2. **Identify the Most Frequently Accessed Endpoint**
3. **Detect Suspicious Activity** (e.g., failed login attempts)

### **Features**
- Count requests per IP address.
- Identify the most frequently accessed endpoint.
- Detect suspicious activities based on failed login attempts (status `401` or "Invalid credentials").
- Save the results in a CSV file (`log_analysis_results.csv`).

---

## **Requirements**

- **Python 3.8 or later**.
- Libraries: Python standard library (`re`, `csv`, `sys`, `logging`, `pathlib`, `collections`).

---

## **Installation**

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Anushdubey01/Log-Analyzer.git
   cd Log-Analyzer
   ```

2. **Ensure Python 3 is installed**:
   ```bash
   python3 --version
   ```

3. **Install any additional dependencies (if applicable)**:
   If your script depends on any external libraries, include instructions here.

---

## **Usage**

### **Prepare Your Log File**
- Download or create a sample log file (`sample.log`). A sample log is included with this project.

### **Run the Script**
To analyze the log file, simply run the script from the terminal:

```bash
python3 log_analysis_script.py
```

### **Results**
- The script will display the analysis results in the terminal.
- A CSV file named `log_analysis_results.csv` will be generated containing the following data:
  - **Requests per IP**: IP Address and Request Count.
  - **Most Accessed Endpoint**: Endpoint and Access Count.
  - **Suspicious Activity**: IP Address and Failed Login Count.

---

## **Code Overview**

### **1. Count Requests per IP Address**

The script parses the log file to count how many requests each IP address made. It sorts the results by request count and displays the IPs with the highest traffic.

### **2. Identify the Most Frequently Accessed Endpoint**

It extracts the endpoints from each log entry and identifies the one accessed the most.

### **3. Detect Suspicious Activity**

The script looks for entries with HTTP status `401` (Unauthorized) or the message "Invalid credentials" to detect potential brute-force login attempts. If an IP address exceeds a configurable threshold (default: 10), it flags that IP as suspicious.

### **4. Output Results**

- **Terminal Output**: Displays the analysis results directly in the terminal.
- **CSV Output**: Saves the results to `log_analysis_results.csv` in the specified format.

---

## **Example Log File Format**

The log entries should follow this format (based on the NGINX or Apache log formats):

```
<IP Address> - - [<Date>] "<HTTP Method> <Endpoint> HTTP/1.1" <Status Code> <Response Size> "<Message>"
```

Sample log entries:
```
192.168.1.1 - - [03/Dec/2024:10:12:34 +0000] "GET /home HTTP/1.1" 200 512
203.0.113.5 - - [03/Dec/2024:10:12:35 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
10.0.0.2 - - [03/Dec/2024:10:12:36 +0000] "GET /about HTTP/1.1" 200 256
```

---

## **CSV Output Format**

The resulting CSV file will have the following structure:

### **Requests per IP**
| IP Address       | Request Count |
|------------------|---------------|
| 192.168.1.1      | 234           |
| 203.0.113.5      | 187           |

### **Most Accessed Endpoint**
| Endpoint     | Access Count |
|--------------|--------------|
| /home        | 403          |

### **Suspicious Activity**
| IP Address    | Failed Login Count |
|---------------|--------------------|
| 192.168.1.100 | 56                 |
| 203.0.113.34  | 12                 |

---

## **Evaluation Criteria**

1. **Functionality**
   - The script successfully parses logs, identifies the most accessed endpoint, counts requests per IP, and detects suspicious activity.
   - CSV export works as expected.

2. **Code Quality**
   - Clean and modular code, following Python best practices.
   - Proper use of comments and meaningful variable names.

3. **Performance**
   - The script can handle larger log files without significant delays.

4. **Output**
   - Correctly formatted output both in the terminal and in the CSV file.

---

## **Contact**

For any questions or suggestions, feel free to open an issue or contact at [anushdubey881@gmail.com](mailto:anushdubey881@gmail.com).
