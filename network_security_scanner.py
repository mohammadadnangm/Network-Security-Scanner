import nmap
from scapy.all import *
import pandas as pd
import tkinter as tk
from tkinter import messagebox
import threading

scanning = True  # Global variable to control the scanning process


# Time took to think about flow of the program was 1 day.


# Function to scan the network
def network_scan(network, text_area):
    global scanning
    nm = nmap.PortScanner()
    nm.scan(hosts=network, arguments='-sS')
    hosts_info = []

    for i, host in enumerate(nm.all_hosts()):
        if not scanning:
            break
        host_info = {
            'Host': host,
            'Hostname': nm[host].hostname(),
            'State': nm[host].state(),
            'Open Ports': []
        }
        for proto in nm[host].all_protocols():
            if not scanning:
                break
            ports = nm[host][proto].keys()
            for port in ports:
                if not scanning:
                    break
                port_info = {
                    'Port': port,
                    'State': nm[host][proto][port]['state'],
                    'Service': nm[host][proto][port]['name']
                }
                host_info['Open Ports'].append(port_info)
        hosts_info.append(host_info)

        text_area.insert(tk.END, f"Scanned host {i+1}.\n")
        text_area.update_idletasks()

    text_area.insert(tk.END, "Network scan completed.\n")
    return hosts_info



# Time took to do scanning of network was 3 days.

# Function to check for simple vulnerabilities
def check_vulnerabilities(host_info, text_area):
    global scanning
    vuln_info = []
    for i, host in enumerate(host_info):
        if not scanning:
            break
        for port in host['Open Ports']:
            if not scanning:
                break
            if port['Port'] in [21, 22, 23, 25, 80, 110, 143, 443, 3389]:  # Common ports with known vulnerabilities
                vuln_info.append({
                    'Host': host['Host'],
                    'Port': port['Port'],
                    'Service': port['Service'],
                    'Vulnerability': 'Potential Vulnerability'
                })

        text_area.insert(tk.END, f"Checked vulnerabilities for host {i+1}.\n")
        text_area.update_idletasks()

    return vuln_info


# Time took to check vulnerabilities was 2 days.


# Function to analyze network protocols
def analyze_protocols(text_area):
    global scanning
    packets = sniff(filter="ip", count=100)
    protocols_info = []

    for i, packet in enumerate(packets):
        if not scanning:
            break
        protocols_info.append({
            'Source IP': packet[IP].src,
            'Destination IP': packet[IP].dst,
            'Protocol': packet[IP].proto
        })

        text_area.insert(tk.END, f"Analyzed packet {i+1}.\n")
        text_area.update_idletasks()

    text_area.insert(tk.END, "Protocol analysis completed.\n")
    return protocols_info



# Time took to analyze network protocols was 1 day.



# Function to generate reports in Excel
def generate_report(host_info, vuln_info, protocols_info, report_file, text_area):
    writer = pd.ExcelWriter(report_file, engine='openpyxl')

    hosts_data = []
    for host in host_info:
        for port in host['Open Ports']:
            hosts_data.append({
                'Host': host['Host'],
                'Hostname': host['Hostname'],
                'State': host['State'],
                'Port': port['Port'],
                'Port State': port['State'],
                'Service': port['Service']
            })

    hosts_df = pd.DataFrame(hosts_data)
    vuln_df = pd.DataFrame(vuln_info)
    proto_df = pd.DataFrame(protocols_info)

    hosts_df.to_excel(writer, sheet_name='Network Scan', index=False)
    text_area.insert(tk.END, "Wrote Network Scan sheet.\n")
    text_area.update_idletasks()

    vuln_df.to_excel(writer, sheet_name='Vulnerabilities', index=False)
    text_area.insert(tk.END, "Wrote Vulnerabilities sheet.\n")
    text_area.update_idletasks()

    proto_df.to_excel(writer, sheet_name='Protocol Analysis', index=False)
    text_area.insert(tk.END, "Wrote Protocol Analysis sheet.\n")
    text_area.update_idletasks()

    writer.close()
    text_area.insert(tk.END, f"Report generated: {report_file}\n")



# Time took to generate report was 1 day.



# Function to start the scan
def start_scan():
    global scanning
    scanning = True
    network = network_entry.get()
    report_file = report_entry.get()
    threading.Thread(target=main, args=(network, report_file, text_area)).start()
    stop_scan_button.config(state=tk.NORMAL)  # Enable the stop button

# Function to stop the scan
def stop_scan():
    global scanning
    scanning = False
    messagebox.showinfo("Scan Stopped", "Network Security Scan Stopped")
    stop_scan_button.config(state=tk.DISABLED)  # Disable the stop button

# Function to clear the text area
def clear_text_area():
    text_area.delete(1.0, tk.END)

# Main function to run the network scan
def main(network, report_file, text_area):
    text_area.insert(tk.END, "Network scan started...\n")
    text_area.update_idletasks()
    host_info = network_scan(network, text_area)

    text_area.insert(tk.END, "Checking for vulnerabilities...\n")
    text_area.update_idletasks()
    vuln_info = check_vulnerabilities(host_info, text_area)

    text_area.insert(tk.END, "Analyzing network protocols...\n")
    text_area.update_idletasks()
    protocols_info = analyze_protocols(text_area)

    text_area.insert(tk.END, "Generating report...\n")
    text_area.update_idletasks()
    generate_report(host_info, vuln_info, protocols_info, report_file, text_area)

    messagebox.showinfo("Scan Completed", "Network Security Scan Completed and Report Generated!")

if __name__ == '__main__':
    root = tk.Tk()
    root.title("Network Security Scanner")
    root.geometry('800x600')  # Set the window size

    # Create a frame for the text area and scrollbar
    text_frame = tk.Frame(root)
    text_frame.pack(fill=tk.BOTH, expand=True)

    # Create a scrollbar and a text area
    scrollbar = tk.Scrollbar(text_frame)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    text_area = tk.Text(text_frame, height=30, width=100, yscrollcommand=scrollbar.set)
    text_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    scrollbar.config(command=text_area.yview)

    # Create a frame for the buttons
    button_frame = tk.Frame(root)
    button_frame.pack(fill=tk.X)

    # Create a label and entry for the network range
    network_label = tk.Label(button_frame, text="Network Range:")
    network_label.pack(side=tk.LEFT, padx=10)

    network_entry = tk.Entry(button_frame)
    network_entry.insert(0, '192.168.1.0/24')  #
    network_entry.pack(side=tk.LEFT, padx=10)

    # Create a label and entry for the report file
    report_label = tk.Label(button_frame, text="Report File:")
    report_label.pack(side=tk.LEFT, padx=10)

    report_entry = tk.Entry(button_frame)
    report_entry.insert(0, 'network_security_report.xlsx')  # Default report file
    report_entry.pack(side=tk.LEFT, padx=10)

    # Create the start and stop scan buttons
    start_scan_button = tk.Button(button_frame, text="Start Scan", command=start_scan)
    start_scan_button.pack(side=tk.RIGHT, padx=10)

    # Create the clear button
    clear_button = tk.Button(button_frame, text="Clear", command=clear_text_area)
    clear_button.pack(side=tk.RIGHT, padx=10)

    stop_scan_button = tk.Button(button_frame, text="Stop Scan", command=stop_scan, state=tk.DISABLED)  # Disable the stop button initially
    stop_scan_button.pack(side=tk.RIGHT, padx=10)

    root.mainloop()


# Time took to run the network security scanner was 7 days.