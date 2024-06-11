import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Function to visualize the scan results
def visualize_results(report_file):
    # Read the Excel report
    hosts_df = pd.read_excel(report_file, sheet_name='Network Scan')
    vuln_df = pd.read_excel(report_file, sheet_name='Vulnerabilities')
    proto_df = pd.read_excel(report_file, sheet_name='Protocol Analysis')

    # Plot the number of open ports per host
    plt.figure(figsize=(12, 6))
    sns.countplot(data=hosts_df, x='Host', hue='Port')
    plt.title('Number of Open Ports per Host')
    plt.xticks(rotation=90)
    plt.tight_layout()
    plt.savefig('open_ports_per_host.png')
    plt.show()

    # Plot the vulnerabilities found
    plt.figure(figsize=(12, 6))
    sns.countplot(data=vuln_df, x='Host', hue='Port')
    plt.title('Vulnerabilities Found per Host')
    plt.xticks(rotation=90)
    plt.tight_layout()
    plt.savefig('vulnerabilities_per_host.png')
    plt.show()

    # Plot the protocols analysis
    proto_counts = proto_df['Protocol'].value_counts()
    plt.figure(figsize=(12, 6))
    sns.barplot(x=proto_counts.index, y=proto_counts.values)
    plt.title('Protocol Usage Analysis')
    plt.xlabel('Protocol')
    plt.ylabel('Count')
    plt.tight_layout()
    plt.savefig('protocol_usage_analysis.png')
    plt.show()

# Main function to run the visualization
def main():
    report_file = 'network_security_report.xlsx'
    print("Visualizing results...")
    visualize_results(report_file)
    print("Visualization completed.")

if __name__ == '__main__':
    main()
