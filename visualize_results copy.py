import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Function to visualize the scan results
def visualize_results(report_file):
    # Read the Excel report
    hosts_df = pd.read_excel(report_file, sheet_name='Network Scan')
    vuln_df = pd.read_excel(report_file, sheet_name='Vulnerabilities')
    proto_df = pd.read_excel(report_file, sheet_name='Protocol Analysis')

    # Print the first few rows of the DataFrames to check their content
    print("Hosts DataFrame:")
    print(hosts_df.head())
    print("\nVulnerabilities DataFrame:")
    print(vuln_df.head())
    print("\nProtocols DataFrame:")
    print(proto_df.head())

    # Ensure columns are present
    if 'Host' not in hosts_df.columns or 'Port' not in hosts_df.columns:
        print("Error: Required columns 'Host' or 'Port' not found in hosts DataFrame.")
        return

    if 'Host' not in vuln_df.columns or 'Port' not in vuln_df.columns:
        print("Error: Required columns 'Host' or 'Port' not found in vulnerabilities DataFrame.")
        return

    if 'Protocol' not in proto_df.columns:
        print("Error: Required column 'Protocol' not found in protocols DataFrame.")
        return

    # Plot the number of open ports per host
    plt.figure(figsize=(14, 8))
    try:
        sns.countplot(data=hosts_df, x='Host', hue='Port', palette="viridis")
        plt.title('Number of Open Ports per Host')
        plt.xlabel('Host IP Address')
        plt.ylabel('Number of Open Ports')
        plt.legend(title='Port', bbox_to_anchor=(1.05, 1), loc='upper left')
        plt.xticks(rotation=90)
        plt.tight_layout()

        # Adding a summary box
        total_hosts = hosts_df['Host'].nunique()
        total_open_ports = len(hosts_df)
        plt.gcf().text(0.02, 0.95, f'Total Hosts: {total_hosts}', fontsize=12)
        plt.gcf().text(0.02, 0.92, f'Total Open Ports: {total_open_ports}', fontsize=12)

        plt.savefig('open_ports_per_host.png')
    except Exception as e:
        print(f"Failed to plot open ports per host: {e}")

    # Plot the vulnerabilities found
    plt.figure(figsize=(14, 8))
    try:
        sns.countplot(data=vuln_df, x='Host', hue='Port', palette="viridis")
        plt.title('Vulnerabilities Found per Host')
        plt.xlabel('Host IP Address')
        plt.ylabel('Number of Vulnerabilities')
        plt.legend(title='Port', bbox_to_anchor=(1.05, 1), loc='upper left')
        plt.xticks(rotation=90)
        plt.tight_layout()

        # Adding a summary box
        total_vulnerabilities = len(vuln_df)
        plt.gcf().text(0.02, 0.95, f'Total Vulnerabilities: {total_vulnerabilities}', fontsize=12)

        plt.savefig('vulnerabilities_per_host.png')
    except Exception as e:
        print(f"Failed to plot vulnerabilities per host: {e}")

    # Plot the protocols analysis
    try:
        proto_counts = proto_df['Protocol'].value_counts()
        plt.figure(figsize=(14, 8))
        sns.barplot(x=proto_counts.index, y=proto_counts.values, palette="viridis")
        plt.title('Protocol Usage Analysis')
        plt.xlabel('Protocol Number')
        plt.ylabel('Count')
        plt.tight_layout()

        # Adding a summary box
        total_protocols = len(proto_df)
        plt.gcf().text(0.02, 0.95, f'Total Protocols Analyzed: {total_protocols}', fontsize=12)

        plt.savefig('protocol_usage_analysis.png')
    except Exception as e:
        print(f"Failed to plot protocol usage analysis: {e}")

    # Show all plots at once
    plt.show()

# Main function to run the visualization
def main():
    report_file = 'network_security_report.xlsx'
    print("Visualizing results...")
    visualize_results(report_file)
    print("Visualization completed.")

if __name__ == '__main__':
    main()
