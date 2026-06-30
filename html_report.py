from datetime import datetime

def generate_html_report(target, scan_results):
    import os

    os.makedirs("reports", exist_ok=True)

    filename = os.path.join("reports", "scan_report.html")

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>VulnScanner Pro Report</title>
        <style>
            body {{
                font-family: Arial;
                background:#f4f4f4;
                padding:20px;
            }}

            h1 {{
                color:#2c3e50;
            }}

            table {{
                border-collapse: collapse;
                width:100%;
                background:white;
            }}

            th, td {{
                border:1px solid #ddd;
                padding:10px;
                text-align:center;
            }}

            th {{
                background:#3498db;
                color:white;
            }}

            .low {{
                color:green;
                font-weight:bold;
            }}

            .medium {{
                color:orange;
                font-weight:bold;
            }}

            .high {{
                color:red;
                font-weight:bold;
            }}
        </style>
    </head>

    <body>

    <h1>🛡 VulnScanner Pro Report</h1>

    <p><b>Target:</b> {target}</p>

    <p><b>Generated:</b> {datetime.now()}</p>

    <table>

    <tr>
        <th>Port</th>
        <th>Service</th>
        <th>State</th>
        <th>Risk</th>
    </tr>
    """

    for item in scan_results:
        html += f"""
        <tr>
            <td>{item['port']}</td>
            <td>{item['service']}</td>
            <td>{item['state']}</td>
            <td class="{item['risk'].lower()}">{item['risk']}</td>
        </tr>
        """

    html += """
    </table>

    </body>
    </html>
    """

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"\nHTML report saved as {filename}")