# Import necessary libraries
import os
import extract_msg
import csv
import re

# Define the directory containing the .msg files
directory = os.path.join(os.getcwd(), 'messages')
csv_file = 'extracted_data.csv'

# Function to extract data based on headings
def extract_data_from_body(body):
    headings = ["Severity", "Time of occurence", "Activity", "Sensitive Data Detected", "User", "Policy Violated", "Alert ID", "File owner", "File name", "Rule/Conditions Matched details ", "Policy Details "]
    data = {}
    for heading in headings:
        pattern = rf"{heading}:(.*?)\n"
        match = re.search(pattern, body, re.DOTALL)
        data[heading] = match.group(1).strip() if match else ""
    return data

# Open the CSV file for writing
with open(csv_file, mode='w', newline='', encoding='utf-8') as file:
    writer = csv.writer(file)
    # Write the header row
    writer.writerow(["Filename"] + ["Subject"] + ["Body"] + ["Severity", "Time of occurrence", "Activity", "Sensitive Data Detected", "User", "Policy Violated", "Alert ID", "File Owner", "File name", "Rule/Conditions Matched details", "Policy Details"])

    # Loop through all files in the directory
    for filename in os.listdir(directory):
        if filename.endswith(".msg"):
            msg = extract_msg.Message(os.path.join(directory, filename))
            # Extract the required fields
            subject = msg.subject
            body = msg.body
            extracted_data = extract_data_from_body(body)
            # Write the data to the CSV file
            writer.writerow([filename, subject, body] + [extracted_data[heading] for heading in extracted_data])
