# B01803952 - MSc Dissertation Project
# Author: Manish Hajur Khadka
#
# main.py: Main script for the rule-based phishing detection system.
# This script contains the final implementation of the detection engine and the
# evaluation logic used to process the dataset and generate performance metrics.

import pandas as pd #loads the dataset
import re
from bs4 import BeautifulSoup
from sklearn.metrics import confusion_matrix, accuracy_score, precision_score, recall_score
import seaborn as sns
import matplotlib.pyplot as plt
from urllib.parse import urlparse #parses domain from URLs


# --- 1. Helper Functions ---
# This section contains functions that perform pre-processing tasks, such as
# extracting key information from the email text before the rules are applied.

def extract_links(email_text):
    """
    Extracts all unique hyperlinks (URLs) from the email text, searching for
    both plain text links and links within HTML <a> tags.
    """
    if not isinstance(email_text, str):
        return []
    # Regex for finding URLs in plain text
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    plain_text_links = re.findall(url_pattern, email_text)

    # Use BeautifulSoup to find links in HTML <a> tags
    try:
        soup = BeautifulSoup(email_text, 'html.parser')
        html_links = [a['href'] for a in soup.find_all('a', href=True)]
        # Combine and remove duplicates
        all_links = list(set(plain_text_links + html_links))
    except Exception:
        all_links = plain_text_links
    return all_links


def extract_sender_domain(email_text):
    """
    Extracts the sender's domain from the 'From:' header in the email text.
    Returns the domain in lowercase or None if not found.
    """
    if not isinstance(email_text, str): return None
    # This regex provides a simple method for finding the 'From:' line.
    # A more comprehensive implementation could use a full email parsing library.
    from_pattern = r'From:.*?@([\w\.-]+)'
    match = re.search(from_pattern, email_text, re.IGNORECASE)
    if match:
        return match.group(1).lower()
    return None


# --- 2. Rule Definitions ---
# This section defines the five heuristic rules used by the detection engine.
# Each function checks for a specific phishing indicator and returns True if found.

def check_for_urgency(email_text):
    """Rule 1: Checks for keywords that create a sense of urgency."""
    if not isinstance(email_text, str): return False
    urgency_keywords = [
        r'\burgen(t|cy)\b', r'\baction required\b', r'\bimmediate(ly)?\b',
        r'\bexpire(s|d)?\b', r'\bsuspen(d|sion|ded)\b', r'\bfailed delivery\b',
        r'\baccount restricted\b', r'\bsecurity alert\b', r'\bwarning\b'
    ]
    for keyword in urgency_keywords:
        if re.search(keyword, email_text, re.IGNORECASE):
            return True
    return False


def check_for_ip_in_links(links):
    """Rule 2: Checks if any link in the email uses a numerical IP address."""
    if not links: return False
    ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
    for link in links:
        if re.search(ip_pattern, link):
            return True
    return False


def check_link_text_mismatch(email_text):
    """Rule 3: Checks for deceptive links where the visible text is a domain
    that does not match the actual destination URL."""
    if not isinstance(email_text, str): return False
    try:
        soup = BeautifulSoup(email_text, 'html.parser')
        for a_tag in soup.find_all('a', href=True):
            link_text = a_tag.text.strip()
            href = a_tag['href']
            # A simple heuristic: if the link text looks like a domain but isn't in the href
            if '.' in link_text and not link_text.startswith('http') and link_text.lower() not in href.lower():
                return True
    except Exception:
        return False
    return False


def check_generic_salutation(email_text):
    """Rule 4: Checks for generic salutations common in phishing emails."""
    if not isinstance(email_text, str): return False
    generic_salutation_pattern = r'\bDear\s+(Valued\s+)?(Customer|User|Client|Member)\b'
    if re.search(generic_salutation_pattern, email_text, re.IGNORECASE):
        return True
    return False


def check_sender_link_domain_mismatch(sender_domain, links):
    """Rule 5: Checks if link domains are different from the sender's domain."""
    if not sender_domain or not links:
        return False

    for link in links:
        try:
            link_domain = urlparse(link).netloc.lower()
            # This check allows for subdomains (e.g., mail.google.com is valid for google.com)
            if sender_domain not in link_domain:
                return True
        except Exception:
            # Ignore malformed links that cannot be parsed
            continue
    return False


# --- 3. Main Processing Logic ---

def analyze_email(email_text):
    """
    Applies all defined rules to a single email and returns a cumulative
    phishing score based on the number of triggered rules.
    """
    phishing_score = 0
    # Perform pre-processing to extract necessary information
    links = extract_links(email_text)
    sender_domain = extract_sender_domain(email_text)

    # Apply each rule and increment the score if triggered
    if check_for_urgency(email_text): phishing_score += 1
    if check_for_ip_in_links(links): phishing_score += 1
    if check_link_text_mismatch(email_text): phishing_score += 1
    if check_generic_salutation(email_text): phishing_score += 1
    if check_sender_link_domain_mismatch(sender_domain, links): phishing_score += 1

    return phishing_score


# --- 4. Full Dataset Evaluation ---

# The main execution block, which runs when the script is executed directly.
if __name__ == "__main__":
    print("--- Starting Full System Evaluation (Final Engine with 5 Rules) ---")

    try:
        df = pd.read_csv('Phishing_Email.csv')
    except FileNotFoundError:
        print("Error: 'Phishing_Email.csv' not found. Please place it in the project folder.")
        exit()

    # Drop rows with missing email text to prevent errors
    df.dropna(subset=['Email Text'], inplace=True)

    print(f"Loaded {len(df)} emails for analysis.")

    # The classification threshold determines the score needed to flag an email as phishing.
    SCORE_THRESHOLD = 1

    actual_labels = df['Email Type'].tolist()
    predicted_labels = []

    # Loop through the entire dataset and analyze each email
    for email_text in df['Email Text']:
        score = analyze_email(email_text)
        if score >= SCORE_THRESHOLD:
            predicted_labels.append('Phishing Email')
        else:
            predicted_labels.append('Safe Email')

    print("--- Evaluation Complete. Generating Report ---")

    # --- Generate and Print the Performance Report ---

    # Calculate performance metrics using scikit-learn
    accuracy = accuracy_score(actual_labels, predicted_labels)
    precision = precision_score(actual_labels, predicted_labels, pos_label='Phishing Email', zero_division=0)
    recall = recall_score(actual_labels, predicted_labels, pos_label='Phishing Email', zero_division=0)

    print("\n--- Performance Metrics (Final Engine) ---")
    print(f"Classification Threshold (Score >=): {SCORE_THRESHOLD}")
    print(f"Accuracy: {accuracy:.2%}")
    print(f"Precision: {precision:.2%}")
    print(f"Recall: {recall:.2%}")

    # Generate and display the confusion matrix in the console
    print("\n--- Confusion Matrix ---")
    cm = confusion_matrix(actual_labels, predicted_labels, labels=['Safe Email', 'Phishing Email'])
    print("                 Predicted")
    print("                 Safe      Phishing")
    print(f"Actual Safe      {cm[0][0]:<10}{cm[0][1]:<10}")
    print(f"Actual Phishing  {cm[1][0]:<10}{cm[1][1]:<10}")

    # Save the graphical confusion matrix to a file for the dissertation report
    output_filename = 'confusion_matrix_final.png'

    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=['Safe Email', 'Phishing Email'],
                yticklabels=['Safe Email', 'Phishing Email'])
    plt.xlabel('Predicted Label')
    plt.ylabel('Actual Label')
    plt.title(f'Confusion Matrix (Final Engine, Threshold >= {SCORE_THRESHOLD})')
    plt.savefig(output_filename)

    print(f"\n[INFO] A graphical confusion matrix has been saved as '{output_filename}'")

