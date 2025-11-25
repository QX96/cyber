"""
Introduction: Python Script for checking PHISHING vulnerabilities
Features: ver 1.3
Installation: pip install -r requirements.txt
License: MIT License
Copyright (c) [2025] [Roberto Quadrini]
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
Auhor: Roberto Quadrini
"""
import email
import re
import sys

class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    RESET = '\033[0m' # The \033 code signals to the terminal that what follows is a control code. The value 1 represents bold, m refers to graphic formatting.

def extract_and_examine_email_headers(eml_file_path):
    """
    Extracts and prints the From, Return-Path, and Reply-To headers from an EML file.

    Args:
        eml_file_path (str): The path to the EML file to be analyzed.

    Returns:
        dict: A dictionary containing the values of the extracted headers.
              Returns None in case of an error.
    """
    extracted_headers = {
        "From": None,
        "Return-Path": None,
        "Reply-To": None
    }
    total_score = 0 # Total score counter

    try:
        # Opens the EML file with UTF-8 encoding, ignoring decoding errors
        with open(eml_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            msg = email.message_from_file(f) # This function reads an open file (f) and converts the content into a Python message object (email.message.Message).

        ###############################
        ### Header Analysis Section ###
        ###############################
        print(f"\n--- {Colors.BOLD}Header Analysis{Colors.RESET} ---")

        # Extracts the 'From' header
        from_header = msg['From'] # Extraction of the 'From' field from the message object
        extracted_headers["From"] = from_header
        print(f"From (Sender): {from_header}")

        # 'From' header domain extraction
        from_domain = None
        if from_header:
            # Search for the email address in angle brackets, e.g., "Name" <email@domain.com>
            match = re.search(r'<([^>]+)>', from_header) # The parentheses () define the capture group
            if match:
                email_address = match.group(1)
            else:
                # Otherwise, use the entire header (cleaned of spaces)
                email_address = from_header.strip() # Removes all leading and trailing whitespace
            if '@' in email_address:
                from_domain = email_address.split('@')[-1] # '@' is used as a separator to split the email address into two parts and select the second part (the domain)
                print(f"From (Domain): {from_domain}")

        # 'Return-Path' header (Envelope-From) extraction
        return_path_header = msg['Return-Path'] # Accesses the email message and retrieves the Return-Path value
        extracted_headers["Return-Path"] = return_path_header # Inserts the Return-Path value into a Python dictionary, using "Return-Path" as the key
        print(f"Return-Path (Envelope-From): {return_path_header}")

        # 'Return-Path' domain extraction
        return_path_domain = None
        if return_path_header:
            # Cleans the address of any unnecessary characters like angle brackets
            clean_address = return_path_header.strip().strip('<>') # Removes whitespace from the beginning and end, and then the <> brackets
            if '@' in clean_address:
                # Extracts the part after the '@'
                return_path_domain = clean_address.split('@')[-1] # -1 is used to select the last element of the list, i.e., the second part of the email address
                print(f"Return-Path (Domain): {return_path_domain}")

        # 'Reply-To' header extraction
        reply_to_header = msg['Reply-To']
        extracted_headers["Reply-To"] = reply_to_header
        
        # If 'Reply-To' does not exist, msg['Reply-To'] will return None.
        # It's good practice to handle this for clearer output.
        if reply_to_header:
            print(f"Reply-To: {reply_to_header}")
        else:
            print("Reply-To: Not Present")
        
        if from_header and return_path_header and from_header != return_path_header:
            print(f"{Colors.RED}WARNING:{Colors.RESET} 'From' (Sender) and 'Return-Path' (Envelope-From) are {Colors.RED}DIFFERENT{Colors.RESET} --> Score: {Colors.RED}-1{Colors.RESET}")
            total_score -= 1
        
        else:
            print("DOMAIN: 'From' and 'Return-Path' match or one is absent.")
            total_score += 1

        # Comparison between the 'From' and 'Return-Path' domains
        if from_domain and return_path_domain: # Checks that both variables are not None
            if from_domain.lower() == return_path_domain.lower(): # The lower() method ignores case differences
                print(f"{Colors.YELLOW}INFO:{Colors.RESET} 'From' (Domain) and 'Return-Path' (Domain) are {Colors.GREEN}EQUAL{Colors.RESET} --> Score: {Colors.GREEN}+1{Colors.RESET}")
                total_score += 1
                
            else:
                print(f"{Colors.RED}WARNING{Colors.RESET}: 'From' domain ({from_domain}) and 'Return-Path' domain ({return_path_domain}) are {Colors.RED}DIFFERENT{Colors.RESET} --> Score: {Colors.RED}-1{Colors.RESET}")
                total_score -= 1
            
        # Comparison between 'Reply-To' and 'From'
        if reply_to_header:
            if reply_to_header == from_header:
                print(f"{Colors.YELLOW}INFO:{Colors.RESET} 'Reply-To' and 'From' are {Colors.GREEN}EQUAL{Colors.RESET} --> Score: {Colors.GREEN}+1{Colors.RESET}")
                total_score += 1
            else:
                print(f"{Colors.RED}WARNING:{Colors.RESET} 'Reply-To' ('{reply_to_header}') and 'From' ('{from_header}') are {Colors.RED}DIFFERENT{Colors.RESET} --> Score: {Colors.RED}-1{Colors.RESET}")
                total_score -= 1
        else:
            # If Reply-To is not present, it is neither equal nor different, so no score is applied.
            print(f"{Colors.YELLOW}INFO:{Colors.RESET} 'Reply-To' is not present. No score change.")

        print(f"{Colors.BOLD}Header Analysis Score{Colors.RESET} --> {total_score}")

        ####################################################
        ### Authentication-Results' per SPF, DKIM, DMARC ###
        ####################################################

        auth_results_header = msg['Authentication-Results']
        if auth_results_header:
            print(f"\n--- {Colors.BOLD}Authentication Analysis{Colors.RESET} ---")
            #print(f"Authentication-Results: {auth_results_header.strip()}") # Not all fields are highlighted, as they are superfluous

            ####################
            ### SPF Analysis ### 
            ####################
            spf_match = re.search(r'spf=(\w+)', auth_results_header, re.IGNORECASE)
            if spf_match:
                spf_result = spf_match.group(1).lower()
                if spf_result == 'pass':
                    print(f"SPF Result: {Colors.GREEN}{spf_result}{Colors.RESET} --> Score: {Colors.GREEN}+1{Colors.RESET}")
                    total_score += 1
                else:
                    print(f"SPF Result: {spf_result}Score: --> {Colors.RED}-1{Colors.RESET}")
                    total_score -= 1
                    
            #####################
            ### DKIM Analysis ###
            #####################
            dkim_match = re.search(r'dkim=(\w+)', auth_results_header, re.IGNORECASE)
            if dkim_match:
                dkim_result = dkim_match.group(1).lower()
                if dkim_result == 'pass':
                    print(f"DKIM Result: {Colors.GREEN}{dkim_result}{Colors.RESET} --> Score: {Colors.GREEN}+1{Colors.RESET}")
                    total_score += 1
                else:
                    print(f"DKIM Result: {dkim_result} --> Score: {Colors.RED}-1{Colors.RESET}")
                    total_score -= 1
           
            ###################### 
            ### DMARC Analysis ###
            ######################
            dmarc_match = re.search(r'dmarc=(\w+)', auth_results_header, re.IGNORECASE)
            if dmarc_match:
                dmarc_result = dmarc_match.group(1).lower()
                if dmarc_result == 'pass':
                    print(f"DMARC Result: {Colors.GREEN}{dmarc_result}{Colors.RESET} --> Score: {Colors.GREEN}+1{Colors.RESET}")
                    total_score += 1
                else:
                    print(f"DMARC Result: {dmarc_result}. Score: {Colors.RED}-1{Colors.RESET}")
                    total_score -= 1
        else:
            print("\n--- {Colors.BOLD}Authentication Analysis{Colors.RESET} ---")
            print(f"Authentication-Results: Not Present (impossible to verify SPF/DKIM/DMARC). Score: {Colors.RED}-1{Colors.RESET}")
            total_score -= 1 # Penalty if authentication cannot be verified
        
        print(f"Authentication Analysis Score --> {Colors.BOLD}{total_score}{Colors.RESET}")
        
        #####################
        ### Body Analysis ###  
        #####################
        print(f"\n--- {Colors.BOLD}Body Analysis{Colors.RESET} ---")
        phishing_keywords = ["carte di credito", "pagamento", "fattura", "scaduta", "subito", "pagare", "username", "PIN", "PayPal", "Dati bancari", "verifica account", "sicurezza", "accesso", "clicca qui", "link", "urgente", "immediato", "conferma", "sospeso", "problema", "supporto", "aggiorna", "informazioni personali", "identità", "furto di identità", "password", "account bloccato", "transazione non autorizzata"]
        body = ""
        
        if msg.is_multipart(): # Extraction of an email's body
            for part in msg.walk(): # Generator that traverses all sections within the email message body
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))
                # Extracts the text only if it is not an attachment
                if content_type in ['text/plain', 'text/html'] and 'attachment' not in content_disposition:
                    try:
                        payload = part.get_payload(decode=True)
                        body += payload.decode('utf-8', errors='ignore')
                    except:
                        pass
        else:
            # Non-multipart message
            try:
                payload = msg.get_payload(decode=True)
                body += payload.decode('utf-8', errors='ignore')
            except:
                pass

        found_keywords = [keyword for keyword in phishing_keywords if keyword in body.lower()]
        if found_keywords:
            print(f"Found {len(found_keywords)} suspicious keywords in the text:")
            for keyword in found_keywords:
                print(f"- '{keyword}'. Score: {Colors.RED}-1{Colors.RESET}")
                total_score -= 1
            print(f"Body Analysis Score: --> {Colors.BOLD}{total_score}{Colors.RESET}")
            
        else:
            print("No suspicious keywords found in the text.")
            total_score += 1
            print(f"Body Analysis Score: --> {Colors.BOLD}{total_score}{Colors.RESET}")
        

        # --- Shortened URL Analysis (e.g., bit.ly) ---
        print("\n--- URL Analysis ---")
        if "bit.ly" in body.lower():
            print(f"Suspicious URL (bit.ly). Score: {Colors.RED}-1{Colors.RESET}")
            total_score -= 1
            print(f"URL Score: --> {Colors.BOLD}{total_score}{Colors.RESET}")
        else:
            print("No Suspicious URL (bit.ly) found.")
            total_score += 1
            print(f"URL Score: --> {Colors.BOLD}{total_score}{Colors.RESET}")

       
        # --- Attachment Analysis ---
        print(f"\n--- {Colors.BOLD}Attachment Analysis{Colors.RESET} ---")
        # Defines a set of file extensions commonly associated with security risks.
        dangerous_extensions = {
            "exe", "com", "scr", "bat", "cmd", "pif", "msi", "dll", "ps1", "vbs", 
            "js", "jse", "wsf", "sh", "bin", "elf", "jar", "docm", "xlsm", "pptm", 
            "dotm", "xltm", "pdf", "zip", "rar", "7z", "tar", "gz", "iso", "img", 
            "lnk", "jpg", "png", "mp3", "mp4"
        }

        found_attachments = False
        for part in msg.walk():
            filename = part.get_filename()
            # A more robust way to find attachments is to check if a part has a filename.
            if filename:
                found_attachments = True
                # Extracts the file extension (without the dot) in lowercase for a case-insensitive comparison
                file_ext = filename.split('.')[-1].lower() if '.' in filename else ''
                
                # Checks if the extension is in the list of dangerous extensions
                if file_ext in dangerous_extensions:
                    print(f"Found attachment: '{filename}'. Potentially dangerous type. Score: {Colors.RED}-1{Colors.RESET}")
                    total_score -= 1
                else:
                    print(f"Found attachment: '{filename}'. Type not classified as dangerous. Score: 0")
        if not found_attachments:
            print("No attachments found in the email.") # No attachments found in the email.

        # --- Final Assessment ---
        print("\n" + "="*40)
        print("--- FINAL RISK ASSESSMENT ---")
        print(f"TOTAL RISK SCORE: {total_score}")
        if total_score >= 0:
            print(f"RESULT: {Colors.GREEN}Likely Not Phishing{Colors.RESET}")
        else:
            print(f"RESULT: {Colors.RED}Potential Phishing Email{Colors.RESET}")
        print("="*40)
        
        return extracted_headers

    except FileNotFoundError:
        print(f"Error: The file '{eml_file_path}' was not found.")
        return None
    except Exception as e:
        print(f"An error occurred while processing the file '{eml_file_path}': {e}")
        return None

if __name__ == "__main__":
    # Example usage:
    # To use it, you can pass the EML file path as a command-line argument.
    # python Phish_Check_CL_v1.3.py /path/to/your/file.eml
    # Test the .eml file directly in the development environment with a hardcoded path
    
    # In the command-line version, this should be commented out
    #eml_file_path_for_testing = "/Users/robertoquadrini/VirtualBox/FileShare/Python/Email/phish1.eml"

    # Uncomment in the Command Line version
    # When testing the file directly in the code, the following instructions for handling command-line arguments should be commented out
    if len(sys.argv) < 2:
        print("Usage: python your_script.py <path_to_file.eml>")
        print("       You can pass multiple EML files separated by spaces.")
        sys.exit(1)
    
    # In the command-line version, this should be commented out
    #extracted_data = extract_and_examine_email_headers(eml_file_path_for_testing)
    # Iterates over all EML files provided as arguments
    
    # Reactivate when using an external file (Command Line) by uncommenting from 'for' to 'if extracted_data'
    for eml_file in sys.argv[1:]:
        extracted_data = extract_and_examine_email_headers(eml_file)
        # If you want to do something with the extracted data, you can use it here.
        # For example, you could save it to a CSV file or a database.
        if extracted_data:
             print(f"Data extracted for {eml_file}: {extracted_data}")