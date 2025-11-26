Python script version 3.13.9 to analyze emails in .eml format to identify phishing. 
A score is assigned for each check: +1 if the check is successful, -1 if the email contains suspicious phishing fields.
The final analysis results in a score if >= 0 emails are classified as SPAM. 
If the final score is <0, an alert is provided for the presence of phishing emails.

Script Usage
$ python3 EN_CL_Phish_Check_ver_1.3.py test_email_1.eml
