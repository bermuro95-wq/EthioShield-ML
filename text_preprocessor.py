import re 
import unicodedata 

class TextPreprocessor: 
    def __init__(self): 
        # Emoji pattern - expanded to include modern security/financial emojis
        self.emoji_pattern = re.compile("[" 
            u"\U0001F600-\U0001F64F" 
            u"\U0001F300-\U0001F5FF" 
            u"\U0001F680-\U0001F6FF" 
            u"\U0001F1E0-\U0001F1FF" 
            "]+", flags=re.UNICODE) 
     
    def preprocess(self, text): 
        """Clean and normalize text specifically for Ethiopian Cyber-Threat analysis""" 
        if not text: 
            return "" 
         
        # Convert to lowercase 
        text = text.lower() 
         
        # Normalize unicode (Handles Ge'ez/Amharic script variations)
        # NFKC is crucial for ensuring 'አ' is always treated as the same character
        text = unicodedata.normalize('NFKC', text) 
         
        # Remove emojis 
        text = self.emoji_pattern.sub(r'', text) 
         
        # ETHIOPIAN SPECIFIC: Replace Amharic full stops (።) and commas (፣) with spaces
        # This prevents the model from getting confused by punctuation attached to words.
        text = text.replace('።', ' ').replace('፣', ' ').replace('፡', ' ')
         
        # Remove special characters but keep English and Amharic (U+1200 - U+137F)
        # We also keep numbers as they are vital for identifying fake bank codes/amounts.
        text = re.sub(r'[^\w\s\u1200-\u137F]', ' ', text) 
         
        # Remove extra whitespace 
        text = ' '.join(text.split()) 
         
        return text.strip() 
     
    def extract_ethiopian_phones(self, text): 
        """
        Specialized for Ethiopia: Detects +251..., 09..., or 07... 
        Essential for EthioShield-ML to flag scammer contact info.
        """ 
        # Pattern covers +251911223344, 0911223344, and 0711223344 formats
        ethio_phone_pattern = r'(\+251[79]\d{8}|0[79]\d{8})' 
        return re.findall(ethio_phone_pattern, text) 
     
    def extract_emails(self, text): 
        """Extract email addresses""" 
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b' 
        return re.findall(email_pattern, text)