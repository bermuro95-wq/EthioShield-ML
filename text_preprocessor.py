import re
import unicodedata

class TextPreprocessor:
    def __init__(self):
        # Emoji pattern
        self.emoji_pattern = re.compile("["
            u"\U0001F600-\U0001F64F"
            u"\U0001F300-\U0001F5FF"
            u"\U0001F680-\U0001F6FF"
            u"\U0001F1E0-\U0001F1FF"
            "]+", flags=re.UNICODE)
    
    def preprocess(self, text):
        """Clean and normalize text for analysis"""
        if not text:
            return ""
        
        # Convert to lowercase
        text = text.lower()
        
        # Remove emojis
        text = self.emoji_pattern.sub(r'', text)
        
        # Remove extra whitespace
        text = ' '.join(text.split())
        
        # Normalize unicode (handle Amharic)
        text = unicodedata.normalize('NFKC', text)
        
        # Remove special characters but keep Amharic (Unicode range 1200-137F)
        text = re.sub(r'[^\w\s\u1200-\u137F]', ' ', text)
        
        # Remove numbers (optional - keep if needed for analysis)
        # text = re.sub(r'\d+', '', text)
        
        return text.strip()
    
    def extract_phone_numbers(self, text):
        """Extract phone numbers from text"""
        phone_pattern = r'\b(?:\+?[0-9]{1,3}[-.]?)?\(?[0-9]{3}\)?[-.]?[0-9]{3}[-.]?[0-9]{4}\b'
        return re.findall(phone_pattern, text)
    
    def extract_emails(self, text):
        """Extract email addresses"""
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        return re.findall(email_pattern, text)