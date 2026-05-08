import numpy as np 
import pickle 
import os 
import re 
import logging 

logger = logging.getLogger(__name__) 

class ScamDetector: 
    def __init__(self): 
        self.model = None 
        self.tokenizer = None 
        self.use_fallback = True 
        
        # Ethiopian-Specific Scam Patterns (The "INSA" Differentiator)
        self.scam_patterns = { 
            'urgency': r'\b(urgent|immediate|asap|now|today|አስቸኳይ|አሁኑኑ)\b', 
            'verification': r'\b(verify|confirm|validate|update|unlock|አረጋግጥ|ክፈት)\b', 
            'financial': r'\b(bank|account|transfer|money|loan|cbe|telebirr|birr|ብር|ባንክ|አካውንት)\b', 
            'prize': r'\b(winner|won|prize|reward|gift|congratulations|ሽልማት|እጣ)\b', 
            'threat': r'\b(suspended|blocked|closed|terminated|fraud|ተዘግቷል|ታግዷል)\b', 
            'personal': r'\b(password|pin|login|credentials|ሚስጥር|መለያ)\b' 
        } 
        
        # Expanded keywords including Amharic Common Scams
        self.scam_keywords = [ 
            'urgent', 'verify', 'account', 'suspended', 'winner', 'prize', 
            'click here', 'confirm now', 'security alert', 'payment required',
            'telebirr', 'cbe birr', 'commercial bank', 'ሽልማት', 'አስቸኳይ', 'አረጋግጥ'
        ] 
        
        self.load_model() 
     
    def load_model(self): 
        """Load pre-trained LSTM model from the 'models/' directory""" 
        try: 
            model_path = 'models/scam_model.h5'
            tokenizer_path = 'models/tokenizer.pkl'
            
            if os.path.exists(model_path) and os.path.exists(tokenizer_path): 
                from tensorflow.keras.models import load_model 
                self.model = load_model(model_path) 
                with open(tokenizer_path, 'rb') as f: 
                    self.tokenizer = pickle.load(f) 
                self.use_fallback = False 
                logger.info("EthioShield-ML: LSTM model loaded successfully") 
            else: 
                logger.warning("No ML model found. Using Rule-Based Fallback.") 
        except Exception as e: 
            logger.error(f"Model loading error: {str(e)}") 
     
    def extract_suspicious_words(self, text): 
        """Extract suspicious keywords and patterns from text""" 
        suspicious = [] 
        text_lower = text.lower() 
         
        # Check explicit keywords
        for keyword in self.scam_keywords: 
            if keyword in text_lower: 
                suspicious.append(keyword) 
         
        # Check RegEx patterns for Amharic and English urgency/threats
        for pattern_name, pattern in self.scam_patterns.items(): 
            if re.search(pattern, text_lower, re.IGNORECASE): 
                if pattern_name not in suspicious: 
                    suspicious.append(pattern_name) 
         
        return list(set(suspicious[:10])) 
     
    def predict(self, text): 
        """Hybrid Prediction: Combines Neural Network logic with Heuristic Rules""" 
        try: 
            suspicious_words = self.extract_suspicious_words(text) 
             
            # 1. Rule-Based Base Score (Up to 40%)
            rule_score = min(len(suspicious_words) * 10, 40) 
            
            # Additional Heuristics (URL, Phones, Punctuation)
            if re.search(r'https?://\S+', text.lower()): rule_score += 15
            if re.search(r'(\+251[79]\d{8}|0[79]\d{8})', text): rule_score += 15 # Ethio Phone
            if text.count('!') > 2: rule_score += 5
             
            # 2. ML Prediction (The heavy lifter)
            ml_score = 0 
            if not self.use_fallback and self.model and self.tokenizer: 
                from tensorflow.keras.preprocessing.sequence import pad_sequences 
                
                # Preprocessing for the model
                sequence = self.tokenizer.texts_to_sequences([text]) 
                padded = pad_sequences(sequence, maxlen=100, padding='post') 
                
                # Get raw probability (0.0 to 1.0)
                prediction = self.model.predict(padded, verbose=0) 
                ml_score = float(prediction[0][0]) * 100 
                
                # Weighted combination: ML takes priority but Rules add safety
                # Formula: 70% ML + 30% Rules
                final_confidence = (ml_score * 0.7) + (min(rule_score, 100) * 0.3)
            else: 
                # Fallback only
                final_confidence = min(rule_score, 100) 
                ml_score = 0 # No ML available
             
            # Decision Threshold (50%)
            is_scam = final_confidence >= 50 
             
            return { 
                'is_scam': bool(is_scam), 
                'confidence': round(final_confidence, 2), 
                'suspicious_words': suspicious_words, 
                'ml_score': round(ml_score, 2),
                'engine': "Hybrid-LSTM" if not self.use_fallback else "Heuristic-Only"
            } 
             
        except Exception as e: 
            logger.error(f"Prediction error: {str(e)}") 
            return { 
                'is_scam': False, 
                'confidence': 0.0, 
                'suspicious_words': [], 
                'error': str(e) 
            }