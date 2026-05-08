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
        self.load_model()
        
        # Comprehensive scam keyword patterns
        self.scam_patterns = {
            'urgency': r'\b(urgent|immediate|asap|quickly|now|today|action required)\b',
            'verification': r'\b(verify|confirm|validate|update|reactivate|unlock)\b',
            'financial': r'\b(bank|account|payment|transfer|credit|money|loan|refund)\b',
            'prize': r'\b(winner|won|prize|lucky|reward|gift|congratulations|lottery)\b',
            'threat': r'\b(suspended|blocked|closed|terminated|violation|legal|fraud)\b',
            'personal': r'\b(password|ssn|social security|credit card|pin|login|credentials)\b'
        }
        
        self.scam_keywords = [
            'urgent', 'verify', 'account', 'suspended', 'winner', 'prize', 'password',
            'credit card', 'bank account', 'click here', 'limited time', 'exclusive offer',
            'confirm now', 'security alert', 'unusual activity', 'payment required'
        ]
    
    def load_model(self):
        """Load pre-trained LSTM model if available"""
        try:
            if os.path.exists('models/scam_model.h5'):
                from tensorflow.keras.models import load_model
                self.model = load_model('models/scam_model.h5')
                with open('models/tokenizer.pkl', 'rb') as f:
                    self.tokenizer = pickle.load(f)
                self.use_fallback = False
                logger.info("LSTM model loaded successfully")
            else:
                logger.warning("No model found, using fallback detection")
        except Exception as e:
            logger.error(f"Model loading error: {str(e)}")
    
    def extract_suspicious_words(self, text):
        """Extract suspicious keywords from text"""
        suspicious = []
        text_lower = text.lower()
        
        for keyword in self.scam_keywords:
            if keyword in text_lower:
                suspicious.append(keyword)
        
        # Check patterns
        for pattern_name, pattern in self.scam_patterns.items():
            if re.search(pattern, text_lower, re.IGNORECASE):
                if pattern_name not in suspicious:
                    suspicious.append(pattern_name)
        
        return list(set(suspicious[:10]))
    
    def predict(self, text):
        """Predict if text is scam or safe"""
        try:
            suspicious_words = self.extract_suspicious_words(text)
            
            # Calculate base score from keywords
            base_score = min(len(suspicious_words) * 12, 50)
            
            # ML prediction if available
            ml_score = 0
            if not self.use_fallback and self.model and self.tokenizer:
                from tensorflow.keras.preprocessing.sequence import pad_sequences
                sequence = self.tokenizer.texts_to_sequences([text])
                padded = pad_sequences(sequence, maxlen=100)
                prediction = self.model.predict(padded, verbose=0)
                ml_score = float(prediction[0][0]) * 100
                final_confidence = min(base_score + ml_score * 0.5, 100)
            else:
                # Enhanced rule-based scoring
                text_lower = text.lower()
                score = base_score
                
                # URL detection
                if re.search(r'https?://\S+', text_lower):
                    score += 15
                
                # Phone numbers
                if re.search(r'\b\d{10,}\b', text_lower):
                    score += 10
                
                # Excessive punctuation
                if text_lower.count('!') > 2 or text_lower.count('?') > 2:
                    score += 5
                
                # ALL CAPS sections
                if any(len(word) > 3 and word.isupper() for word in text.split()):
                    score += 10
                
                final_confidence = min(score, 100)
                ml_score = final_confidence
            
            is_scam = final_confidence > 50
            
            return {
                'is_scam': is_scam,
                'confidence': round(final_confidence, 2),
                'suspicious_words': suspicious_words,
                'ml_score': round(ml_score, 2)
            }
            
        except Exception as e:
            logger.error(f"Prediction error: {str(e)}")
            return {
                'is_scam': False,
                'confidence': 0.0,
                'suspicious_words': [],
                'error': str(e)
            }