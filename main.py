import os 
import re 
import logging 
from flask import Blueprint, request, jsonify, render_template 
from werkzeug.utils import secure_filename 
from app.models.scam_detector import ScamDetector 
from app.models.phishing_detector import PhishingDetector 
from app.utils.ocr_processor import OCRProcessor 

# Create blueprint 
bp = Blueprint('main', __name__) 

# Setup professional logging 
logging.basicConfig(level=logging.INFO) 
logger = logging.getLogger(__name__) 

# Ensure uploads directory exists for OCR processing
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Initialize AI/ML components 
scam_detector = ScamDetector() 
phishing_detector = PhishingDetector() 
ocr_processor = OCRProcessor() 

# ENHANCED: Localized Ethiopian scam keywords
AMHARIC_KEYWORDS = { 
    'urgent': ['አስቸኳይ', 'በፍጥነት', 'አሁኑኑ'], 
    'verify': ['አረጋግጥ', 'ማረጋገጫ', 'ሊንኩን'], 
    'account': ['አካውንት', 'መለያ', 'ዝግ'], 
    'bank': ['ባንክ', 'ባንክዎ', 'ሲቢኢ', 'ንግድ ባንክ'], 
    'winner': ['አሸናፊ', 'ሽልማት', 'እድለኛ', 'ሎተሪ'], 
    'password': ['የይለፍ ቃል', 'ፓስወርድ', 'ሚስጥር'],
    'telebirr': ['ቴሌብር', 'ብር', 'ተልኮለታል']
} 

@bp.route('/') 
def index(): 
    return render_template('index.html') 

@bp.route('/predict', methods=['POST']) 
def predict(): 
    try: 
        text_input = request.form.get('text', '') 
        image_file = request.files.get('image') 
         
        extracted_text = "" 
         
        # 1. OCR PROCESSING (IMAGE TO TEXT)
        if image_file and image_file.filename: 
            filename = secure_filename(image_file.filename) 
            filepath = os.path.join(UPLOAD_FOLDER, filename) 
            image_file.save(filepath) 
             
            # Extract text from image (e.g., screenshot of a scam SMS)
            extracted_text = ocr_processor.extract_text(filepath) 
            logger.info(f"EthioShield OCR Processed: {extracted_text[:100]}") 
             
            # Clean up immediately for privacy/security 
            if os.path.exists(filepath):
                os.remove(filepath) 
         
        # Combine text inputs for total analysis
        full_text = f"{text_input} {extracted_text}".strip()
         
        if not full_text: 
            return jsonify({'error': 'No input detected. Please provide text or an image.'}), 400 
         
        # 2. PHISHING & URL ANALYSIS 
        urls_detected = phishing_detector.extract_urls(full_text) 
        url_analysis = [phishing_detector.analyze_url(url) for url in urls_detected] 
         
        # 3. MACHINE LEARNING PREDICTION
        scam_result = scam_detector.predict(full_text) 
         
        # 4. AMHARIC HEURISTIC CHECK
        amharic_matches = [] 
        for category, keywords in AMHARIC_KEYWORDS.items(): 
            for keyword in keywords: 
                if keyword in full_text: 
                    amharic_matches.append(keyword) 
         
        # Merge all suspicious indicators
        all_suspicious = list(set(scam_result.get('suspicious_words', []) + amharic_matches)) 
         
        # 5. GENERATE HUMAN-READABLE EXPLANATION 
        explanation = generate_explanation(full_text, scam_result, url_analysis, amharic_matches) 
         
        # INSA-READY RESPONSE SCHEMA
        response = { 
            'result': 'SCAM' if (scam_result['is_scam'] or any(u['is_suspicious'] for u in url_analysis)) else 'SAFE', 
            'confidence': scam_result['confidence'], 
            'threat_count': len(all_suspicious),
            'urls_detected': urls_detected, 
            'url_analysis': url_analysis, 
            'suspicious_keywords': all_suspicious[:10], 
            'explanation': explanation, 
            'metadata': {
                'ocr_executed': bool(extracted_text),
                'language': 'Amharic/English Mixed'
            }
        } 
         
        return jsonify(response) 
         
    except Exception as e: 
        logger.error(f"EthioShield System Error: {str(e)}") 
        return jsonify({'error': 'System encountered an error during analysis.'}), 500 

def generate_explanation(text, scam_result, url_analysis, amharic_matches): 
    """Creates a professional security report for the end-user""" 
    reasons = [] 
     
    # Risk Leveling
    if scam_result['confidence'] > 85: 
        reasons.append(f"🛑 CRITICAL: AI identified extreme scam patterns ({scam_result['confidence']:.0f}% confidence).") 
    elif scam_result['confidence'] > 50: 
        reasons.append(f"⚠️ WARNING: Moderate scam indicators detected by Neural Network.") 
     
    # Amharic detection
    if amharic_matches: 
        reasons.append(f"🇪🇹 Localized Scam detected: Found suspicious Amharic terms: {', '.join(amharic_matches[:3])}") 
     
    # Urgency and Pressure Tactics
    urgency_words = ['urgent', 'immediately', 'today', 'now', 'አሁኑኑ', 'አስቸኳይ'] 
    if any(word in text.lower() for word in urgency_words): 
        reasons.append("⏰ Pressure Tactic: Message uses urgency to force a fast, emotional decision.") 
     
    # URL Safety
    for url_info in url_analysis: 
        if url_info['is_suspicious']: 
            reasons.append(f"🔗 Malicious Link: {url_info['reason']}") 
     
    # Sensitive Data Requests 
    if any(p in text.lower() for p in ['password', 'pin', 'otp', 'cbe', 'telebirr']): 
        reasons.append("🚨 Data Theft: Message attempts to solicit banking or login credentials.") 
     
    return reasons if reasons else ["✅ Analysis complete: No known threats detected."]

if __name__ == '__main__': 
    # Use create_app pattern for professional Flask deployment
    try:
        from app import create_app 
        app = create_app() 
        app.run(debug=False, host='0.0.0.0', port=5000)
    except ImportError:
        print("EthioShield: Running in standalone mode.")