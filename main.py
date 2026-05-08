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

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize components
scam_detector = ScamDetector()
phishing_detector = PhishingDetector()
ocr_processor = OCRProcessor()

# Amharic scam keywords
AMHARIC_KEYWORDS = {
    'urgent': ['አስቸኳይ', 'በፍጥነት'],
    'verify': ['አረጋግጥ', 'ማረጋገጫ'],
    'account': ['አካውንት', 'መለያ'],
    'bank': ['ባንክ', 'ባንክዎ'],
    'winner': ['አሸናፊ', 'ሽልማት'],
    'password': ['የይለፍ ቃል', 'ፓስወርድ']
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
        
        # Process image if uploaded
        if image_file and image_file.filename:
            filename = secure_filename(image_file.filename)
            filepath = os.path.join('uploads', filename)
            image_file.save(filepath)
            
            # Extract text from image
            extracted_text = ocr_processor.extract_text(filepath)
            logger.info(f"OCR extracted: {extracted_text[:100]}")
            
            # Clean up
            os.remove(filepath)
        
        # Combine text inputs
        full_text = text_input + " " + extracted_text if extracted_text else text_input
        
        if not full_text.strip():
            return jsonify({'error': 'No text or image provided'}), 400
        
        # Extract and analyze URLs
        urls_detected = phishing_detector.extract_urls(full_text)
        url_analysis = []
        for url in urls_detected:
            analysis = phishing_detector.analyze_url(url)
            url_analysis.append(analysis)
        
        # Detect scam using ML
        scam_result = scam_detector.predict(full_text)
        
        # Check for Amharic keywords
        amharic_matches = []
        for category, keywords in AMHARIC_KEYWORDS.items():
            for keyword in keywords:
                if keyword in full_text:
                    amharic_matches.append(keyword)
        
        # Combine suspicious keywords
        all_suspicious = list(set(scam_result['suspicious_words'] + amharic_matches))
        
        # Generate explanation
        explanation = generate_explanation(full_text, scam_result, url_analysis, amharic_matches)
        
        response = {
            'result': 'SCAM' if scam_result['is_scam'] else 'SAFE',
            'confidence': scam_result['confidence'],
            'urls_detected': urls_detected,
            'url_analysis': url_analysis,
            'suspicious_keywords': all_suspicious[:10],
            'explanation': explanation,
            'processed_text': extracted_text if extracted_text else None
        }
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Prediction error: {str(e)}")
        return jsonify({'error': str(e)}), 500

def generate_explanation(text, scam_result, url_analysis, amharic_matches):
    """Generate detailed human-readable explanation"""
    reasons = []
    
    # ML confidence based explanation
    if scam_result['confidence'] > 80:
        reasons.append(f"🔴 HIGH RISK: Neural network detected scam patterns with {scam_result['confidence']:.0f}% confidence")
    elif scam_result['confidence'] > 60:
        reasons.append(f"⚠️ MEDIUM RISK: ML model identified suspicious patterns ({scam_result['confidence']:.0f}% confidence)")
    elif scam_result['confidence'] > 30:
        reasons.append(f"ℹ️ LOW RISK: Some suspicious indicators found ({scam_result['confidence']:.0f}% confidence)")
    
    # Suspicious keywords
    if scam_result['suspicious_words']:
        keywords = ', '.join(scam_result['suspicious_words'][:5])
        reasons.append(f"📝 Contains known scam keywords: {keywords}")
    
    # Amharic keywords
    if amharic_matches:
        reasons.append(f"🇪🇹 Amharic scam indicators detected: {', '.join(amharic_matches)}")
    
    # Urgency tactics
    urgency_words = ['urgent', 'immediately', 'asap', 'now', 'today', '立即']
    if any(word in text.lower() for word in urgency_words):
        reasons.append("⏰ Uses urgency tactics to pressure immediate action (common scam technique)")
    
    # URL analysis
    for url_info in url_analysis:
        if url_info['is_suspicious']:
            reasons.append(f"🔗 {url_info['reason']}: {url_info['domain']}")
    
    # Sensitive information requests
    sensitive_patterns = ['password', 'credit card', 'ssn', 'pin', 'verify account', 'bank details']
    if any(pattern in text.lower() for pattern in sensitive_patterns):
        reasons.append("🔐 Requests sensitive personal information (never share this data)")
    
    # Grammar/spelling patterns
    if len(text.split()) > 10 and scam_result['confidence'] > 70:
        reasons.append("📊 Text patterns match known scam message characteristics")
    
    if not reasons:
        reasons.append("✅ No scam indicators detected - message appears safe")
    
    return reasons

# For running directly
if __name__ == '__main__':
    from app import create_app
    app = create_app()
    app.run(debug=True, host='0.0.0.0', port=5000)