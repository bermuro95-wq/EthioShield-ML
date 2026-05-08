import pytesseract 
from PIL import Image, ImageEnhance, ImageFilter 
import logging 
import sys 
import os

logger = logging.getLogger(__name__) 

class OCRProcessor: 
    def __init__(self): 
        # Configure Tesseract path based on OS 
        if sys.platform == 'win32': 
            # Standard path for 64-bit Windows installation
            pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe' 
        elif sys.platform == 'darwin': 
            pytesseract.pytesseract.tesseract_cmd = '/usr/local/bin/tesseract' 
        else: 
            # Standard path for Linux (Ubuntu/Debian)
            pytesseract.pytesseract.tesseract_cmd = '/usr/bin/tesseract' 
     
    def extract_text(self, image_path): 
        """Extract text from image with dual-language support (English + Amharic)""" 
        try: 
            if not os.path.exists(image_path):
                logger.error(f"Image not found at {image_path}")
                return ""

            # Open and preprocess image 
            image = Image.open(image_path) 
            processed_image = self.preprocess_image(image) 
             
            # ETHIO-SPECIFIC: Support English + Amharic (amh)
            # CRITICAL: 'tesseract-ocr-amh' must be installed on the system
            try: 
                # Attempt to extract using both languages simultaneously
                text = pytesseract.image_to_string(processed_image, lang='eng+amh') 
            except Exception as e: 
                logger.warning(f"Amharic OCR failed or not installed, falling back to English: {e}")
                text = pytesseract.image_to_string(processed_image, lang='eng') 
             
            # Clean and normalize text 
            text = ' '.join(text.split()) 
            text = text.strip() 
             
            logger.info(f"EthioShield OCR: Extracted {len(text)} characters") 
            return text 
             
        except Exception as e: 
            logger.error(f"OCR error: {str(e)}") 
            return "" 
     
    def preprocess_image(self, image): 
        """Advanced preprocessing for low-quality screenshots and receipts""" 
        try: 
            # 1. Convert to grayscale 
            if image.mode != 'L': 
                image = image.convert('L') 
             
            # 2. Resize for better character recognition (Scale up 2x)
            # This helps Tesseract read small text in screenshots
            width, height = image.size
            image = image.resize((width * 2, height * 2), Image.Resampling.LANCZOS)
             
            # 3. Increase contrast significantly 
            # Scammers often use low-contrast or blurry images
            enhancer = ImageEnhance.Contrast(image) 
            image = enhancer.enhance(2.5) 
             
            # 4. Apply sharpening 
            image = image.filter(ImageFilter.SHARPEN) 
             
            # 5. Adaptive-style Binarization
            # Converts the image to high-contrast Black and White
            threshold = 140 
            image = image.point(lambda p: p > threshold and 255) 
             
            return image 
             
        except Exception as e: 
            logger.warning(f"Image preprocessing error: {str(e)}") 
            return image