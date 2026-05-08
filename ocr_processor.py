import pytesseract
from PIL import Image, ImageEnhance, ImageFilter
import logging
import sys

logger = logging.getLogger(__name__)

class OCRProcessor:
    def __init__(self):
        # Configure Tesseract path based on OS
        if sys.platform == 'win32':
            pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
        elif sys.platform == 'darwin':
            pytesseract.pytesseract.tesseract_cmd = '/usr/local/bin/tesseract'
        else:
            pytesseract.pytesseract.tesseract_cmd = '/usr/bin/tesseract'
    
    def extract_text(self, image_path):
        """Extract text from image with preprocessing"""
        try:
            # Open and preprocess image
            image = Image.open(image_path)
            processed_image = self.preprocess_image(image)
            
            # Extract text (support English + Amharic)
            # For Amharic support, install tesseract-ocr-amh
            try:
                text = pytesseract.image_to_string(processed_image, lang='eng')
            except:
                text = pytesseract.image_to_string(processed_image, lang='eng')
            
            # Clean and normalize text
            text = ' '.join(text.split())
            text = text.strip()
            
            logger.info(f"OCR extracted {len(text)} characters")
            return text
            
        except Exception as e:
            logger.error(f"OCR error: {str(e)}")
            return ""
    
    def preprocess_image(self, image):
        """Advanced image preprocessing for better OCR"""
        try:
            # Convert to grayscale
            if image.mode != 'L':
                image = image.convert('L')
            
            # Resize if too large (max 2000px)
            max_size = 2000
            if max(image.size) > max_size:
                ratio = max_size / max(image.size)
                new_size = tuple(int(dim * ratio) for dim in image.size)
                image = image.resize(new_size, Image.Resampling.LANCZOS)
            
            # Increase contrast
            enhancer = ImageEnhance.Contrast(image)
            image = enhancer.enhance(2.0)
            
            # Apply sharpening
            image = image.filter(ImageFilter.SHARPEN)
            
            # Binarize image (black and white)
            threshold = 128
            image = image.point(lambda p: p > threshold and 255)
            
            return image
            
        except Exception as e:
            logger.warning(f"Image preprocessing error: {str(e)}")
            return image