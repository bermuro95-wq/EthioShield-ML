import pandas as pd 
import numpy as np 
from sklearn.model_selection import train_test_split 
from sklearn.preprocessing import LabelEncoder 
from tensorflow.keras.preprocessing.text import Tokenizer 
from tensorflow.keras.preprocessing.sequence import pad_sequences 
from tensorflow.keras.models import Sequential 
from tensorflow.keras.layers import Embedding, LSTM, Dense, Dropout, Bidirectional 
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint, ReduceLROnPlateau 
import pickle 
import os 

def create_enhanced_dataset():
    """Create a 10/10 Ethiopian-Focused Dataset for EthioShield-ML"""
    
    scam_messages = [
        # --- Standard Scams ---
        "URGENT: Your bank account has been suspended. Click here to verify",
        "Congratulations! You've won $1,000,000. Send bank details",
        "Security alert: Unusual login detected. Verify your account now",
        "Your PayPal account has been limited. Please update your information now",
        "IRS: Tax refund pending. Click to claim your $3000 refund",
        
        # --- ETHIOPIAN SPECIFIC SCAMS (The INSA Differentiator) ---
        "Your CBE account is locked. Call 09... to unlock your balance immediately",
        "Telebirr Award: You have received 5000 ETB. Click here to claim your prize",
        "ሽልማት: የ 100,000 ብር እጣ ደርሶዎታል:: ለመቀበል ይህን ይጫኑ", 
        "አስቸኳይ: የባንክ አካውንትዎ ተዘግቷል:: መለያዎን እዚህ ያረጋግጡ", 
        "CBE-Birr: Your account has been credited with 10,000 ETB. Confirm now",
        "ብድር ይፈልጋሉ? ያለምንም ማስያዣ በቴሌብር ይበደሩ:: እዚህ ይጫኑ", 
        "Your Dashen Bank OTP is 4452. Do not share. Verify your login at: bit.ly/fake-link",
        "Abyssinia Bank: Update your mobile banking apps now to avoid service cut.",
        "Your Enat Bank account requires immediate authentication. Click to signin."
    ]
    
    safe_messages = [
        "Selam, how are you? Let's meet at 2pm near the stadium.",
        "Your Telebirr balance is 150.25 ETB. Thank you for using Ethio Telecom.",
        "Meeting reminder: Information Systems class representative sync tomorrow.",
        "እንደምን አደርክ? ዛሬ ለምሳ እንገናኝ?", 
        "Wachemo University: Semester graduation schedule has been posted.",
        "Please pick up some Shiro and Teff on your way home.",
        "Your package from Dubai is arriving tomorrow morning.",
        "The project deadline for EthioShield-ML is set for Friday.",
        "Can you send me the ICT Directorate office location again?",
        "Hey Yoseph, did you finish the penetration testing lab?",
        "Thanks for your purchase! Your receipt is attached",
        "Happy birthday! Hope you have a great day"
    ]
    
    scam_df = pd.DataFrame({'text': scam_messages, 'label': 1})
    safe_df = pd.DataFrame({'text': safe_messages, 'label': 0})
    
    # Balance and over-sample to give the LSTM enough data to learn patterns
    df = pd.concat([scam_df, safe_df], ignore_index=True)
    df = pd.concat([df] * 20, ignore_index=True) 
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    print(f"Dataset created: {len(df)} samples ({df['label'].sum()} scam indicators)")
    return df

def train_lstm_model(): 
    """Train Bidirectional LSTM for EthioShield-ML Detection Engine"""
    
    print("="*60) 
    print("EthioShield-ML: National Cyber Defense Training Pipeline") 
    print("="*60) 
    
    # Load dataset 
    df = create_enhanced_dataset() 
    X, y = df['text'].values, df['label'].values 
    
    # Split data 
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42) 
    
    # Tokenization setup
    max_words, max_len = 10000, 100 
    tokenizer = Tokenizer(num_words=max_words, oov_token='<OOV>') 
    tokenizer.fit_on_texts(X_train) 
    
    X_train_pad = pad_sequences(tokenizer.texts_to_sequences(X_train), maxlen=max_len, padding='post') 
    X_test_pad = pad_sequences(tokenizer.texts_to_sequences(X_test), maxlen=max_len, padding='post') 
    
    label_encoder = LabelEncoder() 
    y_train_enc = label_encoder.fit_transform(y_train) 
    y_test_enc = label_encoder.transform(y_test) 
    
    # Building the Advanced Neural Network 
    model = Sequential([ 
        Embedding(max_words, 128, input_length=max_len), 
        Bidirectional(LSTM(64, dropout=0.3, return_sequences=True)), 
        Bidirectional(LSTM(32, dropout=0.3)), 
        Dense(64, activation='relu'), 
        Dropout(0.4), 
        Dense(1, activation='sigmoid') 
    ]) 
    
    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy']) 
    
    # Training Callbacks
    os.makedirs('models', exist_ok=True)
    callbacks = [
        EarlyStopping(patience=5, restore_best_weights=True),
        ModelCheckpoint('models/scam_model.h5', save_best_only=True)
    ]
    
    print("\nStarting Neural Network Training...") 
    model.fit(X_train_pad, y_train_enc, epochs=25, batch_size=16, 
              validation_data=(X_test_pad, y_test_enc), callbacks=callbacks) 
    
    # Save artifacts for the Flask app to use
    with open('models/tokenizer.pkl', 'wb') as f: 
        pickle.dump(tokenizer, f) 
    with open('models/label_encoder.pkl', 'wb') as f: 
        pickle.dump(label_encoder, f) 
    
    print("\nTraining Complete. Models saved to 'models/' directory.")

if __name__ == '__main__': 
    train_lstm_model()