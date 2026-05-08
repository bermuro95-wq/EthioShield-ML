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
    """Create comprehensive training dataset"""
    
    scam_messages = [
        # Financial scams
        "URGENT: Your bank account has been suspended. Click here to verify immediately",
        "Your PayPal account has been limited. Please update your information now",
        "Bank of America: Unusual activity detected. Verify your account now",
        "Your credit card has been charged $500. Call this number to dispute",
        "IRS: Tax refund pending. Click to claim your $3000 refund",
        
        # Prize scams
        "Congratulations! You've won $1,000,000. Send us your bank details to claim prize",
        "FREE iPhone giveaway! Click this link to claim your prize now",
        "You are the lucky winner of our lottery. Send $200 for processing",
        
        # Employment scams
        "Work from home! Make $5000 weekly. Limited positions available",
        "You have been selected for a job. Send $100 for background check",
        
        # Account verification scams
        "Security alert: Unusual login detected. Verify your account now",
        "Your Netflix subscription has expired. Update payment method",
        "Amazon: Your order cannot be delivered. Confirm your address",
        
        # Nigerian prince style
        "I am a prince needing help to transfer $10 million. Send your bank details",
        
        # Tech support scams
        "Your computer has a virus! Call Microsoft support immediately",
        
        # Romance scams
        "I love you! Send me money so I can visit you",
        
        # Investment scams
        "Double your Bitcoin in 24 hours! Limited time offer",
        
        # Fake invoice scams
        "Invoice #INV-2024-001 is overdue. Pay immediately to avoid legal action",
    ]
    
    safe_messages = [
        "Hey, how are you doing today? Want to grab lunch?",
        "Your package has been shipped. Track it here: amazon.com/track",
        "Meeting reminder: Team sync at 2 PM tomorrow",
        "Thanks for your purchase! Your receipt is attached",
        "Happy birthday! Hope you have a great day",
        "Can you pick up some milk on your way home?",
        "The project deadline has been extended to Friday",
        "Your appointment is confirmed for Tuesday at 3 PM",
        "Don't forget to submit your timesheet by Friday",
        "Great job on the presentation today!",
        "Let's meet at Starbucks at 10am",
        "The weather is beautiful today",
        "I finished reading that book you recommended",
        "Dinner at 7pm? I'll make reservations",
        "Your order #12345 has been delivered",
    ]
    
    # Create DataFrame
    scam_df = pd.DataFrame({'text': scam_messages, 'label': 1})
    safe_df = pd.DataFrame({'text': safe_messages, 'label': 0})
    
    # Duplicate safe messages for balance
    safe_df = pd.concat([safe_df] * (len(scam_df) // len(safe_df) + 1), ignore_index=True)
    safe_df = safe_df.head(len(scam_df))
    
    df = pd.concat([scam_df, safe_df], ignore_index=True)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    print(f"Dataset created: {len(df)} samples ({df['label'].sum()} scam, {len(df)-df['label'].sum()} safe)")
    return df

def train_lstm_model():
    """Train LSTM neural network for scam detection"""
    
    print("="*60)
    print("EthioShield-ML Training Pipeline")
    print("="*60)
    
    # Load dataset
    print("\n[1/5] Loading dataset...")
    df = create_enhanced_dataset()
    
    # Prepare data
    X = df['text'].values
    y = df['label'].values
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    print(f"Training samples: {len(X_train)}, Test samples: {len(X_test)}")
    
    # Tokenize text
    print("\n[2/5] Tokenizing text...")
    max_words = 10000
    max_len = 100
    
    tokenizer = Tokenizer(num_words=max_words, oov_token='<OOV>')
    tokenizer.fit_on_texts(X_train)
    
    X_train_seq = tokenizer.texts_to_sequences(X_train)
    X_test_seq = tokenizer.texts_to_sequences(X_test)
    
    X_train_pad = pad_sequences(X_train_seq, maxlen=max_len, padding='post', truncating='post')
    X_test_pad = pad_sequences(X_test_seq, maxlen=max_len, padding='post', truncating='post')
    
    print(f"Vocabulary size: {len(tokenizer.word_index)}")
    
    # Encode labels
    label_encoder = LabelEncoder()
    y_train_enc = label_encoder.fit_transform(y_train)
    y_test_enc = label_encoder.transform(y_test)
    
    # Build LSTM model
    print("\n[3/5] Building LSTM neural network...")
    model = Sequential([
        Embedding(max_words, 128, input_length=max_len),
        Bidirectional(LSTM(64, dropout=0.5, return_sequences=True)),
        Bidirectional(LSTM(32, dropout=0.5)),
        Dense(64, activation='relu'),
        Dropout(0.3),
        Dense(32, activation='relu'),
        Dropout(0.2),
        Dense(1, activation='sigmoid')
    ])
    
    model.compile(
        optimizer='adam',
        loss='binary_crossentropy',
        metrics=['accuracy', 'precision', 'recall']
    )
    
    model.summary()
    
    # Callbacks
    callbacks = [
        EarlyStopping(patience=5, restore_best_weights=True, verbose=1),
        ReduceLROnPlateau(factor=0.5, patience=3, verbose=1),
        ModelCheckpoint('models/scam_model.h5', save_best_only=True, verbose=1)
    ]
    
    # Train model
    print("\n[4/5] Training model...")
    history = model.fit(
        X_train_pad, y_train_enc,
        epochs=30,
        batch_size=32,
        validation_data=(X_test_pad, y_test_enc),
        callbacks=callbacks,
        verbose=1
    )
    
    # Evaluate
    print("\n[5/5] Evaluating model...")
    loss, accuracy, precision, recall = model.evaluate(X_test_pad, y_test_enc)
    
    print("\n" + "="*60)
    print("Training Results:")
    print(f"Accuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"Loss:      {loss:.4f}")
    print("="*60)
    
    # Save artifacts
    os.makedirs('models', exist_ok=True)
    with open('models/tokenizer.pkl', 'wb') as f:
        pickle.dump(tokenizer, f)
    with open('models/label_encoder.pkl', 'wb') as f:
        pickle.dump(label_encoder, f)
    
    print("\n Model and artifacts saved to 'models/' directory")
    
    # Test predictions
    print("\n Testing sample predictions:")
    test_samples = [
        "URGENT: Your account has been suspended! Click here to verify",
        "Hey, want to grab coffee tomorrow?",
        "You won $1000! Send your bank details now",
        "Don't forget our meeting at 2pm"
    ]
    
    for sample in test_samples:
        seq = tokenizer.texts_to_sequences([sample])
        padded = pad_sequences(seq, maxlen=max_len, padding='post', truncating='post')
        pred = model.predict(padded, verbose=0)[0][0]
        result = "SCAM" if pred > 0.5 else "SAFE"
        print(f"  '{sample[:50]}...' -> {result} ({pred*100:.1f}%)")
    
    return model, history

if __name__ == '__main__':
    train_lstm_model()