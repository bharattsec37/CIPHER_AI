"""
Machine Learning AI Security System
Uses TF-IDF + Logistic Regression to classify prompts as SAFE or MALICIOUS
"""

import pandas as pd
import os
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix


# ============================================================================
# GLOBAL VARIABLES
# ============================================================================

# Model components (initialized during training)
vectorizer = None
model = None


# ============================================================================
# MODEL TRAINING
# ============================================================================

def train_model(dataset_path: str = "dataset.csv", test_size: float = 0.2, random_state: int = 42):
    """
    Train the ML security model.
    
    Args:
        dataset_path: Path to the CSV dataset file
        test_size: Proportion of data for testing (default: 0.2)
        random_state: Random seed for reproducibility (default: 42)
        
    Returns:
        Dictionary containing training results and metrics
    """
    global vectorizer, model
    
    print("=" * 70)
    print("TRAINING ML AI SECURITY SYSTEM")
    print("=" * 70)
    
    # Load dataset
    if not os.path.exists(dataset_path):
        raise FileNotFoundError(f"Dataset file not found: {dataset_path}")
    
    data = pd.read_csv(dataset_path)
    print(f"\n📊 Dataset loaded: {len(data)} samples")
    print(f"   - Columns: {list(data.columns)}")
    
    # Check label distribution
    label_counts = data["label"].value_counts()
    print(f"\n📈 Label distribution:")
    for label, count in label_counts.items():
        percentage = (count / len(data)) * 100
        print(f"   - {label}: {count} ({percentage:.1f}%)")
    
    # Features and labels
    X = data["text"]
    y = data["label"]
    
    # Split data into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, 
        test_size=test_size, 
        random_state=random_state,
        stratify=y  # Maintain label distribution in both sets
    )
    
    print(f"\n🔀 Data split:")
    print(f"   - Training samples: {len(X_train)}")
    print(f"   - Testing samples: {len(X_test)}")
    
    # Text vectorization with TF-IDF
    print("\n🔤 Converting text to numerical features (TF-IDF)...")
    vectorizer = TfidfVectorizer(
        max_features=5000,        # Limit to top 5000 features
        ngram_range=(1, 2),       # Use unigrams and bigrams
        min_df=2,                 # Ignore terms that appear in less than 2 documents
        max_df=0.95,              # Ignore terms that appear in more than 95% of documents
        strip_accents='unicode',  # Remove accents
        lowercase=True,           # Convert to lowercase
        stop_words='english'      # Remove common English stop words
    )
    
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)
    
    print(f"   - Feature matrix shape: {X_train_vec.shape}")
    print(f"   - Vocabulary size: {len(vectorizer.vocabulary_)}")
    
    # Train Logistic Regression model
    print("\n🤖 Training Logistic Regression model...")
    model = LogisticRegression(
        max_iter=1000,           # Increase iterations for convergence
        C=1.0,                   # Regularization strength
        solver='lbfgs',          # Optimization algorithm
        random_state=random_state,
        class_weight='balanced'  # Handle class imbalance
    )
    
    model.fit(X_train_vec, y_train)
    print("   ✅ Model training completed!")
    
    # Make predictions
    y_train_pred = model.predict(X_train_vec)
    y_test_pred = model.predict(X_test_vec)
    
    # Calculate accuracies
    train_accuracy = accuracy_score(y_train, y_train_pred)
    test_accuracy = accuracy_score(y_test, y_test_pred)
    
    # Print evaluation metrics
    print("\n" + "=" * 70)
    print("MODEL EVALUATION")
    print("=" * 70)
    print(f"\n📊 Accuracy:")
    print(f"   - Training Accuracy: {train_accuracy:.4f} ({train_accuracy * 100:.2f}%)")
    print(f"   - Testing Accuracy:  {test_accuracy:.4f} ({test_accuracy * 100:.2f}%)")
    
    # Classification report
    print(f"\n📋 Detailed Classification Report (Test Set):")
    print("-" * 70)
    print(classification_report(y_test, y_test_pred, target_names=['MALICIOUS', 'SAFE']))
    
    # Confusion matrix
    print(f"🔍 Confusion Matrix (Test Set):")
    cm = confusion_matrix(y_test, y_test_pred, labels=['SAFE', 'MALICIOUS'])
    print("-" * 70)
    print(f"                  Predicted")
    print(f"                  SAFE    MALICIOUS")
    print(f"Actual SAFE       {cm[0][0]:<8}{cm[0][1]:<8}")
    print(f"       MALICIOUS  {cm[1][0]:<8}{cm[1][1]:<8}")
    
    print("\n" + "=" * 70)
    print("✅ TRAINING COMPLETE!")
    print("=" * 70)
    
    return {
        "train_accuracy": train_accuracy,
        "test_accuracy": test_accuracy,
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "vocabulary_size": len(vectorizer.vocabulary_),
        "classification_report": classification_report(y_test, y_test_pred, output_dict=True)
    }


# ============================================================================
# PREDICTION FUNCTION
# ============================================================================

def _ensure_model_trained():
    """
    Lazily train the model if it hasn't been loaded yet.
    Silently skips if dataset.csv is not found.
    """
    global vectorizer, model
    if vectorizer is None or model is None:
        try:
            train_model()
        except FileNotFoundError:
            pass  # No dataset available — prediction will raise RuntimeError
        except Exception:
            pass

def ml_predict(prompt: str) -> str:
    """
    Predict whether a prompt is SAFE or MALICIOUS.
    
    Args:
        prompt: User input text to classify
        
    Returns:
        "SAFE" or "MALICIOUS"
        
    Raises:
        RuntimeError: If model hasn't been trained yet
    """
    global vectorizer, model
    
    if vectorizer is None or model is None:
        raise RuntimeError(
            "Model not trained! Please run train_model() first or "
            "ensure the script has been executed to train the model."
        )
    
    # Vectorize the input prompt
    prompt_vec = vectorizer.transform([prompt])
    
    # Make prediction
    prediction = model.predict(prompt_vec)[0]
    
    return prediction


def ml_analyze(prompt: str) -> dict:
    """
    Analyze a prompt and return detailed risk assessment.
    
    Args:
        prompt: User input text to analyze
        
    Returns:
        Dictionary containing:
            - prediction: "SAFE" or "MALICIOUS"
            - risk_score: Integer from 0-100
            - confidence: Float probability of the prediction
            - risk_level: "LOW", "MEDIUM", or "HIGH"
            
    Raises:
        RuntimeError: If model hasn't been trained yet
    """
    global vectorizer, model
    
    if vectorizer is None or model is None:
        raise RuntimeError(
            "Model not trained! Please run train_model() first or "
            "ensure the script has been executed to train the model."
        )
    
    # Vectorize the input prompt
    prompt_vec = vectorizer.transform([prompt])
    
    # Get prediction probabilities
    # predict_proba returns [[prob_class_0, prob_class_1]]
    probabilities = model.predict_proba(prompt_vec)[0]
    
    # Get class labels to identify which index is MALICIOUS
    classes = model.classes_
    malicious_idx = list(classes).index("MALICIOUS")
    safe_idx = list(classes).index("SAFE")
    
    # Get probability of MALICIOUS class
    malicious_prob = probabilities[malicious_idx]
    safe_prob = probabilities[safe_idx]
    
    # Determine prediction based on higher probability
    if malicious_prob > safe_prob:
        prediction = "MALICIOUS"
        confidence = malicious_prob
    else:
        prediction = "SAFE"
        confidence = safe_prob
    
    # Convert MALICIOUS probability to risk score (0-100)
    risk_score = int(malicious_prob * 100)
    
    # Determine risk level based on MALICIOUS probability
    if malicious_prob > 0.8:
        risk_level = "HIGH"
    elif malicious_prob >= 0.5:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"
    
    return {
        "prediction": prediction,
        "risk_score": risk_score,
        "confidence": float(confidence),
        "risk_level": risk_level
    }


# ============================================================================
# PUBLIC API WRAPPER  (used by /predict endpoint)
# ============================================================================

def predict_ml(text: str) -> dict:
    """
    Public wrapper for the /predict endpoint.

    Lazily trains the model on first call if not already trained.
    Returns the same dict as ml_analyze() or an error dict on failure.

    Args:
        text: User input prompt to classify

    Returns:
        dict with keys: prediction, risk_score, confidence, risk_level
        On error: {"error": "<message>", "prediction": "UNKNOWN", "risk_score": 0,
                   "confidence": 0.0, "risk_level": "UNKNOWN"}
    """
    _ensure_model_trained()
    try:
        return ml_analyze(text)
    except RuntimeError as exc:
        return {
            "error": str(exc),
            "prediction": "UNKNOWN",
            "risk_score": 0,
            "confidence": 0.0,
            "risk_level": "UNKNOWN",
        }


# ============================================================================
# MAIN EXECUTION
# ============================================================================

if __name__ == "__main__":
    # Train the model
    try:
        results = train_model()
        
        # Interactive testing loop
        print("\n\n" + "=" * 70)
        print("INTERACTIVE TESTING MODE - RISK SCORING ENABLED")
        print("=" * 70)
        print("Enter prompts to test the model. Type 'exit' to quit.\n")
        
        while True:
            try:
                user_input = input("\n🔍 Enter prompt: ")
                
                if user_input.lower() in ["exit", "quit", "q"]:
                    print("\n👋 Goodbye!")
                    break
                
                if not user_input.strip():
                    print("⚠️  Please enter a non-empty prompt.")
                    continue
                
                # Use ml_analyze for detailed risk assessment
                analysis = ml_analyze(user_input)
                
                # Display results with color coding
                print(f"\n{'='*60}")
                if analysis["prediction"] == "SAFE":
                    print(f"✅ Prediction: {analysis['prediction']}")
                else:
                    print(f"🚨 Prediction: {analysis['prediction']}")
                
                print(f"📊 Risk Score: {analysis['risk_score']}/100")
                print(f"🎯 Confidence: {analysis['confidence']:.2f}")
                
                # Color-code risk level
                if analysis["risk_level"] == "HIGH":
                    print(f"⚠️  Risk Level: {analysis['risk_level']}")
                elif analysis["risk_level"] == "MEDIUM":
                    print(f"⚡ Risk Level: {analysis['risk_level']}")
                else:
                    print(f"✅ Risk Level: {analysis['risk_level']}")
                print(f"{'='*60}")
                    
            except KeyboardInterrupt:
                print("\n\n👋 Goodbye!")
                break
            except Exception as e:
                print(f"❌ Error: {e}")
                
    except FileNotFoundError as e:
        print(f"\n❌ Error: {e}")
        print("Please ensure dataset.csv is in the same directory as this script.")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()