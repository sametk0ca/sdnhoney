#!/usr/bin/env python3
import numpy as np
import pandas as pd
import pickle
import os
import time
import logging
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report
from sklearn.model_selection import GridSearchCV

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('../logs/ml_training.log'),
        logging.StreamHandler()
    ]
)

def load_data():
    """Load the dataset from pickle files"""
    logging.info("Loading dataset...")
    
    try:
        with open('models/X_train.pkl', 'rb') as f:
            X_train = pickle.load(f)
        
        with open('models/X_test.pkl', 'rb') as f:
            X_test = pickle.load(f)
        
        with open('models/y_train.pkl', 'rb') as f:
            y_train = pickle.load(f)
        
        with open('models/y_test.pkl', 'rb') as f:
            y_test = pickle.load(f)
        
        logging.info(f"Loaded dataset with {X_train.shape[0]} training samples and {X_test.shape[0]} test samples")
        return X_train, X_test, y_train, y_test
    
    except FileNotFoundError:
        logging.error("Dataset files not found. Please run generate_dataset.py first.")
        return None, None, None, None

def train_model(X_train, y_train, hyperparameter_tuning=False):
    """Train a RandomForest model on the training data"""
    logging.info("Training model...")
    
    if hyperparameter_tuning:
        logging.info("Performing hyperparameter tuning...")
        # Define parameter grid
        param_grid = {
            'n_estimators': [50, 100, 200],
            'max_depth': [None, 10, 20, 30],
            'min_samples_split': [2, 5, 10],
            'min_samples_leaf': [1, 2, 4]
        }
        
        # Create GridSearchCV object
        model = GridSearchCV(
            RandomForestClassifier(random_state=42),
            param_grid,
            cv=3,
            scoring='f1',
            n_jobs=-1
        )
        
        # Fit model
        model.fit(X_train, y_train)
        
        # Get best parameters
        logging.info(f"Best parameters: {model.best_params_}")
        
        # Use best model
        model = model.best_estimator_
    else:
        # Use default parameters
        model = RandomForestClassifier(
            n_estimators=100, 
            max_depth=None,
            min_samples_split=2,
            min_samples_leaf=1,
            random_state=42
        )
        model.fit(X_train, y_train)
    
    return model

def evaluate_model(model, X_test, y_test):
    """Evaluate the trained model on the test data"""
    logging.info("Evaluating model...")
    
    # Make predictions
    y_pred = model.predict(X_test)
    
    # Calculate metrics
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    
    logging.info(f"Model performance:")
    logging.info(f"Accuracy:  {accuracy:.4f}")
    logging.info(f"Precision: {precision:.4f}")
    logging.info(f"Recall:    {recall:.4f}")
    logging.info(f"F1-Score:  {f1:.4f}")
    
    # Display detailed classification report
    report = classification_report(y_test, y_pred)
    logging.info(f"Classification Report:\n{report}")
    
    # Feature importance
    feature_importance = pd.DataFrame({
        'Feature': X_test.columns,
        'Importance': model.feature_importances_
    }).sort_values('Importance', ascending=False)
    
    logging.info(f"Feature Importance:\n{feature_importance}")
    
    return accuracy, precision, recall, f1

def save_model(model):
    """Save the trained model to disk"""
    logging.info("Saving model...")
    
    with open('models/ml_model.pkl', 'wb') as f:
        pickle.dump(model, f)
    
    logging.info("Model saved to models/ml_model.pkl")

if __name__ == '__main__':
    # Check if dataset exists, otherwise generate it
    if not os.path.exists('models/X_train.pkl'):
        logging.info("Dataset not found, generating it first...")
        import generate_dataset
        generate_dataset.main()
    
    # Load data
    X_train, X_test, y_train, y_test = load_data()
    
    if X_train is None:
        logging.error("Failed to load dataset. Exiting.")
        exit(1)
    
    # Train model
    start_time = time.time()
    model = train_model(X_train, y_train, hyperparameter_tuning=False)
    training_time = time.time() - start_time
    logging.info(f"Model training completed in {training_time:.2f} seconds")
    
    # Evaluate model
    evaluate_model(model, X_test, y_test)
    
    # Save model
    save_model(model)
    
    logging.info("Model training and evaluation complete!") 