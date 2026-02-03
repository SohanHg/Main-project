from flask import Flask, request, jsonify
from flask_cors import CORS
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import pickle
import os
import logging
from datetime import datetime

# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('apk_detector.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ============================================================================
# FLASK APP INITIALIZATION
# ============================================================================
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# ============================================================================
# GLOBAL VARIABLES
# ============================================================================
model = None
feature_columns = []
model_metadata = {}
whitelist = set()

# File paths
MODEL_PATH = 'rf_model.pkl'
FEATURES_PATH = 'features.pkl'
METADATA_PATH = 'metadata.pkl'
WHITELIST_PATH = 'whitelist.pkl'

# Expected features from frontend (MUST MATCH FRONTEND ORDER) - ALL 58 FEATURES
EXPECTED_FEATURES = [
    # === PERMISSION FEATURES (10) ===
    'dangerous_permissions_count',
    'total_permissions_count',
    'internet_permission',
    'sms_permission',
    'phone_permission',
    'location_permission',
    'camera_permission',
    'microphone_permission',
    'contacts_permission',
    'storage_permission',
    
    # === CODE COMPLEXITY FEATURES (7) ===
    'obfuscation_high',
    'entropy',
    'dex_files_count',
    'native_code',
    'native_libs_count',
    'estimated_methods_count',
    'reflection_usage',
    
    # === FILE ANALYSIS FEATURES (4) ===
    'suspicious_files_ratio',
    'large_file',
    'total_files_count',
    'has_resources',
    
    # === CERTIFICATE FEATURES (3) ===
    'is_self_signed',
    'debug_certificate',
    'certificates_count',
    
    # === MANIFEST FEATURES (5) ===
    'min_sdk_version',
    'target_sdk_version',
    'exported_activities_count',
    'services_count',
    'receivers_count',
    
    # === NETWORK BEHAVIOR FEATURES (6) ===
    'outbound_connections',
    'suspicious_domains',
    'data_exfiltration',
    'http_requests_count',
    'https_requests_count',
    'dns_queries_count',
    
    # === FILE OPERATIONS FEATURES (5) ===
    'files_created',
    'files_deleted',
    'files_modified',
    'system_file_access',
    'external_storage_access',
    
    # === SYSTEM CALLS FEATURES (4) ===
    'privileged_calls',
    'process_creation',
    'service_interactions',
    'broadcast_intents',
    
    # === RUNTIME BEHAVIOR FEATURES (6) ===
    'root_escalation',
    'anti_analysis',
    'dynamic_loading',
    'debugger_detection',
    'emulator_detection',
    'crypto_usage',
    
    # === COMMUNICATION FEATURES (5) ===
    'sms_operations',
    'phone_calls',
    'location_requests',
    'camera_usage',
    'microphone_usage',
    
    # === STRING ANALYSIS FEATURES (3) ===
    'suspicious_strings_count',
    'urls_found',
    'ip_addresses_found'
]

# Total: 58 features

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def load_whitelist():
    """Load whitelist from disk"""
    global whitelist
    try:
        if os.path.exists(WHITELIST_PATH):
            with open(WHITELIST_PATH, 'rb') as f:
                whitelist = pickle.load(f)
            logger.info(f"✓ Whitelist loaded: {len(whitelist)} entries")
    except Exception as e:
        logger.error(f"✗ Error loading whitelist: {str(e)}")


def save_whitelist():
    """Save whitelist to disk"""
    try:
        with open(WHITELIST_PATH, 'wb') as f:
            pickle.dump(whitelist, f)
        logger.info(f"✓ Whitelist saved: {len(whitelist)} entries")
    except Exception as e:
        logger.error(f"✗ Error saving whitelist: {str(e)}")


def load_saved_model():
    """Load previously saved model"""
    global model, feature_columns, model_metadata
    
    try:
        if os.path.exists(MODEL_PATH) and os.path.exists(FEATURES_PATH):
            with open(MODEL_PATH, 'rb') as f:
                model = pickle.load(f)
            with open(FEATURES_PATH, 'rb') as f:
                feature_columns = pickle.load(f)
            
            if os.path.exists(METADATA_PATH):
                with open(METADATA_PATH, 'rb') as f:
                    model_metadata = pickle.load(f)
            
            logger.info(f"✓ Model loaded with {len(feature_columns)} features")
            return True
    except Exception as e:
        logger.error(f"✗ Error loading model: {str(e)}")
    
    return False


def save_model_files():
    """Save trained model"""
    try:
        with open(MODEL_PATH, 'wb') as f:
            pickle.dump(model, f)
        with open(FEATURES_PATH, 'wb') as f:
            pickle.dump(feature_columns, f)
        with open(METADATA_PATH, 'wb') as f:
            pickle.dump(model_metadata, f)
        
        logger.info("✓ Model saved successfully")
        return True
    except Exception as e:
        logger.error(f"✗ Error saving model: {str(e)}")
        return False


def normalize_csv_features(df):
    """
    Normalize CSV features to match frontend normalization (0-1 range)
    This ensures training data matches prediction data format.
    
    CRITICAL: This aligns the RAW data from 'android_malware_research_dataset_v2.csv'
    with the 0-1 values sent by the React frontend.
    """
    df_norm = df.copy()
    
    # Normalize count-based features (PERMISSION)
    if 'dangerous_permissions_count' in df_norm.columns:
        df_norm['dangerous_permissions_count'] = np.clip(df_norm['dangerous_permissions_count'] / 20.0, 0, 1)
    
    if 'total_permissions_count' in df_norm.columns:
        df_norm['total_permissions_count'] = np.clip(df_norm['total_permissions_count'] / 50.0, 0, 1)
    
    # Normalize CODE COMPLEXITY features
    if 'entropy' in df_norm.columns:
        df_norm['entropy'] = np.clip(df_norm['entropy'] / 8.0, 0, 1)
    
    if 'dex_files_count' in df_norm.columns:
        df_norm['dex_files_count'] = np.clip(df_norm['dex_files_count'] / 5.0, 0, 1)
    
    if 'native_libs_count' in df_norm.columns:
        df_norm['native_libs_count'] = np.clip(df_norm['native_libs_count'] / 10.0, 0, 1)
    
    if 'estimated_methods_count' in df_norm.columns:
        df_norm['estimated_methods_count'] = np.clip(df_norm['estimated_methods_count'] / 50000.0, 0, 1)
    
    # Normalize FILE ANALYSIS features
    if 'suspicious_files_ratio' in df_norm.columns:
        df_norm['suspicious_files_ratio'] = np.clip(df_norm['suspicious_files_ratio'] / 10.0, 0, 1)
    
    if 'total_files_count' in df_norm.columns:
        df_norm['total_files_count'] = np.clip(df_norm['total_files_count'] / 1000.0, 0, 1)
    
    # Normalize CERTIFICATE features
    if 'certificates_count' in df_norm.columns:
        df_norm['certificates_count'] = np.clip(df_norm['certificates_count'] / 3.0, 0, 1)
    
    # Normalize MANIFEST features
    if 'min_sdk_version' in df_norm.columns:
        df_norm['min_sdk_version'] = np.clip(df_norm['min_sdk_version'] / 30.0, 0, 1)
    
    if 'target_sdk_version' in df_norm.columns:
        df_norm['target_sdk_version'] = np.clip(df_norm['target_sdk_version'] / 34.0, 0, 1)
    
    if 'exported_activities_count' in df_norm.columns:
        df_norm['exported_activities_count'] = np.clip(df_norm['exported_activities_count'] / 10.0, 0, 1)
    
    if 'services_count' in df_norm.columns:
        df_norm['services_count'] = np.clip(df_norm['services_count'] / 15.0, 0, 1)
    
    if 'receivers_count' in df_norm.columns:
        df_norm['receivers_count'] = np.clip(df_norm['receivers_count'] / 10.0, 0, 1)
    
    # Normalize NETWORK BEHAVIOR features
    if 'outbound_connections' in df_norm.columns:
        df_norm['outbound_connections'] = np.clip(df_norm['outbound_connections'] / 30.0, 0, 1)
    
    if 'suspicious_domains' in df_norm.columns:
        df_norm['suspicious_domains'] = np.clip(df_norm['suspicious_domains'] / 5.0, 0, 1)
    
    if 'http_requests_count' in df_norm.columns:
        df_norm['http_requests_count'] = np.clip(df_norm['http_requests_count'] / 100.0, 0, 1)
    
    if 'https_requests_count' in df_norm.columns:
        df_norm['https_requests_count'] = np.clip(df_norm['https_requests_count'] / 50.0, 0, 1)
    
    if 'dns_queries_count' in df_norm.columns:
        df_norm['dns_queries_count'] = np.clip(df_norm['dns_queries_count'] / 50.0, 0, 1)
    
    # Normalize FILE OPERATIONS features
    if 'files_created' in df_norm.columns:
        df_norm['files_created'] = np.clip(df_norm['files_created'] / 30.0, 0, 1)
    
    if 'files_deleted' in df_norm.columns:
        df_norm['files_deleted'] = np.clip(df_norm['files_deleted'] / 10.0, 0, 1)
    
    if 'files_modified' in df_norm.columns:
        df_norm['files_modified'] = np.clip(df_norm['files_modified'] / 20.0, 0, 1)
    
    # Normalize SYSTEM CALLS features
    if 'privileged_calls' in df_norm.columns:
        df_norm['privileged_calls'] = np.clip(df_norm['privileged_calls'] / 100.0, 0, 1)
    
    if 'process_creation' in df_norm.columns:
        df_norm['process_creation'] = np.clip(df_norm['process_creation'] / 10.0, 0, 1)
    
    if 'service_interactions' in df_norm.columns:
        df_norm['service_interactions'] = np.clip(df_norm['service_interactions'] / 20.0, 0, 1)
    
    if 'broadcast_intents' in df_norm.columns:
        df_norm['broadcast_intents'] = np.clip(df_norm['broadcast_intents'] / 30.0, 0, 1)
    
    # Normalize RUNTIME BEHAVIOR features
    if 'anti_analysis' in df_norm.columns:
        df_norm['anti_analysis'] = np.clip(df_norm['anti_analysis'] / 5.0, 0, 1)
    
    # Normalize COMMUNICATION features
    if 'sms_operations' in df_norm.columns:
        df_norm['sms_operations'] = np.clip(df_norm['sms_operations'] / 10.0, 0, 1)
    
    if 'phone_calls' in df_norm.columns:
        df_norm['phone_calls'] = np.clip(df_norm['phone_calls'] / 5.0, 0, 1)
    
    if 'location_requests' in df_norm.columns:
        df_norm['location_requests'] = np.clip(df_norm['location_requests'] / 20.0, 0, 1)
    
    # Normalize STRING ANALYSIS features
    if 'suspicious_strings_count' in df_norm.columns:
        df_norm['suspicious_strings_count'] = np.clip(df_norm['suspicious_strings_count'] / 20.0, 0, 1)
    
    if 'urls_found' in df_norm.columns:
        df_norm['urls_found'] = np.clip(df_norm['urls_found'] / 30.0, 0, 1)
    
    if 'ip_addresses_found' in df_norm.columns:
        df_norm['ip_addresses_found'] = np.clip(df_norm['ip_addresses_found'] / 5.0, 0, 1)
    
    # Ensure binary features are 0 or 1
    binary_features = [
        'internet_permission', 'sms_permission', 'phone_permission',
        'location_permission', 'camera_permission', 'microphone_permission',
        'contacts_permission', 'storage_permission',
        'obfuscation_high', 'native_code', 'reflection_usage',
        'large_file', 'has_resources',
        'is_self_signed', 'debug_certificate',
        'data_exfiltration',
        'system_file_access', 'external_storage_access',
        'root_escalation', 'dynamic_loading', 'debugger_detection',
        'emulator_detection', 'crypto_usage',
        'camera_usage', 'microphone_usage'
    ]
    
    for feat in binary_features:
        if feat in df_norm.columns:
            # Force valid binary logic (greater than 0 is 1, else 0)
            df_norm[feat] = df_norm[feat].apply(lambda x: 1 if x > 0 else 0)
    
    return df_norm


# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.route('/', methods=['GET'])
def home():
    """API information"""
    return jsonify({
        'name': 'APK Malware Detection API',
        'version': '4.2.0',
        'status': 'running',
        'model_trained': model is not None,
        'features_expected': len(EXPECTED_FEATURES),
        'feature_count': 58,
        'whitelist_entries': len(whitelist),
        'endpoints': {
            '/': 'GET - API info',
            '/health': 'GET - Health check',
            '/train': 'POST - Train model with CSV',
            '/predict': 'POST - Predict malware',
            '/model-info': 'GET - Model details',
            '/whitelist': 'GET - View whitelist',
            '/whitelist/add': 'POST - Add to whitelist',
            '/whitelist/remove': 'POST - Remove from whitelist'
        }
    }), 200


@app.route('/health', methods=['GET'])
def health():
    """Health check"""
    return jsonify({
        'status': 'running',
        'model_trained': model is not None,
        'features': feature_columns if model else EXPECTED_FEATURES,
        'feature_count': len(feature_columns) if model else 58,
        'metadata': model_metadata
    }), 200

@app.route('/api/data', methods=['GET'])
def api_data():
    """
    Frontend ↔ Backend connection test endpoint
    """
    return jsonify({
        'message': 'Flask backend connected successfully',
        'status': 'success',
        'model_loaded': model is not None,
        'features_expected': len(EXPECTED_FEATURES),
        'timestamp': datetime.now().isoformat()
    }), 200


@app.route('/model-info', methods=['GET'])
def model_info():
    """Get model information"""
    if model is None:
        return jsonify({'error': 'No model trained'}), 404
    
    return jsonify({
        'model_trained': True,
        'model_type': 'Random Forest Classifier',
        'n_estimators': 100,
        'features': feature_columns,
        'n_features': len(feature_columns),
        'metadata': model_metadata
    }), 200


# ============================================================================
# WHITELIST ENDPOINTS
# ============================================================================

@app.route('/whitelist', methods=['GET'])
def get_whitelist():
    """Get all whitelisted identifiers"""
    return jsonify({
        'whitelist': list(whitelist),
        'count': len(whitelist)
    }), 200


@app.route('/whitelist/add', methods=['POST'])
def add_to_whitelist():
    """Add to whitelist"""
    try:
        data = request.get_json()
        identifier = str(data.get('identifier', '')).strip()
        
        if not identifier:
            return jsonify({'error': 'No identifier provided'}), 400
        
        whitelist.add(identifier)
        save_whitelist()
        
        return jsonify({
            'message': 'Added to whitelist',
            'identifier': identifier,
            'count': len(whitelist)
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/whitelist/remove', methods=['POST'])
def remove_from_whitelist():
    """Remove from whitelist"""
    try:
        data = request.get_json()
        identifier = str(data.get('identifier', '')).strip().lower()
        
        if not identifier:
            return jsonify({'error': 'No identifier provided'}), 400
        
        if identifier in whitelist:
            whitelist.remove(identifier)
            save_whitelist()
            return jsonify({
                'message': 'Removed from whitelist',
                'identifier': identifier,
                'count': len(whitelist)
            }), 200
        else:
            return jsonify({'error': 'Identifier not in whitelist'}), 404
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/whitelist/check', methods=['POST'])
def check_whitelist():
    """Check if in whitelist"""
    try:
        data = request.get_json()
        identifier = str(data.get('identifier', '')).strip()
        
        return jsonify({
            'identifier': identifier,
            'whitelisted': identifier in whitelist
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================================
# TRAINING ENDPOINT
# ============================================================================

@app.route('/train', methods=['POST'])
def train_model():
    """
    Train Random Forest model with CSV dataset
    
    CSV MUST have columns matching EXPECTED_FEATURES (58 features) + 'label' column
    """
    global model, feature_columns, model_metadata
    
    try:
        logger.info("=" * 70)
        logger.info("TRAINING STARTED (58 FEATURES)")
        logger.info("=" * 70)
        
        # Validate file upload
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Load CSV
        df = pd.read_csv(file)
        logger.info(f"✓ Dataset loaded: {df.shape[0]} rows, {df.shape[1]} columns")
        
        # Find label column
        label_col = None
        for col in ['label', 'classification', 'class', 'target', 'malware', 'Class']:
            if col in df.columns:
                label_col = col
                break
        
        if label_col is None:
            return jsonify({
                'error': 'No label column found. Must have: label, classification, class, or target',
                'columns': list(df.columns)
            }), 400
        
        logger.info(f"✓ Label column: '{label_col}'")
        
        # Extract labels
        y = df[label_col].copy()
        
        # Convert labels to binary (1=malware, 0=benign)
        def label_to_binary(val):
            val_str = str(val).upper().strip()
            if val_str in ['MALWARE', 'MALICIOUS', '1', 'TRUE', 'YES']:
                return 1
            elif val_str in ['BENIGN', 'CLEAN', 'SAFE', '0', 'FALSE', 'NO']:
                return 0
            else:
                try:
                    return 1 if float(val) >= 0.5 else 0
                except:
                    return 0
        
        y_binary = y.apply(label_to_binary)
        
        # Extract features
        X = df.drop(columns=[label_col])
        
        # Filter out identifier/whitelist_flag/etc columns from CSV
        # Only keep numeric columns
        non_numeric = X.select_dtypes(exclude=[np.number]).columns
        if len(non_numeric) > 0:
            logger.info(f"✓ Dropping non-numeric columns (like identifiers): {list(non_numeric)}")
            X = X.select_dtypes(include=[np.number])
        
        # Filter out numeric columns that are NOT in expected features (e.g. whitelist_flag)
        available_features = [f for f in EXPECTED_FEATURES if f in X.columns]
        
        if len(available_features) < 10:
            return jsonify({
                'error': f'Need at least 30 expected features. Found {len(available_features)}',
                'expected': EXPECTED_FEATURES,
                'found': list(X.columns),
                'available': available_features
            }), 400
        
        # Use only available expected features
        X = X[available_features]
        feature_columns = available_features
        
        logger.info(f"✓ Using {len(feature_columns)} features")
        
        # CRITICAL: Normalize features to 0-1 range (matching frontend)
        X = normalize_csv_features(X)
        
        # Handle missing values
        X = X.fillna(0)
        X = X.replace([np.inf, -np.inf], 0)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y_binary, test_size=0.2, random_state=42, stratify=y_binary
        )
        
        logger.info(f"✓ Train: {len(X_train)} samples, Test: {len(X_test)} samples")
        
        # Train Random Forest (NO SCALING - data already normalized)
        logger.info("✓ Training Random Forest (100 trees)...")
        
        model = RandomForestClassifier(
            n_estimators=100,
            max_depth=15,
            min_samples_split=10,
            min_samples_leaf=5,
            max_features='sqrt',
            random_state=42,
            class_weight='balanced',
            n_jobs=-1
        )
        
        model.fit(X_train, y_train)
        logger.info("✓ Training complete")
        
        # Evaluate
        y_train_pred = model.predict(X_train)
        y_test_pred = model.predict(X_test)
        
        train_acc = accuracy_score(y_train, y_train_pred)
        test_acc = accuracy_score(y_test, y_test_pred)
        precision = precision_score(y_test, y_test_pred, zero_division=0)
        recall = recall_score(y_test, y_test_pred, zero_division=0)
        f1 = f1_score(y_test, y_test_pred, zero_division=0)
        cm = confusion_matrix(y_test, y_test_pred)
        
        # Get feature importance
        feature_importance = dict(zip(feature_columns, model.feature_importances_))
        top_features = sorted(feature_importance.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Store metadata
        model_metadata = {
            'train_accuracy': float(train_acc),
            'test_accuracy': float(test_acc),
            'precision': float(precision),
            'recall': float(recall),
            'f1_score': float(f1),
            'n_samples': len(df),
            'n_features': len(feature_columns),
            'features': feature_columns,
            'train_date': datetime.now().isoformat(),
        }
        
        # Save model
        save_model_files()
        
        return jsonify({
            'message': f'Model trained successfully with {len(feature_columns)} features',
            'train_accuracy': float(train_acc),
            'test_accuracy': float(test_acc),
            'precision': float(precision),
            'recall': float(recall),
            'f1_score': float(f1),
            'confusion_matrix': cm.tolist(),
            'features': feature_columns,
            'top_features': [{'name': k, 'importance': float(v)} for k, v in top_features]
        }), 200
        
    except Exception as e:
        logger.error(f"✗ Training error: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return jsonify({'error': str(e)}), 500


# ============================================================================
# PREDICTION ENDPOINT (MODIFIED FOR ALWAYS-RUN)
# ============================================================================

@app.route('/predict', methods=['POST'])
def predict():
    """
    Predict malware classification
    
    CHANGES:
    - ALWAYS runs Random Forest model (even if whitelisted)
    - Returns 'whitelisted': True if applicable
    - Returns 'skip_ml_analysis': False (Always)
    - Frontend handles the final override based on 'whitelisted' flag
    """
    global model, feature_columns

    try:
        logger.info("=" * 70)
        logger.info("🔍 PREDICTION REQUEST")
        logger.info("=" * 70)

        # Get request data
        data = request.get_json()
        if not data or 'features' not in data:
            return jsonify({'error': 'No features provided'}), 400

        # Extract identifier or filename
        identifier = str(data.get('identifier', '')).strip().lower()
        
        # Extract category if provided
        category = str(data.get('category', '')).strip().upper()

        # Check whitelist status (BUT DO NOT RETURN EARLY)
        is_whitelisted = identifier in whitelist
        is_dev_category = category == 'DEVELOPMENT_TESTING'
        
        if is_whitelisted:
            logger.info(f"🟢 Whitelisted identifier detected: {identifier} (Proceeding with ML anyway)")
        
        if is_dev_category:
            logger.info(f"🟢 DEVELOPMENT_TESTING category detected (Proceeding with ML anyway)")

        # Prepare features
        features = data['features']

        # Convert dict input to list if needed
        if isinstance(features, dict):
            features = [features.get(f, 0) for f in EXPECTED_FEATURES]

        if len(features) != len(EXPECTED_FEATURES):
            return jsonify({
                'error': f'Invalid feature count: expected {len(EXPECTED_FEATURES)}, got {len(features)}'
            }), 400

        # Ensure model is loaded
        if model is None:
            if not load_saved_model():
                return jsonify({'error': 'No trained model found'}), 500

        # Run Random Forest Model
        X_input = np.array(features).reshape(1, -1)
        prediction = model.predict(X_input)[0]
        probability = model.predict_proba(X_input)[0][1]

        # Construct result
        # NOTE: We set 'skip_ml_analysis' to False so frontend ALWAYS shows the graph
        result = {
            'whitelisted': is_whitelisted or is_dev_category,
            'skip_ml_analysis': False,
            'prediction': 'MALWARE' if prediction == 1 else 'CLEAN',
            'probability': float(probability),
            'isMalware': bool(prediction == 1),
            'confidence': round(abs(probability - 0.5) * 2, 3),
            'algorithm': 'Random Forest (58 features)',
            'identifier': identifier,
            'category': category if category else 'N/A'
        }

        logger.info(f"✓ Prediction: {result['prediction']} (prob={probability:.4f})")

        return jsonify(result), 200

    except Exception as e:
        logger.error(f"✗ Prediction error: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return jsonify({'error': str(e)}), 500


# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    print("\n" + "=" * 75)
    print("🛡️  APK MALWARE DETECTION BACKEND v4.2.0 (ALWAYS RUN ML)")
    print("=" * 75)
    # ... (rest of main block same as before)
    
    # Load saved model and whitelist
    load_saved_model()
    load_whitelist()
    
    # Start server
    app.run(host='0.0.0.0', port=5000, debug=True)