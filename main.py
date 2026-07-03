from dotenv import load_dotenv
load_dotenv()

import os
import cv2
import numpy as np
import firebase_admin
from firebase_admin import credentials, firestore
from insightface.app import FaceAnalysis
from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import bcrypt
from google.cloud import storage as gcs
import functions_framework
import traceback
import time
from datetime import datetime

app = Flask(__name__)

# Initialize Firebase Admin
cred = credentials.Certificate(os.environ['GOOGLE_APPLICATION_CREDENTIALS'])
firebase_admin.initialize_app(cred)
db = firestore.client()
bucket = gcs.Client().bucket(os.environ['FIREBASE_STORAGE_BUCKET'])

# Initialize InsightFace model
app_face = FaceAnalysis(name='buffalo_l')
app_face.prepare(ctx_id=0, det_size=(640, 640))

# AES key for PIN encryption/decryption
AES_KEY = bytes.fromhex(os.environ['AES_KEY'])

# Thresholds and parameters for continuous learning
THRESHOLD_HIGH = 0.75          # High confidence unlock
THRESHOLD_MEDIUM_HIGH = 0.70   # Medium-high for optional storage
THRESHOLD_MEDIUM = 0.60        # Minimum for unlock
THRESHOLD_REMOVAL = 0.65       # Remove if below this (no longer useful)
MAX_ADAPTIVE_EMBEDDINGS = 5    # Maximum adaptive embeddings per user
EMBEDDING_SIMILARITY_THRESHOLD = 0.08  # Min distance to avoid storing duplicates

# Temporal Decay Parameters
TEMPORAL_DECAY_HALF_LIFE = 90  # Days for embedding to decay to 50% weight
TEMPORAL_DECAY_MIN_WEIGHT = 0.3  # Minimum weight even for very old embeddings

def decrypt_data(encrypted_data):
    try:
        cipher = AES.new(AES_KEY, AES.MODE_ECB)
        decrypted = unpad(cipher.decrypt(encrypted_data), 16)
        return decrypted
    except Exception:
        print("PIN decryption failed:")
        print(traceback.format_exc())
        return None

def get_embedding(image_bytes):
    try:
        nparr = np.frombuffer(image_bytes, np.uint8)
        image = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        if image is None:
            print("cv2.imdecode failed: image is None")
            return None
        faces = app_face.get(image)
        print(f"Number of faces detected: {len(faces)}")
        if len(faces) == 0:
            return None
        return faces[0].embedding.tolist()
    except Exception:
        print("Exception in get_embedding:")
        print(traceback.format_exc())
        return None

def calculate_embedding_distance(emb1, emb2):
    """Calculate Euclidean distance between two embeddings"""
    emb1_np = np.array(emb1)
    emb2_np = np.array(emb2)
    return np.linalg.norm(emb1_np - emb2_np)

def calculate_similarity(emb1, emb2):
    """Calculate cosine similarity between two embeddings"""
    emb1_np = np.array(emb1)
    emb2_np = np.array(emb2)
    return np.dot(emb1_np, emb2_np) / (np.linalg.norm(emb1_np) * np.linalg.norm(emb2_np))

def is_embedding_duplicate(new_embedding, existing_embeddings):
    """
    Check if new embedding is too similar to existing ones (to avoid duplicates)
    Returns True if similar to any existing embedding
    """
    for existing_emb in existing_embeddings:
        distance = calculate_embedding_distance(new_embedding, existing_emb)
        if distance < EMBEDDING_SIMILARITY_THRESHOLD:
            print(f"Embedding too similar to existing (distance: {distance:.4f}), skipping storage")
            return True
    return False

def calculate_temporal_decay_weight(timestamp_unix):
    """
    Calculate weight for an embedding based on its age (temporal decay)
    Uses exponential decay with configurable half-life
    
    Returns: weight between TEMPORAL_DECAY_MIN_WEIGHT and 1.0
    """
    current_time = int(time.time())
    age_seconds = current_time - timestamp_unix
    age_days = age_seconds / (24 * 3600)
    
    # Exponential decay: weight = 2^(-age / half_life)
    decay_weight = 2 ** (-age_days / TEMPORAL_DECAY_HALF_LIFE)
    
    # Clamp to minimum weight
    weight = max(decay_weight, TEMPORAL_DECAY_MIN_WEIGHT)
    
    print(f"Temporal decay: age={age_days:.1f} days, weight={weight:.4f}")
    return weight

def cleanup_adaptive_embeddings(user_data):
    """
    Remove low-confidence or stale adaptive embeddings
    Applies temporal decay weighting
    Returns updated user_data
    """
    # Collect core embeddings (image1-image5)
    core_embeddings = {}
    adaptive_embeddings = {}
    
    for key in user_data:
        if key in ['image1', 'image2', 'image3', 'image4', 'image5']:
            core_embeddings[key] = user_data[key]
        elif key.startswith('adaptive_'):
            adaptive_embeddings[key] = user_data[key]
    
    # Calculate weighted similarity for each adaptive embedding (with temporal decay)
    adaptive_scores = {}
    for key, adaptive_emb_record in adaptive_embeddings.items():
        adaptive_emb = adaptive_emb_record['embedding']
        timestamp = adaptive_emb_record.get('timestamp', int(time.time()))
        
        # Calculate temporal decay weight
        decay_weight = calculate_temporal_decay_weight(timestamp)
        
        # Calculate best match similarity
        scores = []
        for core_emb in core_embeddings.values():
            sim = calculate_similarity(adaptive_emb, core_emb)
            scores.append(sim)
        
        base_score = max(scores) if scores else 0
        weighted_score = base_score * decay_weight
        
        adaptive_scores[key] = {
            'base_score': base_score,
            'decay_weight': decay_weight,
            'weighted_score': weighted_score
        }
    
    # Remove embeddings with low weighted similarity
    embeddings_to_remove = []
    for key, scores in adaptive_scores.items():
        if scores['weighted_score'] < THRESHOLD_REMOVAL:
            print(f"Removing adaptive embedding {key} "
                  f"(weighted similarity {scores['weighted_score']:.4f} < {THRESHOLD_REMOVAL})")
            embeddings_to_remove.append(key)
    
    # If still over limit, remove oldest
    remaining_adaptive = [k for k in adaptive_embeddings if k not in embeddings_to_remove]
    if len(remaining_adaptive) >= MAX_ADAPTIVE_EMBEDDINGS:
        sorted_adaptive = sorted(
            remaining_adaptive,
            key=lambda k: adaptive_embeddings[k].get('timestamp', 0)
        )
        num_to_remove = len(remaining_adaptive) - MAX_ADAPTIVE_EMBEDDINGS + 1
        for i in range(num_to_remove):
            embeddings_to_remove.append(sorted_adaptive[i])
            print(f"Removing oldest adaptive embedding: {sorted_adaptive[i]}")
    
    # Rebuild user_data without removed embeddings
    updated_data = {k: v for k, v in user_data.items() if k not in embeddings_to_remove}
    return updated_data

def update_adaptive_embeddings(user_id, new_embedding, similarity_score):
    """
    Add new embedding to user's adaptive embeddings if conditions are met
    """
    try:
        user_ref = db.collection('users').document(user_id)
        user_data = user_ref.get().to_dict()
        
        # Collect core embeddings
        core_embeddings = [user_data[k] for k in ['image1', 'image2', 'image3', 'image4', 'image5']]
        
        # Check if embedding is duplicate
        if is_embedding_duplicate(new_embedding, core_embeddings):
            return
        
        # Collect adaptive embeddings
        adaptive_embeddings = []
        for key in sorted(user_data.keys()):
            if key.startswith('adaptive_'):
                adaptive_embeddings.append(user_data[key]['embedding'])
        
        # Check if duplicate among adaptive embeddings too
        if is_embedding_duplicate(new_embedding, adaptive_embeddings):
            return
        
        # Create adaptive embedding record
        current_timestamp = int(time.time())
        adaptive_key = f"adaptive_{current_timestamp}"
        
        user_data[adaptive_key] = {
            'embedding': new_embedding,
            'timestamp': current_timestamp,
            'similarity': similarity_score,
            'date_added': datetime.now().isoformat()
        }
        
        # Cleanup to maintain max limit
        user_data = cleanup_adaptive_embeddings(user_data)
        user_data['timestamp'] = firestore.SERVER_TIMESTAMP
        
        # Update Firestore
        user_ref.set(user_data)
        print(f"Added adaptive embedding for {user_id}, similarity: {similarity_score:.4f}")
    except Exception as e:
        print(f"Error updating adaptive embeddings for {user_id}:")
        print(traceback.format_exc())

@app.route('/register', methods=['POST'])
def register():
    try:
        user_id = request.form['user_id']
        embeddings_dict = {}
        for i in range(1, 6):
            image_key = f'image{i}'
            if image_key not in request.files:
                print(f"Missing {image_key}")
                return jsonify({'error': f'Missing image {image_key}'}), 400
            image_file = request.files[image_key]
            image_bytes = image_file.read()
            embedding = get_embedding(image_bytes)
            if embedding is None:
                print(f"No face detected in {image_key}")
                return jsonify({'error': f'No face detected in image {image_key}'}), 400
            embeddings_dict[image_key] = embedding
        embeddings_dict['timestamp'] = firestore.SERVER_TIMESTAMP
        db.collection('users').document(user_id).set(embeddings_dict)
        print("Successfully registered face images for user:", user_id)
        return jsonify({'status': 'Face registered', 'user_id': user_id}), 200
    except Exception as e:
        print("Exception in /register:")
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

@app.route('/unlock', methods=['POST'])
def unlock():
    try:
        image_bytes = request.data
        embedding = get_embedding(image_bytes)
        if embedding is None:
            print("No face in unlock image")
            return jsonify({'status': 'NO_FACE'}), 400
        
        embedding_np = np.array(embedding)
        users = db.collection('users').stream()
        
        best_match_user = None
        best_similarity = 0.0
        best_match_type = None  # 'core' or 'adaptive'
        best_weighted_similarity = 0.0  # With temporal decay
        
        for user in users:
            user_data = user.to_dict()
            
            # Check core embeddings (image1-image5)
            for key in ['image1', 'image2', 'image3', 'image4', 'image5']:
                if key not in user_data:
                    continue
                stored_emb = np.array(user_data[key])
                similarity = np.dot(embedding_np, stored_emb) / (
                    np.linalg.norm(embedding_np) * np.linalg.norm(stored_emb)
                )
                if similarity > best_similarity:
                    best_similarity = similarity
                    best_match_user = user
                    best_match_type = 'core'
                    best_weighted_similarity = similarity  # Core embeddings have no decay
            
            # Check adaptive embeddings with temporal decay
            for key in sorted(user_data.keys()):
                if key.startswith('adaptive_'):
                    adaptive_record = user_data[key]
                    stored_emb = np.array(adaptive_record['embedding'])
                    timestamp = adaptive_record.get('timestamp', int(time.time()))
                    
                    # Calculate similarity
                    similarity = np.dot(embedding_np, stored_emb) / (
                        np.linalg.norm(embedding_np) * np.linalg.norm(stored_emb)
                    )
                    
                    # Apply temporal decay
                    decay_weight = calculate_temporal_decay_weight(timestamp)
                    weighted_similarity = similarity * decay_weight
                    
                    if weighted_similarity > best_weighted_similarity:
                        best_similarity = similarity
                        best_weighted_similarity = weighted_similarity
                        best_match_user = user
                        best_match_type = 'adaptive'
        
        # Decision logic based on confidence thresholds
        if best_weighted_similarity >= THRESHOLD_HIGH:
            # High confidence - UNLOCK
            user_id = best_match_user.id
            timestamp = int(time.time())
            blob = bucket.blob(f'logs/{user_id}/{timestamp}.jpg')
            blob.upload_from_string(image_bytes, content_type='image/jpeg')
            image_url = blob.public_url
            db.collection('logs').add({
                'user_id': user_id,
                'timestamp': firestore.SERVER_TIMESTAMP,
                'image_url': image_url,
                'similarity': best_similarity,
                'weighted_similarity': best_weighted_similarity,
                'match_type': best_match_type
            })
            print(f"HIGH confidence unlock for {user_id} ({best_match_type}), "
                  f"similarity: {best_similarity:.4f}, weighted: {best_weighted_similarity:.4f}")
            return jsonify({
                'status': 'UNLOCK',
                'similarity': best_similarity,
                'weighted_similarity': best_weighted_similarity,
                'confidence': 'HIGH'
            }), 200
        
        elif THRESHOLD_MEDIUM_HIGH <= best_weighted_similarity < THRESHOLD_HIGH:
            # Medium-high confidence - UNLOCK + STORE ADAPTIVE
            user_id = best_match_user.id
            timestamp = int(time.time())
            blob = bucket.blob(f'logs/{user_id}/{timestamp}.jpg')
            blob.upload_from_string(image_bytes, content_type='image/jpeg')
            image_url = blob.public_url
            db.collection('logs').add({
                'user_id': user_id,
                'timestamp': firestore.SERVER_TIMESTAMP,
                'image_url': image_url,
                'similarity': best_similarity,
                'weighted_similarity': best_weighted_similarity,
                'match_type': best_match_type
            })
            # Store adaptive embedding
            update_adaptive_embeddings(user_id, embedding, best_similarity)
            print(f"MEDIUM-HIGH confidence unlock for {user_id}, "
                  f"similarity: {best_similarity:.4f}, storing adaptive")
            return jsonify({
                'status': 'UNLOCK',
                'similarity': best_similarity,
                'weighted_similarity': best_weighted_similarity,
                'confidence': 'MEDIUM-HIGH'
            }), 200
        
        elif THRESHOLD_MEDIUM <= best_weighted_similarity < THRESHOLD_MEDIUM_HIGH:
            # Medium confidence - UNLOCK + STORE ADAPTIVE
            user_id = best_match_user.id
            timestamp = int(time.time())
            blob = bucket.blob(f'logs/{user_id}/{timestamp}.jpg')
            blob.upload_from_string(image_bytes, content_type='image/jpeg')
            image_url = blob.public_url
            db.collection('logs').add({
                'user_id': user_id,
                'timestamp': firestore.SERVER_TIMESTAMP,
                'image_url': image_url,
                'similarity': best_similarity,
                'weighted_similarity': best_weighted_similarity,
                'match_type': best_match_type
            })
            # Store adaptive embedding
            update_adaptive_embeddings(user_id, embedding, best_similarity)
            print(f"MEDIUM confidence unlock for {user_id}, "
                  f"similarity: {best_similarity:.4f}, storing adaptive")
            return jsonify({
                'status': 'UNLOCK',
                'similarity': best_similarity,
                'weighted_similarity': best_weighted_similarity,
                'confidence': 'MEDIUM'
            }), 200
        
        else:
            # Low confidence - NO MATCH
            print(f"No match found (best weighted similarity: {best_weighted_similarity:.4f})")
            return jsonify({
                'status': 'NO_MATCH',
                'similarity': best_similarity,
                'weighted_similarity': best_weighted_similarity
            }), 200
    
    except Exception as e:
        print("Exception in /unlock:")
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

@app.route('/set_pin', methods=['POST'])
def set_pin():
    try:
        encrypted_pin = request.data
        pin = decrypt_data(encrypted_pin)
        pin = pin.decode('utf-8') if pin else ""
        if not pin.isdigit() or len(pin) != 6:
            print("Invalid PIN format")
            return jsonify({'error': 'PIN must be 6 digits'}), 400
        hashed_pin = bcrypt.hashpw(pin.encode('utf-8'), bcrypt.gensalt())
        db.collection('pins').document('current_pin').set({
            'hash': hashed_pin.decode('utf-8'),
            'timestamp': firestore.SERVER_TIMESTAMP
        })
        print("PIN set successfully")
        return jsonify({'status': 'PIN set'}), 200
    except Exception as e:
        print("Exception in /set_pin:")
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

@app.route('/pin_unlock', methods=['POST'])
def pin_unlock():
    try:
        encrypted_pin = request.data
        pin = decrypt_data(encrypted_pin)
        pin = pin.decode('utf-8') if pin else ""
        stored_pin = db.collection('pins').document('current_pin').get()
        if stored_pin.exists:
            hashed_pin = stored_pin.to_dict()['hash'].encode('utf-8')
            if bcrypt.checkpw(pin.encode('utf-8'), hashed_pin):
                db.collection('logs').add({
                    'user_id': 'pin_unlock',
                    'timestamp': firestore.SERVER_TIMESTAMP,
                    'image_url': ''
                })
                print("PIN unlock success")
                return jsonify({'status': 'UNLOCK'}), 200
        print("Invalid PIN")
        return jsonify({'status': 'INVALID_PIN'}), 400
    except Exception as e:
        print("Exception in /pin_unlock:")
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

@app.route('/get_user_embeddings', methods=['GET'])
def get_user_embeddings():
    """
    Get embedding info for a user (debugging/monitoring)
    Query: ?user_id=person1
    """
    try:
        user_id = request.args.get('user_id')
        if not user_id:
            return jsonify({'error': 'user_id required'}), 400
        
        user_ref = db.collection('users').document(user_id)
        user_data = user_ref.get().to_dict()
        
        if not user_data:
            return jsonify({'error': 'User not found'}), 404
        
        # Summary of embeddings with temporal decay info
        summary = {
            'user_id': user_id,
            'core_embeddings': 5,
            'adaptive_embeddings': sum(1 for k in user_data if k.startswith('adaptive_')),
            'adaptive_details': []
        }
        
        for key in sorted(user_data.keys()):
            if key.startswith('adaptive_'):
                timestamp = user_data[key].get('timestamp', int(time.time()))
                decay_weight = calculate_temporal_decay_weight(timestamp)
                summary['adaptive_details'].append({
                    'key': key,
                    'similarity': user_data[key].get('similarity'),
                    'date_added': user_data[key].get('date_added'),
                    'temporal_decay_weight': decay_weight
                })
        
        return jsonify(summary), 200
    except Exception as e:
        print("Exception in /get_user_embeddings:")
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

@app.route('/system_config', methods=['GET'])
def system_config():
    """
    Return current system configuration for debugging
    """
    config = {
        'thresholds': {
            'HIGH': THRESHOLD_HIGH,
            'MEDIUM_HIGH': THRESHOLD_MEDIUM_HIGH,
            'MEDIUM': THRESHOLD_MEDIUM,
            'REMOVAL': THRESHOLD_REMOVAL
        },
        'temporal_decay': {
            'half_life_days': TEMPORAL_DECAY_HALF_LIFE,
            'min_weight': TEMPORAL_DECAY_MIN_WEIGHT
        },
        'adaptive_embeddings': {
            'max_per_user': MAX_ADAPTIVE_EMBEDDINGS,
            'similarity_threshold': EMBEDDING_SIMILARITY_THRESHOLD
        }
    }
    return jsonify(config), 200

# Functions Framework Entrypoint
@functions_framework.http
def main(request):
    return app(request.environ, lambda status, headers: None)
