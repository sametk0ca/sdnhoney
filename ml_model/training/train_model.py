import numpy as np
import pandas as pd
import pickle
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib

# Eğitim dizini oluştur
MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'models')
os.makedirs(MODEL_DIR, exist_ok=True)

def create_synthetic_data(n_samples=1000):
    """Sentetik veri üret. Gerçek uygulamada, gerçek ağ trafiği verileri kullanılmalıdır."""
    np.random.seed(42)
    
    # Özellikler
    src_ip = np.random.randint(0, 255, size=(n_samples, 4))
    dst_ip = np.random.randint(0, 255, size=(n_samples, 4))
    src_port = np.random.randint(1, 65535, size=n_samples)
    dst_port = np.random.randint(1, 65535, size=n_samples)
    
    # Veriyi birleştir
    X = np.column_stack([
        src_ip, 
        dst_ip,
        src_port, 
        dst_port,
        # protocol dummy değişkenler (TCP=1, UDP=2, ICMP=3, vb.)
        np.random.randint(1, 4, size=n_samples)
    ])
    
    # Hedef değişkeni (0=normal, 1=şüpheli)
    # Şüpheli olması için bazı kurallar belirleyelim:
    # - Eğer hedef port 22 ise (SSH) ve kaynak adresi bilinen değilse
    # - Eğer hedef port 3389 ise (RDP)
    # - Eğer port taraması olduğunu gösterebilecek çok sayıda bağlantı varsa (10000'den büyük portlar)
    
    y = np.zeros(n_samples)
    
    for i in range(n_samples):
        # SSH ve kaynak 10.x.x.x harici
        if dst_port[i] == 22 and src_ip[i, 0] != 10:
            y[i] = 1
        # RDP portu
        elif dst_port[i] == 3389:
            y[i] = 1
        # Yüksek port numaraları (port taraması)
        elif dst_port[i] > 10000 and dst_port[i] < 11000:
            y[i] = 1
        # Belirli aralıklarda tehlikeli olabilecek trafiği işaretle
        elif dst_port[i] in [445, 139, 135]:  # SMB, NetBIOS
            y[i] = 1
            
        # Yüzde 5 ihtimalle rastgele etiketleme (gerçek ağlardaki gürültülü veri için)
        if np.random.random() < 0.05:
            y[i] = 1 - y[i]  # Sınıfı tersine çevir
    
    # Veriyi DataFrame'e dönüştür
    column_names = [
        'src_ip1', 'src_ip2', 'src_ip3', 'src_ip4',
        'dst_ip1', 'dst_ip2', 'dst_ip3', 'dst_ip4',
        'src_port', 'dst_port', 'protocol'
    ]
    df = pd.DataFrame(X, columns=column_names)
    df['label'] = y
    
    return df

def train_model(data):
    """Modeli eğit ve kaydet"""
    # X ve y ayır
    X = data.drop('label', axis=1)
    y = data['label']
    
    # Eğitim ve test veri setlerine ayır
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Özellikleri ölçeklendir
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Modeli eğit
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train_scaled, y_train)
    
    # Test tahminleri
    y_pred = model.predict(X_test_scaled)
    
    # Değerlendirme
    accuracy = accuracy_score(y_test, y_pred)
    conf_matrix = confusion_matrix(y_test, y_pred)
    report = classification_report(y_test, y_pred)
    
    print(f"Doğruluk: {accuracy:.4f}")
    print(f"Karmaşıklık Matrisi:\n{conf_matrix}")
    print(f"Sınıflandırma Raporu:\n{report}")
    
    # Modeli ve ölçekleyiciyi kaydet
    joblib.dump(model, os.path.join(MODEL_DIR, 'rf_model.joblib'))
    joblib.dump(scaler, os.path.join(MODEL_DIR, 'scaler.joblib'))
    
    return model, scaler

if __name__ == "__main__":
    print("Sentetik veri oluşturuluyor...")
    data = create_synthetic_data(n_samples=10000)
    
    print("Model eğitiliyor...")
    model, scaler = train_model(data)
    
    print(f"Model kaydedildi: {os.path.join(MODEL_DIR, 'rf_model.joblib')}")
    print(f"Scaler kaydedildi: {os.path.join(MODEL_DIR, 'scaler.joblib')}") 