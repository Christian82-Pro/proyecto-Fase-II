from fastapi import FastAPI
import pandas as pd
import joblib

# Crear la aplicación
app = FastAPI()

# Cargar modelo y columnas
modelo = joblib.load("modelo_red.pkl")
columnas = joblib.load("columnas.pkl")

@app.get("/")
def home():
    return {"mensaje": "API de detección de ataques de red activa"}

@app.get("/estado")
def estado():
    return {
        "estado": "activo",
        "modelo": "Random Forest",
        "total_columnas": len(columnas)
    }

@app.post("/predict")
def predict(
    duracion_flujo: float = 1000,
    paquetes_adelante: float = 10,
    paquetes_atras: float = 5,
    longitud_adelante: float = 500,
    longitud_atras: float = 300
):
    # Crear entrada básica
    datos = {
        "Flow Duration": duracion_flujo,
        "Total Fwd Packets": paquetes_adelante,
        "Total Backward Packets": paquetes_atras,
        "Total Length of Fwd Packets": longitud_adelante,
        "Total Length of Bwd Packets": longitud_atras
    }

    # Convertir a dataframe
    entrada = pd.DataFrame([datos])

    # Ajustar columnas al modelo
    entrada = entrada.reindex(columns=columnas, fill_value=0)

    # Realizar predicción
    prediccion = modelo.predict(entrada)[0]
    probabilidad = modelo.predict_proba(entrada)[0][1]

    # Interpretar resultado
    resultado = "Ataque detectado" if prediccion == 1 else "Tráfico benigno"

    return {
        "prediccion": int(prediccion),
        "resultado": resultado,
        "probabilidad_ataque": round(float(probabilidad), 4)
    }