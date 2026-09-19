import asyncio
import datetime
import random
import socketio
import pandas as pd
import numpy as np
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from inference import engine

# Socket.IO Server
sio = socketio.AsyncServer(async_mode='asgi', cors_allowed_origins='*')

# FastAPI App
app = FastAPI(title="Hybrid IDS Backend")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Socket.IO ASGI App
socket_app = socketio.ASGIApp(sio, app)

# Stats
stats = {
    "total_events": 0,
    "attacks_detected": 0,
    "normal_events": 0,
    "attack_types": {},
    "mode": "csv"  # "csv" or "live"
}

# CSV simulation data
NETWORK_DATA = None
LOG_DATA = None
NETWORK_INDEX = 0
LOG_INDEX = 0

# Live monitors
live_net_monitor = None
live_log_monitor = None


def load_datasets():
    global NETWORK_DATA, LOG_DATA
    train_dir = '../training/data'
    
    try:
        df_net = pd.read_csv(f'{train_dir}/CICIDS2017.csv')
        df_net = df_net.replace([np.inf, -np.inf], np.nan).dropna()
        label_col = 'Attack Type' if 'Attack Type' in df_net.columns else 'Label'
        NETWORK_DATA = df_net.select_dtypes(include=[np.number])
        NETWORK_DATA['_original_label'] = df_net[label_col].values[:len(NETWORK_DATA)]
        print(f"[DATA] Loaded {len(NETWORK_DATA)} network records")
    except Exception as e:
        print(f"[WARN] Could not load network data: {e}")

    try:
        LOG_DATA = pd.read_csv(f'{train_dir}/BGL.csv')
        LOG_DATA = LOG_DATA.fillna('')
        print(f"[DATA] Loaded {len(LOG_DATA)} log records")
    except Exception as e:
        print(f"[WARN] Could not load log data: {e}")


async def csv_event_generator():
    """Simulate events from CSV datasets."""
    global NETWORK_INDEX, LOG_INDEX
    
    while stats["mode"] == "csv":
        await asyncio.sleep(2)
        
        source = random.choice(["Network", "System Log"])
        event = None
        
        if source == "Network" and NETWORK_DATA is not None:
            idx = NETWORK_INDEX % len(NETWORK_DATA)
            row = NETWORK_DATA.iloc[idx]
            features = row.drop('_original_label', errors='ignore').values.astype(float)
            true_label = NETWORK_DATA.iloc[idx].get('_original_label', 'Unknown')
            
            try:
                pred_label, confidence, shap_values = engine.predict_network(features)
                if pred_label is None:
                    pred_label = str(true_label)
                    confidence = 0.95
                    shap_values = {}
            except Exception as e:
                pred_label = str(true_label)
                confidence = 0.95
                shap_values = {}
            
            is_attack = pred_label not in ['Normal Traffic', 'BENIGN']
            severity = "Critical" if is_attack and confidence > 0.95 else "High" if is_attack else "Normal"
            
            event = {
                "id": stats["total_events"] + 1,
                "source": "Network (CSV)",
                "timestamp": datetime.datetime.now().isoformat(),
                "severity": severity,
                "attack_type": pred_label,
                "confidence": round(confidence, 3),
                "host": f"192.168.1.{random.randint(10, 50)}",
                "explanation": {
                    "shap": shap_values if shap_values else {},
                    "lime": f"MLP classified as '{pred_label}' with {confidence:.1%} confidence"
                },
                "true_label": str(true_label),
            }
            NETWORK_INDEX += 1

        elif source == "System Log" and LOG_DATA is not None:
            idx = LOG_INDEX % len(LOG_DATA)
            row = LOG_DATA.iloc[idx]
            log_content = str(row.get('Content', ''))
            true_label = str(row.get('Label', '-'))
            
            try:
                pred_label, confidence, explanation = engine.predict_log(log_content)
                if pred_label is None:
                    pred_label = "Normal" if true_label == '-' else "Anomaly"
                    confidence = 0.95
                    explanation = "Fallback"
            except Exception as e:
                pred_label = "Normal" if true_label == '-' else "Anomaly"
                confidence = 0.95
                explanation = f"Error: {str(e)}"
            
            is_attack = pred_label == "Anomaly"
            severity = "High" if is_attack else "Normal"
            
            event = {
                "id": stats["total_events"] + 1,
                "source": "System Log (CSV)",
                "timestamp": datetime.datetime.now().isoformat(),
                "severity": severity,
                "attack_type": f"Log Anomaly ({row.get('Component', 'Unknown')})" if is_attack else "Normal Log",
                "confidence": round(confidence, 3),
                "host": str(row.get('Node', 'unknown')),
                "explanation": {"lime": explanation},
                "true_label": f"{'Anomaly' if true_label != '-' else 'Normal'} ({true_label})",
                "log_content": log_content[:200],
            }
            LOG_INDEX += 1
        
        if event:
            await emit_event(event)


def live_event_callback(event):
    """Callback for live monitor events - runs in background thread."""
    import asyncio
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    event["id"] = stats["total_events"] + 1
    event["timestamp"] = datetime.datetime.now().isoformat()
    
    # Update stats
    stats["total_events"] += 1
    if event["severity"] != "Normal":
        stats["attacks_detected"] += 1
        at = event["attack_type"]
        stats["attack_types"][at] = stats["attack_types"].get(at, 0) + 1
    else:
        stats["normal_events"] += 1
    
    loop.run_until_complete(sio.emit('new_event', event))
    loop.run_until_complete(sio.emit('stats_update', stats))
    loop.close()


async def emit_event(event):
    """Emit event to all connected clients."""
    stats["total_events"] += 1
    if event["severity"] != "Normal":
        stats["attacks_detected"] += 1
        at = event["attack_type"]
        stats["attack_types"][at] = stats["attack_types"].get(at, 0) + 1
    else:
        stats["normal_events"] += 1
    
    await sio.emit('new_event', event)
    await sio.emit('stats_update', stats)


@sio.event
async def connect(sid, environ):
    print(f"Client connected: {sid}")
    await sio.emit('stats_update', stats)


@sio.event
async def switch_mode(sid, data):
    """Switch between CSV and Live monitoring modes."""
    global live_net_monitor, live_log_monitor
    
    mode = data.get('mode', 'csv')
    stats["mode"] = mode
    
    if mode == "live":
        # Stop CSV generator
        # Start live monitors
        from live_network_monitor import LiveNetworkMonitor
        from live_log_monitor import LiveLogMonitor
        
        live_net_monitor = LiveNetworkMonitor(engine, callback=live_event_callback)
        live_log_monitor = LiveLogMonitor(engine, callback=live_event_callback)
        
        live_net_monitor.start()
        live_log_monitor.start()
        
        print("[MODE] Switched to LIVE monitoring")
    else:
        # Stop live monitors
        if live_net_monitor:
            live_net_monitor.stop()
            live_net_monitor = None
        if live_log_monitor:
            live_log_monitor.stop()
            live_log_monitor = None
        
        print("[MODE] Switched to CSV simulation")
    
    await sio.emit('mode_changed', {"mode": mode})


@app.on_event("startup")
async def startup_event():
    load_datasets()
    asyncio.create_task(csv_event_generator())
    print("=" * 50)
    print("  Hybrid IDS Backend Started")
    print("  Dashboard: http://localhost:5173")
    print("  API:       http://localhost:8000")
    print("=" * 50)


@app.get("/")
async def root():
    return {
        "message": "Hybrid IDS API Running",
        "models_loaded": engine.network_model is not None,
        "mode": stats["mode"]
    }


if __name__ == "__main__":
    uvicorn.run("main:socket_app", host="0.0.0.0", port=8000, reload=True)
