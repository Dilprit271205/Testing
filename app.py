import os
import sys
import time
import math
import threading
import psutil
import pandas as pd
import streamlit as st

# Page Configuration
st.set_page_config(
    page_title="Dynamic Self-Healing EDR",
    page_icon="🛡️",
    layout="wide"
)

# ==========================================
# 1. LIGHTWEIGHT RUNNING STATS (Welford's Algorithm)
# ==========================================
class RunningStats:
    """
    Computes running mean and standard deviation with O(1) memory and compute.
    Protects system performance under heavy process loads.
    """
    def __init__(self, initial_mean: float, initial_std: float):
        # We start with a virtual count of 20 to seed the baseline with Slide values
        self.count = 20
        self.mean = initial_mean
        # M2 = variance * (count - 1)
        self.M2 = (initial_std ** 2) * (self.count - 1)

    def update(self, x: float):
        """Updates the running mean and variance online using Welford's logic."""
        self.count += 1
        delta = x - self.mean
        self.mean += delta / self.count
        delta2 = x - self.mean
        self.M2 += delta * delta2

    @property
    def variance(self) -> float:
        return self.M2 / (self.count - 1) if self.count > 1 else 0.0

    @property
    def std(self) -> float:
        return math.sqrt(self.variance)


# ==========================================
# 2. THREAD-SAFE STATE STORAGE
# ==========================================
@st.cache_resource
class SystemStateStore:
    def __init__(self):
        self.lock = threading.Lock()
        self.active_processes = {}  # pid: { metrics }
        self.alerts = []            # list of dicts (logs)
        
        # Dynamic baselines scoped by Process Name
        # process_name: { feature_name: RunningStats }
        self.learned_baselines = {}
        
        # Control Switches
        self.lock_baselines = False  # If True, stops learning and enforces frozen state
        
        # Default Configurations (Adjustable via UI)
        self.weight_static = 0.3
        self.weight_dynamic = 0.7
        self.alpha = 0.7
        self.k_factor = 2.0
        self.th_normal = 0.7
        self.th_suspicious = 0.4    
        self.sleep_interval = 2.0

    def update_configs(self, ws, wd, alpha, k, th_norm, th_susp, interval, lock_b):
        with self.lock:
            self.weight_static = ws
            self.weight_dynamic = wd
            self.alpha = alpha
            self.k_factor = k
            self.th_normal = th_norm
            self.th_suspicious = th_susp
            self.sleep_interval = interval
            self.lock_baselines = lock_b

    def add_alert(self, pid, name, status, trust, details):
        with self.lock:
            if self.alerts and self.alerts[-1]["PID"] == pid and self.alerts[-1]["Status"] == status:
                self.alerts[-1]["Timestamp"] = time.strftime("%H:%M:%S")
                return
            self.alerts.append({
                "Timestamp": time.strftime("%H:%M:%S"),
                "PID": pid,
                "Process Name": name,
                "Status": status,
                "Trust Score": round(trust, 2),
                "Action Taken": details
            })
            if len(self.alerts) > 50:
                self.alerts.pop(0)

state_store = SystemStateStore()

# ==========================================
# 3. KERNEL & SYSTEM PROTECTION
# ==========================================
def is_whitelisted(proc: psutil.Process) -> bool:
    try:
        pid = proc.pid
        ppid = proc.ppid()
        name = proc.name().lower()
        
        if pid <= 150 or ppid == 2:
            return True
        if not proc.cmdline():
            return True
            
        current_pid = os.getpid()
        if pid == current_pid or ppid == current_pid:
            return True

        essential_services = {
            "systemd", "init", "sshd", "dbus-daemon", "udevd", "journald",
            "login", "bash", "sh", "zsh", "tmux", "cron", "rsyslogd", 
            "polkitd", "networkmanager", "dockerd", "containerd",
            "xorg", "gnome-shell", "gdm", "lightdm", "pulseaudio", "pipewire",
            "sudo", "systemd-journal", "systemd-resolved", "systemd-timesyn"
        }
        if name in essential_services:
            return True

    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return True
    return False

# ==========================================
# 4. MATHEMATICAL ALIGNMENT (Slides 21-24)
# ==========================================
class FrameworkEvaluator:
    @staticmethod
    def calculate_static_trust(proc: psutil.Process) -> float:
        try:
            exe_path = proc.exe()
            file_name = proc.name()
            file_size_bytes = os.path.getsize(exe_path) if os.path.exists(exe_path) else 1024 * 1024
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return 0.5

        # Location Score
        location_score = 0.2
        if any(exe_path.startswith(p) for p in ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/lib"]):
            location_score = 1.0
        elif any(exe_path.startswith(p) for p in ["/opt", "/usr/local"]):
            location_score = 0.8
        elif exe_path.startswith("/home"):
            location_score = 0.6
        elif any(exe_path.startswith(p) for p in ["/tmp", "/var/tmp", "/dev/shm"]):
            location_score = 0.3

        # Name Score
        name_score = 0.8
        if location_score < 0.8 and any(sys_name in file_name.lower() for sys_name in ["sys", "kern", "systemd", "daemon"]):
            name_score = 0.2
        elif any(char.isalnum() for char in file_name):
            name_score = 0.8
        else:
            name_score = 0.4

        # Size Score
        size_mb = file_size_bytes / (1024 * 1024)
        if 1.0 <= size_mb <= 200.0:
            size_score = 0.8
        elif 0.2 <= size_mb < 1.0 or size_mb > 200.0:
            size_score = 0.6
        elif size_mb < 0.2:
            size_score = 0.5
        else:
            size_score = 0.3

        return round((location_score + name_score + size_score) / 3.0, 2)

    @staticmethod
    def get_or_create_baselines(proc_name: str, store: SystemStateStore) -> dict:
        """Retrieves or registers a new process profile, seeded with Slide 23 defaults."""
        with store.lock:
            if proc_name not in store.learned_baselines:
                store.learned_baselines[proc_name] = {
                    "cpu_percent": RunningStats(20.0, 5.0),
                    "memory_mb":   RunningStats(200.0, 50.0),
                    "threads":     RunningStats(10.0, 3.0),
                    "connections": RunningStats(5.0, 2.0),
                    "file_ops":    RunningStats(1.0, 1.0)
                }
            return store.learned_baselines[proc_name]

    @classmethod
    def calculate_dynamic_trust(cls, proc: psutil.Process, prev_vector: list, store: SystemStateStore) -> tuple:
        proc_name = proc.name()
        baselines = cls.get_or_create_baselines(proc_name, store)

        try:
            cpu = proc.cpu_percent(interval=None)
            mem_mb = proc.memory_info().rss / (1024 * 1024)
            threads = proc.num_threads()
            
            # Optimized expensive I/O calls
            connections = 0
            file_ops = 0
            if cpu > 40.0 or mem_mb > 300.0:
                try:
                    connections = len(proc.connections())
                    file_ops = len(proc.open_files())
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return 0.5, prev_vector

        telemetry = {
            "cpu_percent": cpu,
            "memory_mb": mem_mb,
            "threads": threads,
            "connections": connections,
            "file_ops": file_ops
        }

        # Dynamically update the learned process profile if baseline is UNLOCKED
        if not store.lock_baselines:
            with store.lock:
                for feat in telemetry:
                    baselines[feat].update(telemetry[feat])

        new_vector = []
        features = ["cpu_percent", "memory_mb", "threads", "connections", "file_ops"]
        
        for idx, feat in enumerate(features):
            val = telemetry[feat]
            
            # Retrieve currently learned running mean and standard deviation
            mu = baselines[feat].mean
            sigma = max(baselines[feat].std, 0.001)
            
            # Unidirectional Anomaly Check
            if val > mu:
                A = min(1.0, (val - mu) / (store.k_factor * sigma))
            else:
                A = 0.0
                
            raw_trust = 1.0 - A
            
            # EMA Smoothing (Slide 24)
            prev_t = prev_vector[idx]
            new_t = (store.alpha * prev_t) + ((1.0 - store.alpha) * raw_trust)
            new_vector.append(new_t)

        Td = sum(new_vector) / len(new_vector)
        return Td, new_vector

# ==========================================
# 5. OPTIMIZED DAEMON THREAD
# ==========================================
def run_healing_daemon(store: SystemStateStore):
    process_cache = {}

    while True:
        current_pids = set()
        active_snapshot = {}

        for proc_info in psutil.process_iter(['pid', 'name']):
            try:
                pid = proc_info.info['pid']
                name = proc_info.info['name']
                current_pids.add(pid)

                if pid not in process_cache:
                    proc_obj = psutil.Process(pid)
                    if is_whitelisted(proc_obj):
                        continue
                    ts = FrameworkEvaluator.calculate_static_trust(proc_obj)
                    process_cache[pid] = {
                        "proc_obj": proc_obj,
                        "static_trust": ts,
                        "prev_vector": [1.0, 1.0, 1.0, 1.0, 1.0]
                    }
                else:
                    proc_obj = process_cache[pid]["proc_obj"]

                cache_entry = process_cache[pid]
                ts = cache_entry["static_trust"]

                # Calculates trust score against currently learned running profile
                td, new_vector = FrameworkEvaluator.calculate_dynamic_trust(
                    proc_obj, cache_entry["prev_vector"], store
                )
                process_cache[pid]["prev_vector"] = new_vector

                t_final = (store.weight_static * ts) + (store.weight_dynamic * td)

                if t_final <= store.th_suspicious:
                    status = "CRITICAL"
                elif store.th_suspicious < t_final <= store.th_normal:
                    status = "SUSPICIOUS"
                else:
                    status = "NORMAL"

                action_taken = "Monitoring"
                if status == "CRITICAL":
                    action_taken = "TERMINATED (Adaptive Healing)"
                    store.add_alert(pid, name, "CRITICAL", t_final, "Forcefully Terminated (Adaptive Healing)")
                    try:
                        for child in proc_obj.children(recursive=True):
                            child.kill()
                        proc_obj.kill()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                elif status == "SUSPICIOUS":
                    try:
                        if proc_obj.nice() != 19:
                            proc_obj.nice(19)
                            action_taken = "THROTTLED (Innate Healing - Nice 19)"
                            store.add_alert(pid, name, "SUSPICIOUS", t_final, "Throttled CPU priority to Nice 19")
                        else:
                            action_taken = "Throttled (Nice 19)"
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                else:
                    try:
                        if proc_obj.nice() == 19:
                            proc_obj.nice(0)
                            action_taken = "RESTORED (Trust Recovery)"
                            store.add_alert(pid, name, "NORMAL", t_final, "Restored standard CPU priority")
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                active_snapshot[pid] = {
                    "PID": pid,
                    "Name": name,
                    "Static Trust (Ts)": round(ts, 2),
                    "Dynamic Trust (Td)": round(td, 2),
                    "Final Trust T(p,t)": round(t_final, 2),
                    "Status": status,
                    "Action/State": action_taken
                }

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        dead_pids = set(process_cache.keys()) - current_pids
        for dp in dead_pids:
            del process_cache[dp]

        with store.lock:
            store.active_processes = active_snapshot

        time.sleep(store.sleep_interval)

@st.cache_resource
def start_background_thread():
    daemon_thread = threading.Thread(target=run_healing_daemon, args=(state_store,), daemon=True)
    daemon_thread.start()
    return True

start_background_thread()

# ==========================================
# 6. STREAMLIT FRONTEND DASHBOARD
# ==========================================
st.title("🛡️ Dynamic Self-Healing EDR Dashboard")
st.markdown("A lightweight autonomous system featuring **Dynamic Baseline Profiling via Welford's Algorithm**.")

# SIDEBAR: Configuration Panel
st.sidebar.header("⚙️ Framework Configurations")

# Defense Toggle (Prevent baseline poisoning)
lock_baselines = st.sidebar.checkbox("🔒 Lock Learned Baselines (Enforcement Mode)", value=state_store.lock_baselines)

ws = st.sidebar.slider("Static Weight ($w_s$)", 0.0, 1.0, state_store.weight_static, 0.05)
wd = 1.0 - ws
st.sidebar.info(f"Dynamic Weight ($w_d$): {wd:.2f}")

alpha = st.sidebar.slider("EMA Smoothing Factor ($\\alpha$)", 0.0, 1.0, state_store.alpha, 0.05)
k = st.sidebar.slider("Anomaly Scaling Factor ($k$)", 1.0, 5.0, state_store.k_factor, 0.5)
th_norm = st.sidebar.slider("Normal Threshold ($\\theta_{innate}$)", 0.5, 0.9, state_store.th_normal, 0.05)
th_susp = st.sidebar.slider("Critical Threshold ($\\theta_{adaptive}$)", 0.2, 0.6, state_store.th_suspicious, 0.05)
polling_speed = st.sidebar.slider("Daemon Loop Speed (seconds)", 1.0, 10.0, state_store.sleep_interval, 0.5)

state_store.update_configs(ws, wd, alpha, k, th_norm, th_susp, polling_speed, lock_baselines)

# Dynamic profiling state indicator
if lock_baselines:
    st.sidebar.success("🛡️ Baselines are Locked. Running in strict ENFORCEMENT mode.")
else:
    st.sidebar.warning("📊 Profiling Active. Running in continuous LEARNING mode.")

# MAIN UI: Top Metrics Row
with state_store.lock:
    proc_data = list(state_store.active_processes.values())
    alerts_data = list(state_store.alerts)
    learned_profiles = list(state_store.learned_baselines.keys())

df_proc = pd.DataFrame(proc_data)

total_monitored = len(df_proc) if not df_proc.empty else 0
suspicious_count = len(df_proc[df_proc["Status"] == "SUSPICIOUS"]) if not df_proc.empty else 0
critical_count = sum(1 for a in alerts_data if a["Status"] == "CRITICAL")

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Monitored Processes", total_monitored)
col2.metric("Suspicious (Throttled)", suspicious_count, delta_color="inverse")
col3.metric("Critical Terminations", critical_count, delta_color="inverse")
col4.metric("Known Behavioral Profiles", len(learned_profiles))

# INTERACTIVE VIEW: Inspect Learned Baselines
st.subheader("🔍 Inspect Learned Behavioral Profiles (Dynamic Baselines)")
if learned_profiles:
    selected_name = st.selectbox("Select a registered process name to view its dynamically learned mean ($\mu$) and standard deviation ($\sigma$):", sorted(learned_profiles))
    
    with state_store.lock:
        profile = state_store.learned_baselines[selected_name]
        
    p_data = []
    for feat in profile:
        p_data.append({
            "Metric": feat,
            "Learned Mean (\u03bc)": round(profile[feat].mean, 2),
            "Learned Std Dev (\u03c3)": round(profile[feat].std, 2),
            "Observations Tracked": profile[feat].count - 20 # Subtract our warm-start seeds
        })
    st.table(pd.DataFrame(p_data))
else:
    st.info("Profiles will appear here once the daemon observes system execution.")

# MAIN UI: Real-Time Alerts
st.subheader("🚨 Live Security Alerts")
if alerts_data:
    df_alerts = pd.DataFrame(alerts_data).iloc[::-1]
    
    def color_alerts(row):
        if row["Status"] == "CRITICAL":
            return ['background-color: #ffcccc; color: black'] * len(row)
        elif row["Status"] == "SUSPICIOUS":
            return ['background-color: #fff2cc; color: black'] * len(row)
        return [''] * len(row)
        
    st.dataframe(
        df_alerts.style.apply(color_alerts, axis=1),
        use_container_width=True,
        hide_index=True
    )
else:
    st.info("No suspicious or critical anomalies have been detected yet.")

# MAIN UI: Process Table
st.subheader("📊 Active Evaluated Processes")

if not df_proc.empty:
    def color_status(val):
        if val == "SUSPICIOUS":
            return "background-color: #fff2cc; color: black; font-weight: bold;"
        elif val == "CRITICAL":
            return "background-color: #ffcccc; color: black; font-weight: bold;"
        return "color: green;"

    st.dataframe(
        df_proc.style.map(color_status, subset=["Status"]),
        use_container_width=True,
        hide_index=True,
        column_order=["PID", "Name", "Static Trust (Ts)", "Dynamic Trust (Td)", "Final Trust T(p,t)", "Status", "Action/State"]
    )
else:
    st.warning("No user-space processes are currently undergoing active evaluation.")

time.sleep(3.0)
st.rerun()
