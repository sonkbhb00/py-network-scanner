import threading
from queue import Queue

def threaded_port_scan(target_ip, ports, scan_func, max_threads=50, progress_callback=None):
    
    results = []
    results_lock = threading.Lock()
    scanned = 0
    scanned_lock = threading.Lock()
    port_queue = Queue()
    
    for port in ports:
        port_queue.put(port)
    
    def worker():
        nonlocal scanned
        while True:
            try:
                port = port_queue.get(timeout=0.1)
            except:
                break
            
            result = scan_func(target_ip, port)
            
            if result is not None:
                with results_lock:
                    results.append(result)
            
            with scanned_lock:
                scanned += 1
                if progress_callback:
                    progress_callback(len(ports), scanned)
            
            port_queue.task_done()
    
    threads = []
    num_threads = min(max_threads, len(ports))
    
    for _ in range(num_threads):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        threads.append(t)
    
    port_queue.join()
    
    return sorted(results)