import threading
import time
import json
import subprocess
import os

def callback(new_line):
        
	try:
		data = json.loads(new_line)	
	except json.JSONDecodeError as e:
		print(f"Error decoding JSON: {e}")
        
	container_id = data.get("output_fields", {}).get("container.id")
	container_name = data.get("output_fields", {}).get("container.name")
	if not container_name:
		container_name = "undefined"
	container_port = data.get("output_fields", {}).get("fd.sport")
	container_time = data.get("time")
	
	print(container_time + " " + container_name + " " + str(container_port))
	
	# Get container IP
	command = "docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' " + container_id
	container_ip = subprocess.run(command, shell=True, capture_output=True).stdout.decode('utf-8').strip()
	
	# Run nmap
	filename = "report/nmap_reports/" + container_time + "_" + container_name + "_" + str(container_port) + ".txt"
	nmap_out = subprocess.run(f"nmap --script ssl-enum-ciphers {container_ip} -p {container_port}", shell=True, capture_output=True).stdout.decode('utf-8').strip()   

	with open(filename, 'w') as file:
		file.write(nmap_out)
    
    
def monitor(file_path):

	with open(file_path, 'r') as file:
		# Move to the end of the file
		file.seek(0, 2)

		while True:
			lines = file.readlines()  # Read all available new lines
			if lines:
				for line in lines:
				    # Spawn a thread for each new line
				    thread = threading.Thread(target=callback, args=(line.strip(),))
				    thread.start()
				    
			time.sleep(0.1)  # Small delay to avoid busy waiting


if __name__ == "__main__":

	file_path = "report/openport.txt"
	print(f"Observing file {file_path}")

	# Create report folder
	if not os.path.exists("report/nmap_reports"):
		os.makedirs("report/nmap_reports")
	    
	# Start the monitoring in a separate thread
	monitor_thread = threading.Thread(target=monitor, args=(file_path,), daemon=True)
	monitor_thread.start()

	# Keep the main thread alive
	try:
		while True:
		    time.sleep(1)
	except KeyboardInterrupt:
		print("\nStopped observing")
