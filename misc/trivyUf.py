import subprocess
import sys
import re

def main():
	# Launch trivy with the specified arguments
	args = sys.argv[1:]
	trivy_command = ["trivy"] + args + ["--no-progress"]
	result = subprocess.run(trivy_command, capture_output=True, text=True)	
	
	# Check for errors in trivy command
	if result.stdout != "":
		print(result.stdout)
		print(result.stderr)
		
	# Trivy command is good
	else:
		console_output = result.stderr
		
		# Check for supported OS
		detected_os_pattern = r"Detected OS\s+(.+)"
		match = re.search(detected_os_pattern, console_output)
		if match:
			detected_os_info = match.group(1)
			print("Trivy Image: Supported OS found - " + detected_os_info)	
		else:
			print("Trivy Image: OS not supported")
		
		# Check for language-specific files
		language_files_pattern = r"Number of language-specific files\s+num=(\d+)"
		match = re.search(language_files_pattern, console_output)
		num_value = match.group(1)
		if num_value == "0":
			print("Trivy Image: No language-specific files have been found\n")	
		elif num_value == "1":
			print("Trivy Image: Found 1 language-specific file\n")
		else:
			print("Trivy Image: Found " + num_value + " language-specific files\n")
		
		# Print trivy console output
		print(console_output)
		
if __name__ == "__main__":
    main()
