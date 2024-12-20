import argparse
import sys
import subprocess
import re
import os
import json
import xml.etree.ElementTree as ET
from pathlib import Path

def docker_bench_analysis(image, docker_bench_path, outfolder):
	print(f"\033[1;32m\nStarting Docker-bench-security analysis\033[0m")
	
	# Remove tag from the image because docker-bench doesn't want it	
	stripped_image = image.split(':')[0]
	
	main_directory = os.getcwd()
	os.chdir(docker_bench_path)
	subprocess.run(f"sh docker-bench-security.sh -b -p -i {stripped_image} -c container_images -l {main_directory}/{outfolder}/docker_bench", 
		shell=True, capture_output=True)
	# Remove unnecessary output file
	subprocess.run(f"rm {main_directory}/{outfolder}/docker_bench", shell=True)
	os.chdir(main_directory)
	print("Done")
	

def generate_report(image, lang, trivy_out, trivy_mode, lang_out, outfolder, workdir, excluded_paths):
	print("\033[1;32m\nGenerating final report\033[0m")

	# Check if the language analysis was skipped
	code_section = {
		"workdir": workdir,
		"excluded_paths": excluded_paths,
		"size": lang_out[3],
		"vulnerabilities": {
        	"low": lang_out[0],
        	"medium": lang_out[1],
        	"high": lang_out[2]
		}
	} if lang_out else "skipped" 

	summary_section = {
    	"low": lang_out[0] + trivy_out[0] + trivy_out[3],
    	"medium": lang_out[1] + trivy_out[1] + trivy_out[4],
    	"high": lang_out[2] + trivy_out[2] + trivy_out[5],
		"size": lang_out[3],
	} if lang_out else {
			"low": trivy_out[0] + trivy_out[3],
			"medium": trivy_out[1] + trivy_out[4],
			"high": trivy_out[2] + trivy_out[5],
			"size": "skipped"
		} 
	
	# Build the JSON structure dynamically
	data = {
		"imageName": image,
		"language": lang,
		"reportFolder": str(Path(outfolder).resolve()),
		"analysis": {
		    "trivy": {
		        "imageOS": trivy_out[6],
		        "filesAnalyzed": trivy_out[7],
		        "mode": trivy_mode,
				"OS_vulnerabilities": {
					"low": trivy_out[0], 
					"medium": trivy_out[1],
					"high": trivy_out[2]
				},
				"dependencies_vulnerabilities": {
					"low": trivy_out[3],
					"medium": trivy_out[4],
					"high": trivy_out[5]
				}	
		    },
		    "code": code_section, 
		    "summary": summary_section
		}
	}

	# Save to JSON file
	with open(f"{outfolder}/generalReport.json", "w") as json_file:
		json.dump(data, json_file, indent=4)


def parse_bandit(filepath):
	with open(filepath, "r") as file:
		content = file.read()

	results = []

	# Extract issues by severity 
	severity_match = re.search(
		r"Total issues \(by severity\):\s+(?:Undefined:\s+\d+\s+)?Low:\s+(\d+)\s+Medium:\s+(\d+)\s+High:\s+(\d+)",
		content,
	)
	if severity_match:
		results.extend([int(severity_match.group(1)),  # Low
		                int(severity_match.group(2)),  # Medium
		                int(severity_match.group(3))])  # High

	# Extract LOC analyzed
	lines_of_code_match = re.search(r"Total lines of code:\s+(\d+)", content)
	if lines_of_code_match:
		results.append(int(lines_of_code_match.group(1)))
		
	return results


def parse_spotbugs(filepath):
	# Parse the XML file
	tree = ET.parse(filepath)
	root = tree.getroot()

	# Count the number of issues with priority 1, 2 and 3 (1 being HIGH)
	# belonging to the SECURITY category
	counts = {priority: 0 for priority in ['1', '2', '3']}
	for bug in root.findall('BugInstance'):
		if bug.get('category') == 'SECURITY':  
		    priority = bug.get('priority')
		    if priority in counts:  
		        counts[priority] += 1
	
	# Count the number of unique classes analyzed 
	# This is used as a Java project size metric
	analyzed_classes = set()
	for class_element in root.findall(".//Class"):
		class_name = class_element.get('classname') 
		if class_name:
		    analyzed_classes.add(class_name)
	
	return [counts["3"], counts["2"], counts["1"], len(analyzed_classes)]



def pull_image(image):
    print("\033[1;32m\nPulling Docker Image\033[0m")
    
    result = subprocess.run(
        ['docker', 'pull', image],
        stderr=subprocess.PIPE,
        text=True
    )
    if result.returncode != 0:
        print(f"Error pulling image '{image}'\n{result.stderr}")
        sys.exit(result.returncode)
        
    print(f"Successfully pulled image '{image}'.")


def trivy_analysis(image, outfolder, trivy_mode):
	print("\033[1;32m\nStarting Trivy analysis\033[0m")
	print("\033[1;38;5;214mIt could take some time to download the vulnerability database\033[0m")
	
	trivy_command = ["trivy","image", "--format=table", f"--output={outfolder}/trivyReport.txt", "--parallel=0", f"--detection-priority={trivy_mode}", image]
	result = subprocess.run(trivy_command, capture_output=True, text=True)	

	# Note: The normal Trivy console output is actually stderr.
	# stdout is used when the command has a wrong format in order to show the --help 
	console_output = result.stderr
	
	# Check for FATAL errors
	fatal_pattern = r"FATAL"
	match = re.search(fatal_pattern, result.stderr)
	if match:
		print("FATAL Error during Trivy execution\n")
		print(result.stdout)
		print(console_output)
		sys.exit(1)

	# Check for supported OS
	detected_os_pattern = r"Detected OS\s+(.+)"
	detected_os = "Not supported"
	match = re.search(detected_os_pattern, console_output)
	if match:
		detected_os = match.group(1)
		print("Trivy Image: Supported OS found - " + detected_os)	
	else:
		print("Trivy Image: OS not supported")
	
	# Check for language-specific files
	language_files_pattern = r"Number of language-specific files\s+num=(\d+)"
	match = re.search(language_files_pattern, console_output)
	files_count = match.group(1)
	if files_count == "0":
		print("Trivy Image: No language-specific files have been found\n")	
	elif files_count == "1":
		print("Trivy Image: Found 1 language-specific file\n")
	else:
		print("Trivy Image: Found " + files_count + " language-specific files\n")
	
	# Count the vulnerabilities (CRITICAL vulns are included into HIGH)
	os_low = 0
	os_medium = 0
	os_high = 0
	dep_low = 0
	dep_medium = 0
	dep_high = 0
	
	# The first match is the OS line, the remaining are dependencies
	first_match = True
	with open(f'{outfolder}/trivyReport.txt', 'r') as file:
		for line in file:
			match = re.search(r'LOW: (\d+), MEDIUM: (\d+), HIGH: (\d+), CRITICAL: (\d+)', line)
			if match:
			
				if first_match:
					first_match = False
					os_low = int(match.group(1))
					os_medium = int(match.group(2))
					os_high = int(match.group(3)) + int(match.group(4))
				else:
					dep_low += int(match.group(1))
					dep_medium += int(match.group(2))
					dep_high += int(match.group(3)) + int(match.group(4))
	
	return [os_low, os_medium, os_high, dep_low, dep_medium, dep_high, detected_os, files_count]


def get_installed_files(image, os, lang):

	# Define which file extensions will be considered 
	if lang == "python":
		lang_extensions = "py"
	elif lang == "java":
		lang_extensions = "jar|ear|war|zip|class"
		
	# Differentiate among OS
	if os in ["debian", "ubuntu"]:
		inside_command = rf"dpkg --get-selections | grep -w 'install' | cut -f1 | xargs dpkg -L | grep -E '\.({lang_extensions})$'"
		command = f"docker run --rm --entrypoint bash {image} -c \"{inside_command}\""
	
	elif os == "redhat":
		inside_command = rf"rpm -qa --qf '%{{NAME}}\n' | xargs -I {{}} rpm -ql {{}} | grep -E '\.({lang_extensions})$'"
		command = f"docker run --rm --entrypoint bash {image} -c \"{inside_command}\""
		
	elif os == "alpine":	
		# Write a temporary entrypoint to be mounted into the container
		# This is the only working solution I found for Alpine because using sh -c gives a lot of problems
		alpine_sh_script = rf"""
#!/bin/sh
apk update > /dev/null
apk info | while read -r package; do
	apk info -L "$package" | grep -E '\.({lang_extensions})$'
done
"""
		with open("./tmp_alpine_entrypoint.sh", "w") as script_file:
			script_file.write(alpine_sh_script)
			
		command = f"docker run --rm -v ./tmp_alpine_entrypoint.sh:/tmp_alpine_entrypoint.sh --entrypoint sh {image} /tmp_alpine_entrypoint.sh"


	# Finally run the command
	result = subprocess.run(command, shell=True, capture_output=True, text=True)

	# Cleanup tmp entrypoint (if Alpine)
	if os == "alpine":
		subprocess.run("rm ./tmp_alpine_entrypoint.sh", shell=True)	

	# The returncode will be different from 0 in case of errors or even if no files are found.
	# Either way, this means that no installed files will be skipped
	if result.returncode == 0:
		return [0, result.stdout.splitlines()]
	else:
		return [1, ""]


def lang_analysis(image, detected_os, include_pkg, lang, given_workdir, spotbugs_path, outfolder, excluded_paths):
	print(f"\033[1;32mStarting Language-Specific Analysis: {lang}\033[0m")
	
	# If the workdir is given then that one is used, otherwise we try to fetch it from the image
	workdir = ""
	if given_workdir:
		workdir = given_workdir
	else: 
		# Extract the WorkingDir
		result = subprocess.run(
		    ['docker', 'inspect', image],
		    stdout=subprocess.PIPE,
		    text=True
		)    
		
		image_info = json.loads(result.stdout)
		workdir = image_info[0]["Config"].get("WorkingDir", "")
		if not workdir:
			print("\033[1;91mWorkingDir not detected, skipping analysis\033[0m")
			return "",""
	
	# The absolute workdir is required, otherwise the excluded paths for Bandit and Pylint won't work
	abs_workdir = Path("image-tmp" + workdir).resolve()
			
	# Extract image filesystem with Crane in a tmp folder 
	# (apparently Crane doesn't allow to only extract the specific workdir)
	if not os.path.exists("image-tmp"):
		os.makedirs("image-tmp")
	print("\033[1;37mExtracting image filesystem\033[0m")
	subprocess.run(f"docker save {image} | crane export - image-tmp/filesystem.tar", capture_output=True, shell=True)	
	subprocess.run("tar xf image-tmp/filesystem.tar -C image-tmp", capture_output=True, shell=True)
	subprocess.run(["rm", "image-tmp/filesystem.tar"], capture_output=True)


	# Extract the list of system files to exclude
	if include_pkg:
		print("\033[1;38;5;214mSystem files will be included in the analysis\033[0m")
	else:
		if detected_os != "Not supported":
			detected_os = detected_os.lower() 
			if "debian" in detected_os:
				image_os = "debian"
			elif "ubuntu" in detected_os:
				image_os = "ubuntu"
			elif "redhat" in detected_os:
				image_os = "redhat"
			elif "alpine" in detected_os:
				image_os = "alpine"
			else:
				image_os = ""
		
			if image_os:
				return_code, installed_files = get_installed_files(image, image_os, lang)
				
			if return_code == 1:
				print("\033[1;38;5;214mWarning: the script was not able to exclude system files from the analysis\033[0m")
			else:
				# Prefix the absolute path to image-tmp to each file to exclude
				installed_files = [str(Path("image-tmp").resolve()) + path for path in installed_files]
				
				# Delete the files
				starting_path = Path("./image-tmp").resolve()
				for path in installed_files:
					if path.startswith(str(starting_path)) and path != starting_path:
						subprocess.run(f"rm {path}", capture_output=True, shell=True)
	

    # Java workflow
	if lang == "java":
		print("\033[1;37mStarting Spotbugs analysis\033[0m")
		
		# Spotbugs works with package/class names rather than directories, so in order to exclude paths
		# from the analysis these will be deleted from the image-tmp folder
		# The checks are there to make sure we don't delete folders outside image-tmp if, as an example, .. is used 
		# This is actually a second check because the first one is in the main
		if excluded_paths:
			starting_path = Path("./image-tmp").resolve()
			for path in excluded_paths:
				complete_path = "image-tmp" + path
				abs_path = Path(complete_path).resolve()
				if str(abs_path).startswith(str(starting_path)) and abs_path != starting_path:
					subprocess.run(f"rm -rf {abs_path}", capture_output=True, shell=True)
				else:
					print(f"\033[1;91mInvalid excluded path: {path}\033[0m")
		
		try:
			subprocess.run(f"java -Xmx6G -jar {spotbugs_path}/spotbugs.jar -textui -progress -low -xml={outfolder}/spotbugs.xml -quiet {abs_workdir}", 
				shell=True, check=True)
		
		# An exception is raised if Spotbugs did not find any java files to analyze
		except subprocess.CalledProcessError as ex:
			print("\033[1;91m\nFATAL Error during Spotbugs execution\033[0m")
			lang_out = [0, 0, 0, 0]
		else:
			lang_out = parse_spotbugs(f"{outfolder}/spotbugs.xml")
	
	# Python workflow    
	elif lang == "python":
	
		# Manage excluded paths. Pylint manages differently the excluded folder/package names (--ignore) and paths (--ignore-paths)
		base_excluded = "env,venv,.env,.venv"
		user_excluded = ""
		if_user_excluded = ""
		if excluded_paths:
			if_user_excluded = "--ignore-paths"
			for path in excluded_paths:
				complete_path = "image-tmp" + path
				complete_abs_path = Path(complete_path).resolve()
				user_excluded += str(complete_abs_path) + ","
		user_excluded = user_excluded.rstrip(",")	
		
		# Bandit has what i believe to be a bug: when a folder such as env is in the same directory where the program is executed,
		# using -x env will not work for some reason, while the same option will work if env is in some subdirectory. Instead, 
		# using -x /env appears to be working whatever the location of the env folder may be
		bandit_excluded = "/env,/venv,/.env,/.venv"
		if user_excluded != "":
			bandit_excluded += "," + user_excluded
		
		print("\033[1;37mStarting Pylint analysis\033[0m")
		subprocess.run(f"pylint -j 0 -f json2 --output {outfolder}/pylint.json --recursive y --ignore {base_excluded} {if_user_excluded} {user_excluded} {abs_workdir}", capture_output=True, shell=True)	
		
		print("\033[1;37mStarting Bandit analysis\033[0m")
		subprocess.run(f"bandit -r -x {bandit_excluded} -f txt --output {outfolder}/bandit.txt {abs_workdir}", capture_output=True, shell=True)
		lang_out = parse_bandit(f"{outfolder}/bandit.txt")
	
	# Cleanup and return
	subprocess.run(["rm", "-rf", "image-tmp"])
	return lang_out, workdir

def check_local_image(image):
    # Run the 'docker images' command with formatting
    result = subprocess.run(['docker', 'images', '--format', '{{.Repository}}:{{.Tag}}'],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    # Check if the full image name with tag is in the output
    images = result.stdout.splitlines()
    if image not in images:
        print(f"\033[1;91mImage '{image}' does not exist locally\033[0m")
        sys.exit(1)


def main():
	# Create the argument parser	
	parser = argparse.ArgumentParser(allow_abbrev=False,  formatter_class=argparse.RawDescriptionHelpFormatter, 
	description="This script performs static analysis on a Docker image by leveraging several "
	"open-source tools: docker-bench-security (image building), Trivy (OS and dependency analysis), Spotbugs (Java bytecode analysis), "
	"Pylint and Bandit (Python code analysis). In order for the script to work, Trivy, Bandit and Pylint executables need to be added to $PATH, "
	"while docker-bench-security and Spotbugs are .sh and .jar, so the path to the folders containing these files needs to be specified via "
	"$DOCKERBENCH_PATH and $SPOTBUGS_PATH environment variables; these two paths can also be given to the script with command line arguments.")
	
	parser.add_argument('--image', type=str, metavar="string", help="Complete name of the image (Eg. nginx:latest)", required=True)  
	parser.add_argument('--lang', type=str, metavar="string", help="Application language (python or java)", required=True)
	parser.add_argument('--workdir', type=str, metavar="string", help="The project source directory inside the container. If the Dockerfile contains the WORKDIR " 
	"instruction this is fetched automatically. If neither this argument or the Dockerfile instruction are used the code analysis will be skipped")
	parser.add_argument('--outfolder', type=str, metavar="string", help="Reports will be generated in this folder (Default: reports)")
	parser.add_argument('--exclude', metavar="path1,path2", type=lambda paths: paths.split(','), help="Comma-separated list of folder paths to exclude from the code analysis (Eg. path1,path2). "
	"The values should be absolute paths within the container")
	parser.add_argument('--trivy_mode', type=str, metavar="string", help="Tell Trivy to work in precise or comprehensive mode (Default: precise). "
	"The comprehensive mode will try to find more vulnerabilities but could generate more false positives")
	parser.add_argument('--spotbugs_path', type=str, metavar="string", help="Path to the folder containing 'spotbugs.jar'. "
	"This path can also be set with the $SPOTBUGS_PATH variable")
	parser.add_argument('--docker_bench_path', type=str, metavar="string", help="Path to the folder containing 'docker-bench-security.sh'. "
	"This path can also be set with the $DOCKERBENCH_PATH variable")
	parser.add_argument('--local', action='store_true', help="Use if the image only exists locally and not in DockerHub. This will skip the image pulling step of the script")
	parser.add_argument('--cleanup', action='store_true', help="Using this option will delete the pulled Docker image once the analysis is done"
	"If the --local option is used then this flag will not work to prevent accidentally deleting the local image")
	parser.add_argument('--include_pkg', action='store_true', help="By default the script tries to locate and exclude from the code analysis all the files "
	"installed in the container with a package manager. Use this option if you want to include them in the analysis")
	

	# Parse the arguments
	args = parser.parse_args()

	image = args.image
	if ":" not in image:
		print("\033[1;37m\nImage Tag not specified, using 'latest'\033[0m")
		image = image + ":latest"

	outfolder = "reports"
	if args.outfolder:
		outfolder = args.outfolder.rstrip('/')
		
	lang = args.lang
	if lang not in ["java", "python"]:
		print("\nError: The -lang argument must be 'java' or 'python'.\n")
		parser.print_help()
		sys.exit(1)

	excluded_paths = args.exclude
	if excluded_paths:
		for path in excluded_paths:
			if ".." in path:
				print("\nError: the excluded path cannot contain '..'")
				sys.exit(1)
	
	trivy_mode = args.trivy_mode
	if trivy_mode:
		if trivy_mode not in ["precise", "comprehensive"]:
			print("\nError: The --trivy_mode argument must be 'precise' or 'comprehensive'.\n")
			parser.print_help()
			sys.exit(1)
	else:
		trivy_mode = "precise"
	
	spotbugs_path = "spotbugs-4.8.6/lib" 
	if args.spotbugs_path:
		spotbugs_path = args.spotbugs_path.rstrip('/')
	elif os.environ.get("SPOTBUGS_PATH"):
		spotbugs_path = os.environ.get("SPOTBUGS_PATH").rstrip('/')

	docker_bench_path = "docker-bench-security"
	if args.docker_bench_path:
		docker_bench_path = args.docker_bench_path.rstrip('/')	
	elif os.environ.get("DOCKERBENCH_PATH"):
		docker_bench_path = os.environ.get("DOCKERBENCH_PATH").rstrip('/')

	# Pull Docker image
	if not args.local:
		pull_image(image)
	else:
		check_local_image(image)
		
	# Create report folder    
	if not os.path.exists(outfolder):
		os.makedirs(outfolder)   

	# Docker-bench analysis
	docker_bench_analysis(image, docker_bench_path, outfolder)

	# Trivy analysis
	trivy_out = trivy_analysis(image, outfolder, trivy_mode)
	detected_os = trivy_out[6]

	# Language specific analysis
	lang_out, workdir = lang_analysis(image, detected_os, args.include_pkg, lang, args.workdir, spotbugs_path, outfolder, excluded_paths)

	# Generate final report
	generate_report(image, lang, trivy_out, trivy_mode, lang_out, outfolder, workdir, excluded_paths)
	print("Reports generated at " + str(Path(outfolder).resolve()))

	# Cleanup Docker image
	if args.cleanup and not args.local:
		print(f"\033[1;32m\nDeleting Docker image: \033[0m{image}")
		subprocess.run(f"docker image rm {image}", shell=True, capture_output=True)
		print("Done")

if __name__ == "__main__":
    main()
