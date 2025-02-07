import argparse
import sys
import subprocess
import os

def docker_bench_analysis(name, docker_bench_path, outfolder):
	print(f"\033[1;32m\nStarting Docker-bench-security analysis\033[0m")
	
	main_directory = os.getcwd()
	os.chdir(docker_bench_path)
	subprocess.run(f"sh docker-bench-security.sh -b -p -i {name} -c container_runtime -l {main_directory}/{outfolder}/docker_bench", 
		shell=True, capture_output=True)
		
	# Remove unnecessary output file
	subprocess.run(f"rm {main_directory}/{outfolder}/docker_bench", shell=True)
	os.chdir(main_directory)
	print("Done")
	

def main():
	# Create the argument parser	
	parser = argparse.ArgumentParser(allow_abbrev=False,  formatter_class=argparse.RawDescriptionHelpFormatter, 
	description="This script performs a dynamic analysis on a running container leveraging section 5 (container runtime) of Docker-bench-security. "
	"It is necessary to specify the dockerbench path with the appropriate command line arguments or environment variables. If the application has a REST API, "
	"and an OpenAPI (Swagger) specification is given to the script, it will run CATS to do fuzzing on the API; in order to perform this analysis "
	"it is necessary to tell the path as done with docker-bench-security, and it is also required to point out the container port number to test, and the --https option if the application supports it")
	
	parser.add_argument('--name', type=str, metavar="string", help="Container name (it has to be already running)", required=True)  
	parser.add_argument('--outfolder', type=str, metavar="string", help="Reports will be generated in this folder (Default: reports)")
	parser.add_argument('--docker_bench_path', type=str, metavar="string", help="Path to the folder containing 'docker-bench-security.sh'. "
	"This path can also be set with the $DOCKERBENCH_PATH variable")
	parser.add_argument('--cats_path', type=str, metavar="string", help="Path to the folder containing 'cats.jar'. "
	"This path can also be set with the $CATS_PATH variable. It is only required when cats.jar is not in the same folder as this script")
	parser.add_argument('--apispec', type=str, metavar="string", help="CATS: Path to the OpenAPI specification (Eg. /path/to/API.yaml)")
	parser.add_argument('--port', type=str, metavar="string", help="CATS: Port number to test on the container")
	parser.add_argument('--prefix', type=str, metavar="string", help="CATS: A path prefix that will be added in front of any path in the specification")
	parser.add_argument('--https', action='store_true', help="CATS: Use this option if the REST API supports https")

	# Parse the arguments
	args = parser.parse_args()

	name = args.name
	# Check if the container is running
	ps_out = subprocess.run(f"docker ps --filter \"name={name}\" --quiet", shell=True, capture_output=True).stdout
	if not ps_out:
		print(f"\nError: Container {name} is not running\n")
		parser.print_help()
		sys.exit(1)

	outfolder = "report"
	if args.outfolder:
		outfolder = args.outfolder.rstrip('/')
	
	# Create report folder    
	if not os.path.exists(outfolder):
		os.makedirs(outfolder)  
	
	docker_bench_path = "/home/kali/docker-bench-security"
	if args.docker_bench_path:
		docker_bench_path = args.docker_bench_path.rstrip('/')	
	elif os.environ.get("DOCKERBENCH_PATH"):
		docker_bench_path = os.environ.get("DOCKERBENCH_PATH").rstrip('/')
		
	cats_path = "."
	if args.cats_path:
		cats_path = args.cats_path.rstrip('/')	
	elif os.environ.get("CATS_PATH"):
		cats_path = os.environ.get("CATS_PATH").rstrip('/')
	
	if args.apispec and not args.port:
		print("\nError: Missing argument --port\n")
		parser.print_help()
		sys.exit(1)

	# Docker-bench analysis
	docker_bench_analysis(name, docker_bench_path, outfolder)
	
	# REST API Analysis with CATS
	apispec = args.apispec
	if apispec:
		
		port = args.port

		prefix = ""
		if args.prefix:
			prefix = args.prefix.lstrip("/")

		if args.https:
			protocol = "https"
		else:
			protocol = "http"
			
		# Get container IP
		command = "docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' " + name
		container_ip = subprocess.run(command, shell=True, capture_output=True).stdout.decode('utf-8').strip()
		
		server = protocol + "://" + container_ip + ":" + port + "/" + prefix
		subprocess.run(f"java -jar {cats_path}/cats.jar --contract {apispec} --server {server} --output {outfolder}/cats_report", shell=True)

if __name__ == "__main__":
    main()
