# Dynamic analysis

- [How does it work?](#how-does-it-work)
- [Installation](#Installation)
- [Example](#Example)

# How does it work?
This folder contains a script that performs dynamic analysis on a running container. It leverages docker-bench-security in order to execute the tests from section 5 (Runtime) of the Docker CIS Benchmark and, if an OpenAPI specification is given, it will perform fuzzing on the API with the tool CATS.

<img src="https://github.com/user-attachments/assets/8f0c8130-1a2c-426d-8e01-f4ae18e59e86"  height="400"></img>

While this analysis might seem somewhat limited, it is difficult to find a general approach since a more detailed study would require a tailored configuration for the application under test and penetration testing activities, but that is out of scope for this project.

# Installation
To install docker-bench-security follow the guide in the static analysis folder. <br><br>

CATS is a REST API fuzzer that can be used to find problems in the API configuration. It can be installed either as a binary and as jar; both have been tested and the binary doesn't work on some platforms so just head over to https://github.com/Endava/cats/releases and download the latest uberjar. Once that is done you can simply add cats.jar to this folder or, if you wish to keep it in a separate folder, set the path using the <code>$CATS_PATH</code> environment variable or the <code>--cats_path</code> option.

# Example
