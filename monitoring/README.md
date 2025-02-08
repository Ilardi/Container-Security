# Monitoring

- [How does it work?](#how-does-it-work)
- [Installation](#Installation)
- [Example](#Example)

# How does it work?
This folder contains some files used to monitor activities on the host machine where containers are deployed. This is implemented through Falco, a security tool that can detect suspicious behaviour by analyzing system calls. There is an extensive set of default rules (https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml) and more can be added; for instance, a custom rule has been created for the detection of a newly open port inside a container. Defining new rules is as simple as writing them in falco_custom_rules.yaml .
<br><br>
Each time a rule is matched, a new line is written in the main log file (falco_report.txt); if a new port is opened in a container, that custom event is also written in a different log file (openport.txt). If you execute the observer.py script it will start watching the openport.txt file, so that each time a new port is opened the program will automatically launch nmap with ssl-enum-ciphers in order to evaluate the connection and see if TLS is being used and which versions; this is useful to determine if the connection is unsecure (like older versions of TLS, weak ciphers or TLS missing altogether).   

<p align="center">
<img src="https://github.com/user-attachments/assets/1e0f9a65-fef5-4400-8ea2-00603c7a285f"  height="500"></img>
</p>

# Installation
<h2>Falco</h2>
Since Falco is executed with minimal capabilities, before launching it for the first time it is necessary to give write permissions to the log files contained in the report folder:
<pre><code>chmod 666 report/falco_report.txt report/openport.txt</code></pre>

<br>
Falco is the only mandatory tool for this monitoring process. It can be installed on the host or run as a container; the choice has been the latter because it's the easiest to set up. 
<br><br>
If the kernel is recent enough (>=5.8 but might also work with older versions) there is actually nothing to install as Falco uses an embedded eBPF Probe, so it can be run using the following command:
<pre><code>docker run --rm -it \
--cap-drop all \
--cap-add sys_admin \
--cap-add sys_resource \
--cap-add sys_ptrace \
-v  /var/run/docker.sock:/host/var/run/docker.sock \
-v /proc:/host/proc:ro \
-v /etc:/host/etc:ro \
-v ./falco_custom_rules.yaml:/etc/falco/rules.d/falco_custom_rules.yaml \
-v ./falco.yaml:/etc/falco/falco.yaml \
-v ./report/falco_report.txt:/var/log/falco_report.txt \
-v ./event_handler.sh:/etc/falco/event_handler.sh \
-v ./report/openport.txt:/var/log/openport.txt \
falcosecurity/falco:latest</code></pre>

<h3>Older versions</h3>
Older distributions or kernels might require a different setup; the documentation is found at https://falco.org/docs/setup/container . For instance, a Debian 10 distribution with 4.9.10 kernel has been tested and it works by first installing the Kernel Module: 
<pre><code>docker run --rm -it \
--privileged \
-v /root/.falco:/root/.falco \
-v /boot:/host/boot:ro \
-v /lib/modules:/host/lib/modules \
-v /usr:/host/usr:ro \
-v /proc:/host/proc:ro \
-v /etc:/host/etc:ro \
falcosecurity/falco-driver-loader:latest-buster kmod
</code></pre>
After that you can run the container using:
<pre><code>docker run --rm -it \
-e HOST_ROOT=/ \
--cap-add SYS_PTRACE --pid=host $(ls /dev/falco* | xargs -I {} echo --device {}) \
-v /var/run/docker.sock:/var/run/docker.sock \
-v /etc:/host/etc:ro \
-v ./falco_custom_rules.yaml:/etc/falco/rules.d/falco_custom_rules.yaml \
-v ./falco.yaml:/etc/falco/falco.yaml \
-v ./report/falco_report.txt:/var/log/falco_report.txt \
-v ./event_handler.sh:/etc/falco/event_handler.sh \
-v ./report/openport.txt:/var/log/openport.txt \
falcosecurity/falco:latest falco -o engine.kind=kmod
</code></pre>

<br>
Following the installation guide you can find the appropriate setup for your machine. The important part is to run it as a container with the following volumes:
<pre><code>-v ./falco_custom_rules.yaml:/etc/falco/rules.d/falco_custom_rules.yaml \
-v ./falco.yaml:/etc/falco/falco.yaml \
-v ./report/falco_report.txt:/var/log/falco_report.txt \
-v ./event_handler.sh:/etc/falco/event_handler.sh \
-v ./report/openport.txt:/var/log/openport.txt \</code></pre>

<h2>Nmap (Optional)</h2>
If you choose to run the observer.py script to test new connections, you will need both Python (>=3.0) and Nmap installed on your host. If nmap is not already available, it can be easily downloaded with package managers such as apt or rpm; check the documentation for more details https://nmap.org/download.html .

# Example
Follow the installation guide to start Falco, then run the observer with:
<pre><code>python observer.py</code></pre>
We can now test the system. Let's launch a container with:
<pre><code>docker run --name swaggerapi-petstore3 -p 8080:8080 swaggerapi/petstore3:1.0.19</code></pre>
Then open a shell inside the container with:
<pre><code>docker exec -it swaggerapi-petstore3 sh</code></pre>

<br>
Let's take a look at what happened. If you open falco_report.txt you are going to see 2 events: an open port when the container was launched, and the opening of a shell which is detected by the default rule set:

![image](https://github.com/user-attachments/assets/634b80a4-208a-4093-90f0-cdf1f669bf69)

<br>
In the openport.txt file you will only see the open_port event. If you installed Nmap and started the observer, then when this event happened the script automatically launched Nmap on the newly open port, so you can take a look at the Nmap report:

![image](https://github.com/user-attachments/assets/b95aa061-1e92-4a21-9254-226cba5b2783)

Since the report is not showing any details other than the port being open we can conclude that the container is not using TLS.
<br>
Now let's use a TLS example. Run the following demo https server:
<pre><code>docker run --name https-server -p 443:443 ilardi/python-https-server:latest</code></pre>
If you now look at the nmap report it is going to be something like this:

<img src="https://github.com/user-attachments/assets/23a4a7a1-4aa9-4911-85e1-deb6e5987071"  height="400"></img>

You can see all the details regarding the TLS configuration, and each cipher has a security score. If there were any vulnerabilities with the current setup they would be reported in a "warnings" section.  
