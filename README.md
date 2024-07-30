# Firewall Audit
Perform an audit of one or more Sophos firewalls for compliance with a baseline security settings. The audit compares a defined set of expected settings (the baseline) with the actual running configuration of each firewall, and produces an HTML report indicating audit Pass/Fail status. 

[Example Report Output](https://sophos.github.io/sophos-firewall-audit/)

## Installation
The firewall audit can be installed using the Python `pip` installer. Python 3.9 is the minimum version required on your system prior to installation. We recommend installing into a Python virtual environment so as not to interfere with any other Python packages installed on your system.

```bash
python -m venv firewallaudit
# Activate virtual environment on Linux
source ./firewallaudit/bin/activate
# Activate virtual environment on Windows
firewallaudit\Scripts\activate.bat

pip install sophos-firewall-audit
```
Once installed, the command `sophosfirewallaudit --help` should display the help menu for the program. 

> Windows users may see an error message `ModuleNotFoundError: No module named 'pkg_resources' ` when running the `sophosfirewallaudit` command.  To correct this, run `pip install setuptools`.  

## Setup
The expected settings must first be defined in the `audit_settings.yaml` file. The file `audit_settings.yaml.example` is provided to help with defining the expected settings. It should be modified to match the expected firewall configuration in the target environment. The filename `audit_settings.yaml` will be used by the audit by default. It is also possible to have separate settings files for different firewall configurations.  In that case, you would specify the `-s` or `--settings_file` option to specify the settings filename when running the audit. 

### Firewall Credentials
The program can use username and password credentials stored as environment variables:

```bash
# Linux
export FW_USERNAME=<Your firewall username>
export FW_PASSWORD=<Your firewall password>

# Windows
set FW_USERNAME=<Your firewall username>
set FW_PASSWORD=<Your firewall password>
```
Alternatively, it can pull the credentials from Hashicorp Vault. To do so, the following environment variables must be defined:

```bash
VAULT_MOUNT_POINT = HashiCorp Vault Mount Point (ex. kv)
VAULT_SECRET_PATH = HashiCorp Vault Secret path
VAULT_SECRET_KEY = HashiCore Vault Secret Key
ROLEID = HashiCorp Vault Role ID
SECRETID = HashiCorp Vault Secret ID
```
To use Hashicorp vault when the program is run, the `--use_vault` argument should be specified. 

### Inventory
The audit will be performed on the devices listed in the file `firewalls.yaml`.  An example inventory file is shown below:

```yaml
- hostname: example-host-1.somedomain.com
  port: 4444
- hostname: example-host-2.somedomain.com
  port: 4444
```
  
It is also possible to use [Nautobot](https://github.com/nautobot/) rather than an inventory file. The audit program can access the Nautobot API to retrieve the firewall inventory instead of using the `firewalls.yaml` file. The program will use a GraphQL query to retrieve the inventory from Nautobot. The GraphQL query can be customized as needed to meet your inventory requirements.

If using Nautobot as inventory the following environment variables are required:
```bash
NAUTOBOT_URL = Nautobot URL
NAUTOBOT_TOKEN = Nautobot API Token
```
In addition, you must configure the query to retrieve the inventory.  The query is written in the GraphQL language, for which there is a helpful query tool in the Nautobot UI that can assist with building the queries. There are three example query files in the `nautobot_query` directory of this repository that can be modified to suit your environment:
  
`nautobot_query/all_devices_query.j2`:  This example query returns all firewalls that have a status in Nautobot of Active, have a tag of `SFOS`, and that do not have a tag of `Auxillary`.  The `SFOS` tag is used to select only devices in Nautobot running Sophos Firewall OS. The `Auxillary` tag is used to identify devices in Nautobot that are the standby device in an HA pair. 

`nautobot_query/device_query.j2`: This example query can be used to provide a specific list of devices in Nautobot. 

`nautobot_query/location_query.j2`:  This example query returns the firewalls that are in the specified Location(s) in Nautobot, that have a status of Active, a tag of `SFOS`, and do not have a tag of `Auxillary`. 

> To use the existing queries as-is, you would need to create the Auxillary tag in Nautobot and assign it to one of the members of each HA pair. Also, the `SFOS` tag would need to be created in Nautobot and assigned to devices running Sophos Firewall OS. Since we do not want to target Auxillary devices, we use the `tag__n` notation which tells GraphQL to return devices that do not have the tag Auxillary.  

The query file should be specified using the `-q` or `--query_file` option along with the `-n` or `--use_nautobot` flag on the command line.  

## Usage
```bash
sophosfirewallaudit --help
usage: sophosfirewallaudit [-h] (-i INVENTORY_FILE | -n) [-q QUERY_FILE] [-d] [-s SETTINGS_FILE] [-u]

options:
  -h, --help            show this help message and exit
  -i INVENTORY_FILE, --inventory_file INVENTORY_FILE
                        Inventory filename
  -n, --use_nautobot    Use Nautobot for inventory
  -q QUERY_FILE, --query_file QUERY_FILE
                        File containing Nautobot GraphQL query
  -d, --disable_verify  Disable certificate checking for Nautobot
  -s SETTINGS_FILE, --settings_file SETTINGS_FILE
                        Audit settings YAML file
  -u, --use_vault       Use HashiCorp Vault to retrieve credentials
  -r, --rule_export     Export rules for offline viewing
```
Example:
```bash
sophosfirewallaudit --inventory_file firewalls.yaml --settings_file audit_settings.yaml
```

> The `--rule_export` command provides the ability to export the firewall rules so that they can be viewed offline using a web browser. If this flag is provided, the audit will be skipped and instead the rule export will be executed.

## Viewing Results
Upon completion of each audit run, html files containing the results are generated. The directory `results_html_local` can be used to view the results in the browser by opening them as files (no web server required). The directory `results_html_web` contains html files with the links formatted such that the content can be published on a web server.

> If using the `--rules_export` flag, the results will be written to `rule_export_local` and `rule_export_web`. 
  
### Viewing Results Locally
Upon completion of each audit run, the results are stored in the `results_html_local` directory. In this directory, the `index.html` contains hyperlinks to browse the results as files in a web browser. Simply open the `index.html` file in a web browser. Each time the audit is run, the `index.html` file is updated with a new hyperlink for the new results. 

### Publish using a Docker container
Results are also stored in the directory `results_html_web`, but in this case the hyperlinks are configured for use with a web server. A Docker container can be built that runs a lightweight web proxy (NGINX) to serve the files over HTTPS. Follow the below steps to build and run the container:

1. Create an SSL private key and certificate to be used with the container. You may use the commands here to create a self-signed certificate, however, we recommend obtaining a certificate from a trusted Certificate Authority.

```bash
cd docker
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr
openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt
```
> The files `server.crt` and `server.key` need to be in the `docker` directory, otherwise the NGINX service will not start in the container

2. Build the container

```bash
cd docker
docker build . -t firewall-audit --platform=linux/amd64
```

3. Run the container.  The below command must be run from the directory where the `results_html_web` was created. 
```bash
docker run --rm -d -p 8443:8443 -v $(pwd)/results_html_web:/usr/share/nginx/html firewall-audit
```

The container should now be available on the local host using `https://localhost:8443`. It should also be accessible from other hosts on the network using `https://<hostname_or_ip>:8443`. 

> The reason for using port 8443 instead of 443 here is because some systems require elevated privileges to open ports < 1024. 

### Deploy to Kubernetes
The container can also be deployed on a Kubernetes cluster using the included Helm chart. To accomplish this, the container must be built using Docker and pushed to a container registry that is accessible to the cluster. The `values.yaml` file must be updated with the parameters for your deployment, and then the container can be created in Kubernetes using the included Helm chart. The below example uses Amazon ECR (Elastic Compute Registry) to store the container image in a registry named `fwaudit-results`. 

1. Copy the `results_html_web` folder to `docker/results_html_web`. It is fine to overwrite the existing `docker/results_html_web` folder, as it is only a placeholder. 

2. Build the container
```bash
cd docker
docker build . -t firewall-audit --platform=linux/amd64
```

2. Tag and push the container to the registry
```bash
docker tag firewall-audit 503708563173.dkr.ecr.eu-west-1.amazonaws.com/fwaudit-results:latest
aws ecr get-login-password --region eu-west-1 | docker login --username AWS --password-stdin 503708563173.dkr.ecr.eu-west-1.amazonaws.com
docker push 503708563173.dkr.ecr.eu-west-1.amazonaws.com/fwaudit-results:latest
```
3. In the `helm-chart` directory, update the `values.yaml` with your image name and tag:

```yaml
firewall-audit:
  image:
    repository: 503708563173.dkr.ecr.eu-west-1.amazonaws.com/fwaudit-results  # Replace this
    tag: latest
  replicaCount: 1
  service:
    type: LoadBalancer
    port: 443
    targetPort: 8443
  ingress:
    enabled: true
namespace: firewall-audit
```

4. Deploy the Helm chart:
```bash
cd helm-chart
helm install firewall-audit . -f values.yaml
```
  
Once deployed, display the service URL:
```bash
ubuntu@ip-10-183-4-122:~$ kubectl get svc -n fwaudit
NAME      TYPE           CLUSTER-IP     EXTERNAL-IP                                                                        PORT(S)         AGE
fwaudit   LoadBalancer   172.20.15.15   internal-a9570544864734ace8277f0f0a2777e2-1446725547.eu-west-1.elb.amazonaws.com   443:30603/TCP   3d3h
```

The web browser will be running at `https://<EXTERNAL-IP>`. 

> Using this option, the `results_html_web` directory is copied into the container with the current contents. It will not automatically pick up the latest results when running a new audit. To accomplish that, the container must be re-built each time a new audit is run and pushed to the container registry. The container can then be updated in Kubernetes using `helm upgrade . -f values.yaml`.   
