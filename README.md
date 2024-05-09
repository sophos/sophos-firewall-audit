# Firewall Audit
Perform an audit of one or more Sophos firewalls for compliance with a baseline security settings. The audit compares a defined set of expected settings (the baseline) with the actual running configuration of each firewall, and produces an HTML report indicating audit Pass/Fail status. 

## Setup
The expected settings must first be defined in the `audit_settings.yaml` file. The file `audit_settings.yaml.example` is provided to help with defining the expected settings. It should be modified to match the expected firewall configuration in the target environment. The example file can be named `audit_settings.yaml`, which will be used by the audit by default. Alternatively, it is possible to have settings files for different firewall configurations.  In that case, you would specify the `-f` or `--file` option to specify the settings filename when running the audit. 

### Firewall Credentials
The program can use a single username and password stored as environment variables:

```bash
FW_USERNAME = Firewall username
FW_PASSWORD = Firewall password
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
  
If Nautobot (https://github.com/nautobot/) is in use for storing of inventory, the audit program can access it to retrieve the firewall inventory instead of using the `firewalls.yaml` file. 

If using Nautobot as inventory the following environment variables are required:
```bash
NAUTOBOT_URL = Nautobot URL
NAUTOBOT_TOKEN = Nautobot API Token
```
In addition, you must configure the query to retrieve the inventory.  The query is written in the GraphQL language, for which there is a helpful query tool in the Nautobot UI that can assist with building the queries. There are three files that should be modified to suit your environment:
  
`templates/all_devices_query.j2`: This is the query that is executed if the `--all_devices` argument is specified. The current query returns all firewalls that have a status in Nautobot of Active and that do not have a tag of `Auxillary`.  The `Auxillary` tag is used to tag devices in Nautobot that are the standby device in an HA pair, as they should not be audited. 
  
`templates/site_query.j2`: Query executed when specifying the `--site_list` argument. It returns the firewalls that are in the specified Site(s) in Nautobot, that have a status of Active, and do not have a tag of `Auxillary`. 

`templates/region_query.j2`: Query executed when specifying the `--region_list` argument. It returns the firewalls that are in the specified Region(s), that have a status of Active, and do not have a tag of `Auxillary`.

> To use the existing queries as-is, you would need to create the Auxillary tag in Nautobot and assign it to one of the members of each HA pair

Finally, specify the `--use-nautobot` argument when running the program. 

## Usage
```bash
python audit.py --help
usage: audit.py [-h] (-n | -i INVENTORY_FILE) [-s LOCATION_LIST | -d DEVICE_LIST | -a] [-f FILE] [-v]

options:
  -h, --help            show this help message and exit
  -n, --use_nautobot    Use Nautobot for inventory
  -i INVENTORY_FILE, --inventory_file INVENTORY_FILE
                        Inventory filename
  -s LOCATION_LIST, --location_list LOCATION_LIST
                        Comma separated list of Nautobot Locations for selection of devices
  -d DEVICE_LIST, --device_list DEVICE_LIST
                        Comma separated list of Nautobot Devices
  -a, --all_devices     All Sophos firewalls in Nautobot
  -f FILE, --file FILE  Audit settings YAML file
  -v, --use_vault       Use HashiCorp Vault to retrieve credentials
```
Example:
```bash
python audit.py --inventory_file firewalls.yaml --use_vault -f audit_settings.yaml
```

## Viewing Results
Upon completion of each audit run, html files containing the results are generated. There are three options for local viewing and/or publishing the results. 
  
### Option 1: View Results Locally
Upon completion of each audit run, the results are stored in the `results_html` directory. In this directory, the `index.html` contains hyperlinks to browse the results as files in a web browser. Simply open the `index.html` file in a web browser. Each time the audit is run, the `index.html` file is updated with a new hyperlink for the new results. 

### Option 2: Share using a Docker container
Results are also stored in the directory `docker/results_html`, but in this case the hyperlinks are configured for use with a web server. A Docker container can be built that runs a lightweight web proxy (NGINX) to serve the files over HTTPS. Follow the below steps to build and run the container:

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
docker build . -t firewall-audit --platform=linux/amd64
```

3. Run the container
```bash
docker run --rm -d -p 8443:8443 -v $(pwd)/results_html:/usr/share/nginx/html firewall-audit
```
> Make sure to be in the `docker` directory when running this, otherwise the wrong results_html folder will get mounted into the container and the links will not work.

The container should now be available on the local host using `https://localhost:8443`. It should also be accessible from other hosts on the network using `https://<hostname_or_ip>:8443`. 

> The reason for using port 8443 instead of 443 here is because some systems require elevated privileges to open ports < 1024

### Deploy to Kubernetes
The container can also be deployed on a Kubernetes cluster. To accomplish this, the container must be built using Docker and pushed to a container registry that is accessible to the cluster. The `values.yaml` file must be updated with the parameters for your deployment, and then the container can be created in Kubernetes using the included Helm chart. The below example uses Amazon ECR (Elastic Compute Registry) to store the container image in a registry named `fwaudit-results`. 

1. Build the container
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

> Using this option, the `results_html` directory is copied into the container with the current contents. It will not automatically pick up the latest results when running a new audit. To accomplish that, the container must be re-built each time a new audit is run and pushed to the container registry. The container can then be updated in Kubernetes using `helm upgrade . -f values.yaml`.  Consider using [Sophos Factory](https://www.sophos.com/en-us/products/sophos-factory) to create an automated pipeline to run the audit periodically and update the container.  