## **CloudSOC-OpenSource**
created by - https://www.linkedin.com/in/saibatchu/

CloudSOC-OpenSource is a project designed for security analysts and SOC (Security Operations Center) professionals interested in implementing and exploring a modern CloudSOC architecture using open-source tools. The project is ongoing, with continuous updates and new additions to the repository.

### Key Use Cases of CloudSOC-OpenSource:

1. **Data Collection**:
    - Aggregates cloud and on-premises data into a single platform for unified analysis.
2. **Data Normalization and Parsing**:
    - Normalizes and parses the collected data to standardize various data formats, making it easier to analyze and compare.
3. **Data Visualization and Security Analytics**:
    - Visualizes normalized data to provide insightful security analytics, helping analysts understand and interpret security events.
4. **Incident and Case Management**:
    - Automates the creation of incidents or cases from security alerts detected in the collected data or logs, facilitating quicker response and investigation.
5. **Threat Intelligence Integration**:
    - Enhances data analysis with enrichment from open-source threat intelligence platforms, providing additional context and improving threat detection capabilities.
6. **Automation of SOC Processes**:
    - Automates threat hunting processes, creation of actionable playbooks, and SOC data analytics to improve efficiency and reduce manual workloads.

The project aims to empower SOC teams to leverage open-source tools effectively for comprehensive threat detection, response, and security management.

### Step-by-Step Instructions

1. **Clone the Repository on All EC2 Instances:**

- Connect to each EC2 instance.
- Clone the repository by running:
    
    ```bash
    git clone https://github.com/saidhfm/Cloud-Threat-Detection-Lab.git
    ```
    

2. **Install Dependencies on All EC2 Instances:**

- Run the script to install dependencies:
    
    ```bash
      cd Cloud-Threat-Detection-Lab/
     chmod +x elastic-container.sh
     ./elastic-container.sh start
    ```
    
- This will set up all necessary tools and configurations for the environment.

3. **Deploy Elasticsearch, Kibana, and Fleet Server:**

- **Connect to the Instance**:
    - SSH into the EC2 instance designated for ELK.
- **Modify the `.env` File**:
    - Locate the `.env` file in the ELK setup directory.
    - Change the first two lines to reflect the **public IP** of your ELK instance.
    - Adjust the **password** setting as needed.
    - Update memory settings (`MEM_LIMIT`) based on the available host memory. For example:
        
        ```bash
        MEM_LIMIT=8147483648  # Adjust this value according to your host memory
        By default its 2147483648 in bytes
        ```
        
- **Start the Elastic Stack**:
    - Run the command to start Elasticsearch, Kibana, and Fleet Server:
        
        ```bash
        
        ./elastic-container.sh start
        ```
        
    - Alternatively, use:
        
        ```bash
        bash elastic-container.sh start
        ```
        

### 4. **Troubleshooting Steps:**

- **Delete All Containers and Volumes**:
    - If you need to reset the environment, use the following commands to stop and remove all Docker containers and prune volumes:
        
        ```bash
        docker stop $(docker ps -q) && docker rm $(docker ps -a -q) && docker volume prune -f
        ```
        
    - To remove all Docker volumes:
        
        ```bash
        docker volume ls -q | xargs docker volume rm
        ```
        
    - To remove Deployment:
        
        ```bash
        ./elastic-container.sh destroy
        ./elastic-container.sh -h for more option
        ```
        
- **View Logs for Elastic Agent**:
    - To access diagnostic logs for the Elastic Agent, run:
        
        ```bash
        sudo /opt/Elastic/Endpoint/elastic-endpoint diagnostics
        ```
        
    - Key configuration and log files for Elastic Agent:
        - Configuration: `/etc/elastic-agent/elastic-agent.yml`
        - Binary location: `/usr/share/elastic-agent/bin/elastic-agent`
        - Data directory: `/var/lib/elastic-agent/data/elastic-agent-8.14.1-1348b9/elastic-agent`

### 5. **Access Kibana:**

- Open your browser and navigate to:
    
    ```arduino
    https://<public_ip>:5601
    ```
    
- **Configure Fleet Settings**:
    - Go to **Management** -> **Fleet** -> **Settings**.
    - Ensure both input and output URLs are set to:
        
        ```perl
        https://<private_ip>:8200, https://<private_ip>:9200
        ```
        
    - By default you should see same private IP for both URLs.

By following these steps, you should successfully deploy Elasticsearch, Kibana, and Fleet Server, and be able to manage your ELK stack effectively. Make sure to follow the troubleshooting steps if you encounter any issues during deployment.

**Deploying Elastic Defend EDR  using fleet agent:**

1. **Create an Agent Policy in Elastic Fleet:**

- Go to **Fleet** and create a new **Agent Policy**. Give it a name and create it.

2. **Add Elastic Defend to the Agent Policy:**

- Go to the newly created **Agent Policy**.
- Add **Elastic Defend EDR** as an integration.
- Provide a name for the integration and save it.

3. **Deploy Elastic Agent on Windows:**

- Go to the **Agent** section in Elastic.
- Click **Add Agent** and select the policy you just created.
- Copy the command for Windows deployment.
- On the Windows VM, open **PowerShell** as an administrator.
- Navigate to the **Downloads** folder and run the commands one by one.
- If there are errors, download the agent manually, unzip it, and then run the enrollment command.

4. **Deploy Elastic Agent on Linux:**
- Go to the **Agent** section in Elastic.
- Click **Add Agent** and select the policy you just created.
- Copy the command for Linux deployment.
- Run the commands on the linux host.
    
    ```bash
    
    curl -L -O https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-8.14.1-amd64.deb
    
    ```
    
- Install the Elastic Agent:
    
    ```bash
    
    sudo dpkg -i elastic-agent-8.14.1-amd64.deb
    sudo systemctl enable elastic-agent
    sudo systemctl start elastic-agent
    
    ```
    
- Enroll the agent with the following command (using `-insecure` to disable TLS verification):
    
    ```bash
    
    sudo elastic-agent enroll --url=https://<private-ip>:8220 --enrollment-token=<enrollment-token> --insecure
    
    ```
    
### **Note:**

- Using `-insecure` means you are sending logs without TLS encryption, which is essential for insecure connections.

### CSPM Integration with ELK (Cloud Security Posture Management)

1. **Set Up CSPM Integration:**

- Create a **CSPM policy** in AWS.
- Add the CSPM integration to ELK.

2. **Manual Deployment of CSPM Integration:**

- Create an EC2 instance and attach a role with the following name:
    - **Role Name:** `cloudbeat-securityaudit`
- **Permissions Policy** for the role:
    - Attach the `SecurityAudit` policy.
- **Trust Policy** for the role:
    
    ```json
    
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Principal": {
            "AWS": "arn:aws:iam::accountid:root/anyuser"
          },
          "Action": "sts:AssumeRole"
        },
        {
          "Effect": "Allow",
          "Principal": {
            "AWS": "arn:aws:iam::accountid:role/cloudbeat-securityaudit"
          },
          "Action": "sts:AssumeRole"
        },
        {
          "Effect": "Allow",
          "Principal": {
            "Service": "ec2.amazonaws.com"
          },
          "Action": "sts:AssumeRole"
        }
      ]
    }
    
    ```
    

Deploy the agent to the instance

### AWS CloudTrail Logs to ELK Integration

Send cloudtrail logs to a S3 bucket and configure S3 bucket event notifications to actions you wish to a SQS Queue, use below configuration for SQS

1. **IAM Policy for SQS and S3 Integration:**

- Create a policy to allow S3 to send messages to SQS:
    
    ```json
    
    {
      "Version": "2012-10-17",
      "Id": "example-ID",
      "Statement": [
        {
          "Sid": "example-statement-ID",
          "Effect": "Allow",
          "Principal": {
            "Service": "s3.amazonaws.com"
          },
          "Action": "SQS:SendMessage",
          "Resource": "arn:aws:sqs:us-east-1:accountid:myqueue",
          "Condition": {
            "StringEquals": {
              "aws:SourceAccount": "accountid"
            },
            "ArnLike": {
              "aws:SourceArn": "arn:aws:s3:::aws-cloudtraillogs-accountid-245a3a85"
            }
          }
        }
      ]
    }
    
    ```
    
- This policy allows AWS CloudTrail logs to be sent to an SQS queue from an S3 bucket. similarly you can also send ELB,VPC Flow logs as well using SQS
- Deploy the agent to the instance

By following these steps, you will successfully configure AWS cloudtrail logs to flow into ELK.

### Sending VPC Flow Logs to Elasticsearch using CloudWatch

To send VPC flow logs to Elasticsearch using CloudWatch, follow these steps:

1. **Create a VPC Flow Log**:
    - Go to your VPC dashboard in the AWS Management Console.
    - Click on **Actions** and select **Create flow log**.
    - Provide a name for the flow log (e.g., `vpc-log`).
2. **Configure Flow Log Settings**:
    - **Select Filter Type**: Choose one of the following:
        - **Accept**: Logs only accepted traffic.
        - **Reject**: Logs only rejected traffic.
        - **All**: Logs both accepted and rejected traffic (recommended for comprehensive monitoring).
    - **Set Maximum Aggregation Interval**: Select the aggregation interval:
        - **1 minute**: For detailed, real-time monitoring.
        - **10 minutes**: For less frequent logging with reduced storage costs.
3. **Choose Log Destination**:
    - Select **Send to CloudWatch Logs** to enable searching and analyzing logs in real-time.
4. **Create a CloudWatch Logs Group**:
    - Navigate to **CloudWatch** > **Logs** > **Log groups**.
    - Click **Create log group** and name it (e.g., `vpcflow-logs`).
    - Set a retention period (e.g., 1 month).
5. **Set Up Permissions for VPC Flow Logs**:
    - Return to the VPC dashboard and refresh the **Destination log group** dropdown to select the newly created log group.
    - Click **Set up permissions** and **Create role**.
    - Choose **AWS service** with the use case **EC2**, skip adding permissions, and enter a role name (e.g., `vpcroleforcloudwatch`).
    - Click **Create role**.
6. **Add Permissions to the IAM Role**:
    - Search for the newly created role (`vpcroleforcloudwatch`).
    - Click **Add permissions** > **Create inline policy**.
    - Switch to the **JSON** tab and enter the following policy:
    
    ```json
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Action": [
            "logs:CreateLogGroup",
            "logs:CreateLogStream",
            "logs:PutLogEvents",
            "logs:DescribeLogGroups",
            "logs:DescribeLogStreams"
          ],
          "Resource": "*"
        }
      ]
    }
    
    ```
    
    - Name the policy `cloudwatchpolicy` and click **Create policy**.
7. **Update Trust Relationships**:
    - Go to the **Trust relationships** tab of the role (`vpcroleforcloudwatch`).
    - Click **Edit trust policy** and replace the content with:
    
    ```json
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Principal": {
            "Service": "vpc-flow-logs.amazonaws.com"
          },
          "Action": "sts:AssumeRole"
        }
      ]
    }
    
    ```
    
    - Click **Update policy**.
8. **Integrate with Fleet and Enable CloudWatch Logs**:
    - Copy the ARN of the CloudWatch log group where the VPC flow logs are sent.
    - Go to the Fleet agent policy for CloudLogs in your Elasticsearch instance.
    - Edit the AWS integration settings to enable CloudWatch logs for VPC flow logs.
    - Provide the ARN of the CloudWatch log group.

By following these steps, you'll successfully send VPC flow logs from AWS to Elasticsearch through CloudWatch, allowing for real-time log analysis and monitoring.

### Deploying MISP and Integrating with Elasticsearch for Threat Intelligence:

To deploy MISP (Malware Information Sharing Platform) and integrate it with Elasticsearch, follow these steps:

1. **Deploy MISP**:
    - Use the Docker file provided in the repository.
        
        use “docker compose -f misp.yml up -d” to deploy
        
    - Follow the instructions in the repository to ensure MISP is running correctly.
        
        #Source - https://github.com/NUKIB/misp/tree/main
        #change ports to 0.0.0.0 and base url to public ip
        
        #Access on publicip:80
        
2. **Obtain MISP API Key**:
    - Log in to the MISP web interface.
    - Navigate to **Sync Actions** > **Feeds**.
    - Click **Load default** to load the default feed configurations.
    - Select all feeds by checking the box next to them.
    - Enable the selected feeds and save the changes.
    - Go back to the MISP home page profile and generate a API key.
3. **Integrate MISP with Elasticsearch**:
    - Go to the Elasticsearch Fleet management console.
    - Create a new agent policy.
    - Add the MISP integration to this policy.
    - Provide the MISP URL and the API key obtained earlier.
4. **Deploy the Agent**:
    - Deploy the Elasticsearch agent on the same instance where MISP is hosted.
    - This will allow Elasticsearch to collect and analyze threat intelligence data from MISP.

By following these steps, you will have MISP deployed and integrated with Elasticsearch, enabling seamless data sharing and enhanced threat detection capabilities.
http://pip:8080

Below are the sample deployment where agents configured for each policy.

![image.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/eb6bc734-04fb-4aec-aff8-1f9952555e6b/b6e9d1f5-529b-4349-863e-7bd706adc4c8/image.png)

**To deploy and configure Cribl on the same instance as ELK (Elasticsearch, Logstash, Kibana):**

1. **Deploy Cribl**: Deploy Cribl on the ELK instance.
    
    Use “docker compose -f cribil.yml up -d” to deploy
    
2. **Access Cribl**: Open a web browser and go to `http://<public>:9000` to access Cribl's web interface.
3. **Configure Cribl Input**:
    - Navigate to **Sources** in Cribl.
    - Select **Elasticsearch** and click **Add New**.
    - Name the input `elastic-input-9200` and set the host to `0.0.0.0` and port to 9111.
    - Click **Save**.
4. **Configure Elasticsearch Output in fleet settings**:
    - In the Elasticsearch interface, go to **Fleet** > **Settings**.
    - In the **Outputs** section, add another URL: `http://<private_ip_of_elk>:9111`.
      ex:
        "host": "13.202.105.25",
        "port": 9997,
        "tls": false
    
    ![image.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/eb6bc734-04fb-4aec-aff8-1f9952555e6b/a2b56604-fd38-4b04-ab02-0e811587f3e0/image.png)
    

This setup allows Cribl to collect data from Elasticsearch and route it to the desired destinations.

**To deploy and configure Splunk to receive data from Cribl:**

1. **Deploy Splunk**: Deploy Splunk using container yaml in the repo on a instance. 
    
    “docker compose -f splunk.yml up -d”
    
2. **Configure Cribl Destination**:
    - In Cribl, navigate to **Destinations**.
    - Select **Add Destination** and choose **Splunk**.
    - Name the destination `splunkoutput`.
    - Set the IP to the public IP of the Splunk instance (`http://<public_ip_of_splunk>`). Leave the port unchanged.
    - Click **Save** to apply the configuration.
3. **Verify Data in Splunk**:
    - Open Splunk's web interface and use the search query  *``check for incoming data from Cribl. Access on [http://PIP:8000/](http://3.135.238.39:8000/)

This setup configures Cribl to send logs or data to Splunk, allowing for centralized log management and analysis.

**To integrate New Relic with Cribl and send data from Cribl to New Relic:**

1. **Log in to New Relic**:
    - Log in to your New Relic account.
    - Go to **Add Integrations**.
    - Skip the initial prompts if necessary.
    - On the right side of the page, generate a **license key** and copy it.
2. **Configure Cribl Destination for New Relic**:
    - In Cribl, go to **Destinations**.
    - Click on **Add Destination** and choose **NewRelic-Events**.
    - Set the **Output ID** to `newrelicoutput`.
    - In the **API Key** field, paste the copied New Relic license key.
    - For the **Account ID**, you can find this in the URL of your New Relic dashboard.
    - Set the **Event Type** to `endpointlogs`.
    - Click **Next** and then **Save** to complete the configuration.
3. **Usage Note**:
    - New Relic offers 100GB of free data ingestion per month, so you can monitor your data usage accordingly. Access on http://[pip]:9000

This setup allows Cribl to send events and logs to New Relic for monitoring and analysis.

**Contributing**

We welcome your contributions. Please feel free to fork the code, play with it, make some patches and send us pull requests.

**Enhancements:**

- We will keep on updating this repo with the new implementation.

**Issues**

- Please [open an issue on GitHub]([https://github.com/saidhfm/Cloud-Threat-Detection-Lab-AWS/issues]](https://github.com/saidhfm/Cloud-Threat-Detection-Lab-AWS/issues)
  if you'd like to report a bug or request a feature.
  


References:

https://github.com/peasead/elastic-container,
https://github.com/NUKIB/misp/tree/main,
https://github.com/sakshamtushar/thor-detection-lab

