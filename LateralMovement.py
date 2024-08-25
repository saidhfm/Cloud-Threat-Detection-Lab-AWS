import boto3

def send_ssh_public_key(instance_id, instance_os_user, availability_zone, ssh_public_key_file, region):
    try:
        ec2_instance_connect_client = boto3.client('ec2-instance-connect', region_name=region)
        response = ec2_instance_connect_client.send_ssh_public_key(
            InstanceId=instance_id,
            InstanceOSUser=instance_os_user,
            AvailabilityZone=availability_zone,
            SSHPublicKey=open(ssh_public_key_file).read()
        )
        print(f"SSH public key sent successfully to instance {instance_id} ({instance_os_user} user).")
        print("Response:", response)
    except Exception as e:
        print(f"Failed to send SSH public key to instance {instance_id}: {e}")

if __name__ == '__main__':
    instance_id = 'i-098029b66ac7b3c4'  # Replace with your EC2 instance ID
    instance_os_user = 'ubuntu'  # Replace with the appropriate OS user
    availability_zone = 'us-east-1e'  # Replace with the availability zone of your instance
    ssh_public_key_file = '/path/to/id_rsa.pub'  # Replace with the actual path to your SSH public key file
    region = 'us-east-1'  # Replace with your AWS region

    send_ssh_public_key(instance_id, instance_os_user, availability_zone, ssh_public_key_file, region)
