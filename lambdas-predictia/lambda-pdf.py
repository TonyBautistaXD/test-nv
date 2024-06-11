import paramiko
import boto3
import time

def lambda_handler(event, context):
    print("Creating ec2 resource")
    ec2 = boto3.resource('ec2', region_name='us-east-1')

    instance_id = 'idxxxx'

    instance = ec2.Instance(instance_id)
    print("Starting instance")
    # Start the instance
    #instance.start()

    # Giving some time to start the instance completely
    #time.sleep(60)

    # Print few details of the instance
    print("Instance id - ", instance.id)
    print("Instance public IP - ", instance.public_ip_address)
    print("Instance private IP - ", instance.private_ip_address)
    print("Public dns name - ", instance.public_dns_name)
    print("----------------------------------------------------")

    # Connect to S3, we will use it get the pem key file of your ec2 instance
    s3_client = boto3.client('s3')
    print("Downloading pem")
    # Download private key file from secure S3 bucket
    # and save it inside /tmp/ folder of lambda event
    s3_client.download_file('predictia-secure', 'predictia.pem',
                            '/tmp/keyname.pem')

    # Allowing few seconds for the download to complete
    time.sleep(20)
    print("SSH Connection...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    privkey = paramiko.RSAKey.from_private_key_file('/tmp/keyname.pem')
    ssh.connect(
        instance.public_dns_name, username='ubuntu', pkey=privkey
    )

    # Sending the command but not waiting for it to finish
    ssh.exec_command('nohup python3 create_pdf.py > /dev/null 2>&1 &')
    print("Command sent, not waiting for it to finish.")

    ssh.close()

    # Stop the instance
    # instance.stop()
