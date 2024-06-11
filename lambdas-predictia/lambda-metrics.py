import os
import boto3
import pandas as pd
from io import StringIO

# Initialize the S3 client
s3 = boto3.client('s3')

def lambda_handler(event, context):
    bucket_name = os.getenv("BUCKET_NAME")  # Change this to your bucket name
    file_key = 'forecast_mape_bias.csv'  # Change this to your file path in S3

    # Get the file from S3
    try:
        response = s3.get_object(Bucket=bucket_name, Key=file_key)
        file_content = response['Body'].read().decode('utf-8')

        # Use pandas to read the CSV file
        data = pd.read_csv(StringIO(file_content))

        # Calculate averages
        average_mape = data['mape'].mean()
        average_bias = data['bias'].mean()

        # Prepare the JSON data
        json_data = {
            "mape_values_by_month": data.set_index('ds')['mape'].to_dict(),
            "bias_values_by_month": data.set_index('ds')['bias'].to_dict(),
            "average_mape": average_mape,
            "average_bias": average_bias
        }
        return json_data
    except Exception as e:
        raise f"Error: {e}"
