import boto3

def lambda_handler(event, context):
    # Nombre del bucket y la clave del objeto
    bucket_name = 'predictia-pdf'
    key = 'Estrategia-venta.pdf'
    key2 = 'Orden-compra.pdf'

    # Inicializar el cliente de S3
    s3_client = boto3.client('s3')

    # Generar la URL firmada con una expiración de 5 minutos
    url = s3_client.generate_presigned_url(
        ClientMethod='get_object',
        Params={'Bucket': bucket_name, 'Key': key},
        ExpiresIn=300,  # La URL expirará en 5 minutos (300 segundos)
        # Agregar los parámetros de consulta necesarios
        # Aquí necesitarías agregar los parámetros que se necesiten, como response-content-disposition, X-Amz-Security-Token, etc.
    )
    
    url2 = s3_client.generate_presigned_url(
        ClientMethod='get_object',
        Params={'Bucket': bucket_name, 'Key': key2},
        ExpiresIn=7200,  # La URL expirará en 2 hrs
        # Agregar los parámetros de consulta necesarios
        # Aquí necesitarías agregar los parámetros que se necesiten, como response-content-disposition, X-Amz-Security-Token, etc.
    )

    return {
        'statusCode': 200,
        'body': { 
            'Estrategia-venta' : url,
            'Orden-compra' : url2
            
        }
    }
