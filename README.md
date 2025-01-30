# Ignite Global Gifted Child Art Show
a cool website for the ignite global gifted child art show - an online art competition for young gifted artists.

check it out at [https://ignite-global.org](https://ignite-global.org); maybe even submit some artwork?

made with flask, mongodb, typesense, and bootstrap 5

## Running locally
This project requires you to have:
- a MongoDB instance running locally. You can install MongoDB [here](https://www.mongodb.com/try/download/community).
- a Typesense instance running locally. You can install Typesense [here](https://typesense.org/docs/guide/install-typesense.html).
- an AWS S3 bucket for storing images. You can create an AWS account [here](https://aws.amazon.com/).
- Python 3.12 or higher (untested but may work with lower versions)

To run the project locally, follow these steps:
1. Clone the repository
2. Install the required Python packages by running `pip install -r requirements.txt`
3. Set the following environment variables:
    - `AWS_BUCKET_NAME`: the name of the AWS S3 bucket
    - `AWS_ACCESS_KEY_ID`: the AWS access key ID
    - `AWS_SECRET_ACCESS_KEY`: the AWS secret access key
    - `ADMIN_USERNAME`: the username for the admin account
    - `DB_URI`: the URI for the MongoDB instance
    - `SECRET_KEY`: a secret key for the Flask app
    - `TYPESENSE_API_KEY`: the API key for the Typesense instance