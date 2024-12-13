from pymongo import AsyncMongoClient
import os

uri = os.getenv("MONGO_URI", "mongodb+srv://ankit:f71vuRSztkRNBgsd@cluster0.r2wy8.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")

client = AsyncMongoClient(uri)
database = client.get_database('auth')
user_collection = database.get_collection('users')