from pymongo import mongo_client, MongoClient

db = MongoClient("localhost")["notsus"]

users = db["users"]