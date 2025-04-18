from pymongo import mongo_client, MongoClient

db = MongoClient("mongo",27017)["notsus"]

users = db["users"]