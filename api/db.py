from pymongo import mongo_client, MongoClient

db = MongoClient("mongo",27017)["notsus"]

users = db["users"]
lobbies_collection = db["lobbies"]
lobbies_collection.create_index(
    "createdAt",
    expireAfterSeconds=3600
)