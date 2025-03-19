from pymongo import MongoClient

uri = "mongodb+srv://parimala:Parimala@cluster0.nigrjnx.mongodb.net/WomanEmployment?retryWrites=true&w=majority&appName=Cluster0"

client = MongoClient(uri)
db = client["WomanEmployment"]  # Connect to the database
orders_collection = db["orders"]  # Connect to the 'orders' collection

orders = {
    "userName": "Parimala123",
    "orders": [
        {
            "id": 1235,
            "date": "2023-09-22",
            "items": 1,
            "total": 850,
            "status": "Processing",
            "seller_name": "Lakshmi Crafts"
        },
        {
            "id": 1238,
            "date": "2023-12-01",
            "items": 3,
            "total": 1900,
            "status": "Delivered",
            "seller_name": "Lakshmi Crafts"
        },
        {
            "id": 1241,
            "date": "2024-02-15",
            "items": 2,
            "total": 1450,
            "status": "Shipped",
            "seller_name": "Lakshmi Crafts"
        }
    ]
}

# Insert single document
result = orders_collection.insert_one(orders)
print(f"Inserted document ID: {result.inserted_id}")
