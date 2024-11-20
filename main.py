from fastapi import FastAPI, HTTPException, Depends, status
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel
from typing import Optional
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import JWTError, jwt
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import os
from typing import List
from bson import ObjectId  # For working with MongoDB ObjectIds
from pydantic import Field
from fastapi.middleware.cors import CORSMiddleware


# Load environment variables
app = FastAPI()
# MongoDB connection setup
client = AsyncIOMotorClient("mongodb://localhost:27017")
db = client.IUDelivery
users_collection = db.users



db2 = client.IUDelivery
orders_collection = db2.orders

# Pydantic model for Dish
class Dish(BaseModel):
    id: int
    name: str
    quantity: int

# Pydantic model for User
class User(BaseModel):
    name: str
    latitude: float  # Accept float values for more precision
    longitude: float


class UpdateOrderStatus(BaseModel):
    order_id: str
    status: str


# Pydantic model for Order (includes User model)
class Order(BaseModel):
    _id: Optional[str] = None  # Optional _id field
    eatery_id: int
    eatery_name: str
    dishes: List[Dish]  # List of dishes in the order
    user: User  # Embedded User object with name and location
    status: str
    deliveryPerson: Optional[str] = None

# POST request to create a new order with user location
@app.post("/orders", status_code=status.HTTP_201_CREATED)
async def create_order(order: Order):
    try:
        # Convert Pydantic model to dictionary, excluding 'id' (if it exists)
        order_dict = order.dict()

        # Insert the order into MongoDB
        result = await orders_collection.insert_one(order_dict)

        # Return the inserted order ID
        return {"message": "Order placed successfully", "order_id": str(result.inserted_id)}
    except Exception as e:
        print(f"Error inserting order: {e}")  # Log the error for debugging
        raise HTTPException(status_code=500, detail="Failed to place the order.")


from fastapi import Body


@app.get("/orders/{order_id}/getstatus")
async def get_order_status(order_id: str):
    try:
        # Find the order by its ID
        order = await orders_collection.find_one({"_id": ObjectId(order_id)})

        # If the order doesn't exist, raise a 404 error
        if not order:
            raise HTTPException(status_code=404, detail="Order not found")

        # Return the order status
        return {
            "status": order.get("status"),
            "deliveryPerson": order.get("deliveryPerson")
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))




@app.put("/orders/{order_id}/status")
async def update_order_status(order_id: str, status: str = Body(..., embed=True), deliveryPerson: str = Body(..., embed=True)):
    print("OrderId", order_id)
    try:
        # Validate if the order_id is a valid ObjectId
        if not ObjectId.is_valid(order_id):
            raise HTTPException(status_code=400, detail="Invalid order ID")

        # Update the order status and deliveryPerson in the database
        result = await orders_collection.update_one(
            {"_id": ObjectId(order_id)},
            {"$set": {"status": status, "deliveryPerson": deliveryPerson}}  # Combine in a single $set
        )

        # Check if the order was found and updated
        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="Order not found")

        return {"message": f"Order {order_id} status updated to {status} and assigned to {deliveryPerson}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/orders/notpicked", response_model=List[dict])
async def get_not_picked_orders():
    try:
        # Query MongoDB for orders with "NotPicked" status
        orders_cursor = orders_collection.find({"status": "NotPicked"})
        orders = []

        async for order in orders_cursor:
            # Convert ObjectId to string for JSON serialization
            order["orderId"] = str(order["_id"])  # Add orderId field
            order["_id"] = str(order["_id"])  # Ensure _id is also a string
            orders.append(order)  # Add the order to the list

        print(orders)  # Debug: Print orders
        return orders  # Return the list of orders
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/orders/by-user/{user_name}", response_model=List[Order])
async def get_orders_by_user(user_name: str):
    try:
        # Query orders by user name
        orders_cursor = orders_collection.find({"user.name": user_name})
        orders = []

        async for order in orders_cursor:
            order["order_id"] = str(order["_id"])  # Convert ObjectId to string
            orders.append(order)

        if not orders:
            raise HTTPException(status_code=404, detail="No orders found for this user")

        return orders
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# FastAPI app instance
# Security and password hashing setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# JWT configuration
SECRET_KEY = "supersecretkey123"  # Replace with a strong random string
ALGORITHM = "HS256"               # Recommended algorithm for JWT
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # Token valid for 30 minutes


# User model for signup
class UserCreate(BaseModel):
    username: str
    password: str

# User model for database retrieval
class UserInDB(BaseModel):
    username: str
    hashed_password: str

# Token model
class Token(BaseModel):
    access_token: str
    token_type: str

# Token data model
class TokenData(BaseModel):
    username: Optional[str] = None

# Helper function to hash passwords
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

# Helper function to verify passwords
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

# Helper function to create JWT token
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Signup route
@app.post("/signup", status_code=status.HTTP_201_CREATED)
async def signup(user: UserCreate):
    # Check if user already exists
    existing_user = await users_collection.find_one({"username": user.username})
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")

    # Hash the password and store user in the database
    hashed_password = hash_password(user.password)
    user_dict = {"username": user.username, "hashed_password": hashed_password}
    await users_collection.insert_one(user_dict)
    return {"message": "User registered successfully"}

# Login route
@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    # Retrieve user from database
    user = await users_collection.find_one({"username": form_data.username})
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Create JWT token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# Protected route to test authentication
@app.get("/users/me")
async def read_users_me(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid authentication")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication")

    return {"username": username}


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins, adjust as needed for security
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Run the FastAPI app
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
