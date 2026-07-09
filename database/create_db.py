from database import create_database
import models   # Import models so SQLAlchemy knows about them

create_database()

print("Database created successfully!")