from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import User, Category, Structure, Base

engine = create_engine('sqlite:///structures.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()

# Create dummy user
User1 = User(name="Sara Vagnarelli", email="eng.saravagnarelli@gmail.com",
             picture='')
session.add(User1)
session.commit()

category1 = Category(user_id=1, name="Villa")
session.add(category1)
session.commit()

category2 = Category(user_id=1, name="Studio")
session.add(category2)
session.commit()

category3 = Category(user_id=1, name="Apartment")
session.add(category3)
session.commit()

category4 = Category(user_id=1, name="Room")
session.add(category4)
session.commit()

print "added categories!"
