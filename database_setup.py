import os
import sys
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
 
Base = declarative_base()

class User(Base):
    __tablename__ = 'user'

    id = Column(Integer,primary_key = True)
    username = Column(String(250), nullable = False)
    password = Column(String(250), nullable = False)

class Products(Base):
    __tablename__ = 'products'

    id = Column(Integer, primary_key = True)
    name = Column(String(250), nullable = False)
    category = Column(String(250), nullable = False)
    thits = Column(Integer, nullable = False)
    uhits = Column(Integer, nullable = False)

class Hits(Base):
    __tablename__ = 'hits'

    id = Column(Integer, primary_key = True)
    pid = Column(Integer, ForeignKey('products.id'))
    uid = Column(Integer, ForeignKey('user.id'))

engine = create_engine('sqlite:///database.db')
Base.metadata.create_all(engine)