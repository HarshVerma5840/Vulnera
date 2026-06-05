from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, Float, DateTime, Text
from datetime import datetime

Base=declarative_base()

class NmapHistory(Base):

    __tablename__="nmaphistory"

    id = Column(Integer, primary_key=True, index=True)
    target = Column(String, index=True)
    scan_date = Column(DateTime, default=datetime.utcnow)
    result = Column(Text)
    status = Column(String)

class ZapHistory(Base):

    __tablename__="zaphistory"

    id = Column(Integer, primary_key=True, index=True)
    target = Column(String, index=True)
    scan_date = Column(DateTime, default=datetime.utcnow)
    result = Column(Text)
    status = Column(String)
