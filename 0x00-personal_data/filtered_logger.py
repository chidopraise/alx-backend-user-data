#!/usr/bin/env python3
"""
RedactingFormatter and Database Connection
"""
import re
from typing import List
import logging
import mysql.connector
import os

PII_FIELDS = ("name", "email", "phone", "ssn", "password")


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = "; "

    def __init__(self, fields: List[str]):
        """ Initialize RedactingFormatter """
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """ Format the log record and redact sensitive information """
        msg = super(RedactingFormatter, self).format(record)
        return filter_datum(self.fields, self.REDACTION, msg, self.SEPARATOR)


def filter_datum(fields: List[str], redaction: str, message: str, separator: str) -> str:
    """ Return the log message with sensitive data redacted """
    for field in fields:
        message = re.sub(rf'{field}=[^;]*', f'{field}={redaction}', message)
    return message


def get_logger() -> logging.Logger:
    """ Create a logger object configured for redacting sensitive information """
    logger = logging.getLogger('user_data')
    logger.setLevel(logging.INFO)
    logger.propagate = False
    handler = logging.StreamHandler()
    handler.setLevel(logging.INFO)
    formatter = RedactingFormatter(list(PII_FIELDS))
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """ Connect to the database using environment variables and return the connection object """
    return mysql.connector.connect(
        user=os.getenv('PERSONAL_DATA_DB_USERNAME', 'root'),
        password=os.getenv('PERSONAL_DATA_DB_PASSWORD', ''),
        host=os.getenv('PERSONAL_DATA_DB_HOST', 'localhost'),
        database=os.getenv('PERSONAL_DATA_DB_NAME')
    )


def main():
    """ Main entry point for the script """
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users;")
    logger = get_logger()
    for row in cursor:
        msg = "name={}; email={}; phone={}; ssn={}; password={}; ip={}; last_login={}; user_agent={};".format(
            row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7]
        )
        logger.info(msg)
    cursor.close()
    db.close()


if __name__ == '__main__':
    main()
