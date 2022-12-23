from dotenv import dotenv_values
from os import environ

config = {
    **dotenv_values(".env"),
    **environ
    
}