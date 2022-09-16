#####################################################################################################################################
#                                                                                                                                   #
#                                                                APIs VERSION 2.0                                                   #
#                                                                   based on                                                        #
#                                               Flask, PostgreSQL and Elasticsearch  https://www.elastic.co                         #
#                                                                                                                                   #
#####################################################################################################################################

from urllib import response
import elasticsearch
from flask import Flask, jsonify, request, send_file, current_app, safe_join, send_file
from flask_jwt_extended import ( JWTManager, jwt_required, create_access_token, get_jwt_identity )
import psycopg2
import os
import json
import time
import redis
import datetime
import re
import hashlib
import base64
import logging
from elasticsearch import Elasticsearch,helpers
import flask
import subprocess
import dateutil.parser
from datetime import timedelta
from collections import defaultdict
import operator
import requests
from bs4 import BeautifulSoup
import cssutils
import random
from pathlib import Path
import csv
from datetime import timezone
import concurrent.futures
import cryptocode
import ast
import hmac
from functools import wraps
# custom imports
from colors import colors
from main_db_conf import database_name, database_username, database_password, host_name, db_port, elastichost
from check_private_or_group import check_private_or_group_v001
from category_list import category_list
from username_validator import Scraper_facade
from requests.auth import HTTPBasicAuth
from dateutil.parser import *

######################################################################
# SEARCH ENGINE CREDENTIALS IMPORT
from credconfig import gkey, seid, gmail_password, gmail_account 
######################################################################

from db_table_fresh import create_clients_database

# CORS for Front end
from flask_cors import CORS
from flask_cors import CORS,cross_origin
from flask_mail import Mail, Message
######  END OF IMPORTS ##############################################################

# create clients database if not exists
try:
    print(f"{colors.green} Trying to create client_database {colors.default}")
    create_clients_database()
except Exception as e:
    print(f"{colors.orange} Looks like database already exists. If signing up does not work, please check the db_table_fresh.py script. {colors.default}", e)


app = Flask(__name__,template_folder='./templates/build',static_folder="./templates/build/static")
#logging.basicConfig(filename='flask_app.log', level=logging.DEBUG)

###############################################################################################################
# JWT CONFIGURATION
# For more configurations https://flask-jwt-extended.readthedocs.io/en/stable/options/#configuration-options 
#

app.config['JWT_SECRET_KEY'] = '@Tesseract_test_secret_uSiNg_python369' 
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 6 * 60 * 60  # set for 6 hours expiry, the user will have to log in again after expiry of token, keep False for no-expiration
jwt = JWTManager(app)

# Flask mail Configuration setup for Sender's Email 
# import from credconfig.py file
app.config['MAIL_SERVER'] = 'imap.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = gmail_account #must change email
app.config['MAIL_PASSWORD'] = gmail_password # paste plaintext app-password here [ to be created from Gsuite administrator account ]
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config["CORS_HEADERS"] = "Content-Type"


"""
all index names
Indices onlineusers and uncategorized not mentioned here
"""

all_index_name =  ["telegram2_alias",
"financials_alias",
"extremepolitical2_alias",
"religion_spirituality_alias",
"pharma_drugs_alias",
"criminal_activities_alias",
"information_technology_alias",
"cyber_security_alias",
"science_index_alias",
"betting_gambling_alias",
"adult_content_alias",
"blogs_vlogs_alias",
"education_alias",
"movies_alias",
"travelling_alias",
"gaming_alias",
"lifestyle_alias",
"music_alias",
"books_comics_alias",
"fashion_beauty_alias",
"design_arch_alias",
"humor_entertainment_alias",
"culture_events_alias"]

mail = Mail(app)

# darkowl config
publicKey = 'm3y1893nrGW9h9f/cN/27Q==' #'PUBKEY_HERE'
privateKey = 'pq9rv+v5LT++mHKi1YR74UDcI4xZsSNAuLD6AugBGVI=' #'PRIVKEY_HERE'



# Set a callback function to return a custom response whenever an expired
# token attempts to access a protected route. This particular callback function
# takes the jwt_header and jwt_payload as arguments, and must return a Flask
# response. Check the API documentation to see the required argument and return
# values for other callback functions.
@jwt.expired_token_loader
def my_expired_token_callback():
    return jsonify({"tokenerror":"The token has expired. Please generate a new token again."}), 408


########## Variables
REINDEXING_FOR_UPDATE = False
# search_logging = True
AUTOCRED_ACCOUNT_PREFIX = 'TI2020'
COMPANY_EMAIL = 'tesseract@tesseractintelligence.com'

###CORS Setup
CORS(app, resources={r"/*": {"origins": "*"}})

#########################################################################################################
# Function definitions here

def autocred_prefix_username_blocker(username):
    """
    Not letting usernames start with AUTOCRED_ACCOUNT_PREFIX
    """
    try:
        if username.startswith(str(AUTOCRED_ACCOUNT_PREFIX.lower())) == True or username.startswith(str(AUTOCRED_ACCOUNT_PREFIX)) == True:
            return jsonify({"errormsg":f"Your username can't start with {AUTOCRED_ACCOUNT_PREFIX} or {AUTOCRED_ACCOUNT_PREFIX.lower()}"}), 403 , {'Content-Type': 'application/json'}
    except Exception as e:
        return jsonify({"errormsg":f"Your username has issues we can't identify right now. Please contact us at {COMPANY_EMAIL}"}), 403 , {'Content-Type': 'application/json'}


def rate_limiter(current_user, channelsearch_ratelimit= False):
    
    """
    Rate Limit for customer accounts
    """
    
    # Connect to client_database and check for rate limits
    try:
        conn = psycopg2.connect(database= 'client_database' , user= database_username , password= database_password , host= host_name, port= db_port)
        conn.autocommit = True
        cursor = conn.cursor()
    except Exception as e:
        print(f"{colors.red} CLIENT_DATABASE CONNECTION FAILED. {e} {colors.default}")
        conn.close()
        return "Authentication server is not responding. Please contact your service provider immediately. ERROR CODE: RATELIMITERROUTINE."

    try:
        cursor.execute(f"SELECT username from client_database where username='{current_user}'")
        conn.commit()
        uname = cursor.fetchall()
        #print(uname[0][0])

        cursor.execute(f"""SELECT row_to_json(client_database) from client_database where username='{uname[0][0]}'""")
        conn.commit()
        details = cursor.fetchall()
        #print(details[0][0])

        date_of_record = details[0][0]['date']
        unlimited = details[0][0]['isunlimited']
        ratelimit = details[0][0]['ratelimit']
        channelsearch_num = details[0][0]['channelsearch_ratelimit']
        user_name = uname[0][0]
        
        print(f"{colors.yellow}Username:{colors.default}",user_name, f"\n{colors.yellow}Date: {colors.default}",date_of_record,  f"\n{colors.yellow}Unlimited Access: {colors.default}",unlimited, f"{colors.yellow}\nRate Limit: {colors.default}", ratelimit)

        if unlimited == 'True':
            pass
        else:
            if ratelimit >= 1: 
                # decrease the ratelimit by 1 in the database
                cursor.execute(f"""UPDATE client_database set ratelimit= {int(ratelimit)-1} where username='{user_name}'""")
                conn.commit()
                dtime = datetime.datetime.utcnow().isoformat() + "+00:00"
                rlogger = f"""{dtime}\t{user_name}\toldRL:{ratelimit}\tnewRL:{int(ratelimit)-1}\n"""
                
                with open("ratelimitlogs.txt","a", encoding="UTF-8") as rlgs:
                    rlgs.write(rlogger)

                if channelsearch_ratelimit == True or channelsearch_ratelimit == "True":
                    cursor.execute(f"""SELECT row_to_json(client_database) from client_database where username='{uname[0][0]}'""")
                    conn.commit()
                    resultant = cursor.fetchall()
                    channelsearch_ratelimit_number = resultant[0][0]['channelsearch_ratelimit']
                    cursor.execute(f"""UPDATE client_database set channelsearch_ratelimit= {int(channelsearch_ratelimit_number)-1} where username='{user_name}'""")
                    conn.commit()
                
                conn.close()
            
            else:
                if ratelimit == 0:
                    conn.close()
                    hrs = round( 86400 - (dateutil.parser.isoparse(datetime.datetime.utcnow().isoformat()+'+00:00') - dateutil.parser.isoparse(date_of_record)).seconds)

                    return jsonify({"errormsg":f"You have consumed your daily limit. Please contact your service provider to increase your daily limit, or please wait {hrs} seconds i.e about {round(hrs/60.0,3)} minutes, or {round(hrs/60.0/60.0,2)} hours for your next daily limit."}), 403,  {'Content-Type': 'application/json'}
        
        if channelsearch_ratelimit == True or channelsearch_ratelimit == "True":
            return ratelimit , channelsearch_num
        else:
            return ratelimit

    except Exception as e:
        print(e)




def check_tokens(jwt_all):

    """
    Function that checks if the token fed to the API is not older than the time of last password change.
    This is to avoid the old JWT tokens being used for authentication.s
    This function takes about 2-3ms to complete.
    """

    a = time.time()
    try:
        conn = psycopg2.connect(database= 'client_database' , user= database_username , password= database_password , host= host_name, port= db_port)
        conn.autocommit = True
        cursor = conn.cursor()

        cursor.execute(f"SELECT row_to_json(client_database) from client_database where username='{jwt_all[0]}';")
        conn.commit()
        uname = cursor.fetchall()
        
        last_password_time = uname[0][0]['password_updated_on']
        print(f"{colors.green}Last password update was on: {last_password_time}. This token was created at {jwt_all[1]} {colors.default}")

        if last_password_time != None:
            # was password changed after the token was created? if yes, block the request.
            timediff = dateutil.parser.isoparse(last_password_time) -  dateutil.parser.isoparse(jwt_all[1])
            print(f"Time difference is {timediff} ")

            days = timediff.days
            seconds = timediff.seconds
            microseconds = timediff.microseconds

            print(days, seconds, microseconds)

            print(timediff.total_seconds())
            
            if timediff.total_seconds() >= 0.001:
                print(f"time-taken: {time.time() -a }s.")
                conn.close()
                return {"errormsg":f"This token has expired because you have updated your password recently. If you have not changed your password recently, please contact us promptly."}, 403, {'Content-Type': 'application/json'}

    except Exception as e:
        print("Error", e)
        
        if 'minute must be in' in str(e) or 'second must be in' in str(e) or 'hour must be in' in str(e) or 'out of range' in str(e):
            conn.close()
            print(f"time-taken: {time.time() -a }s.")
            return {"errormsg":"Seconds/Minutes should be in 0-59, hour must be in 0-23. Check if your Year/Month/Days are out of range."}, 403, {'Content-Type': 'application/json'}
        else:
            conn.close()
            print(f"time-taken: {time.time() -a }s.")
            return {"errormsg":f"Date format is wrong. Please input correct date and try again. ServiceErrorCode: API_DEF_CHKTOKENS "}, 403, {'Content-Type': 'application/json'}

    return "successful"

def directory_checker(path_name):
    """
    Checks if a path exists
    """
    return Path(path_name).is_dir()


def index_creater(index_name):
    """
    Create a new index if no such index is present
    """
    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
    if es.indices.exists(index=index_name):
        print('index found')
        return True
    else:
        try:
            es.indices.create(index=index_name, ignore=400)
            return True
        except:
            return False



def index_hex_id_checker(hash_id):
    """
    Check if the hash_id is present in any of the index
    """
    try:
        es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
        if es.exists(index=all_index_name, id=hash_id):
            return False
        else:
            return True

    except Exception as e:
            return True



def folder_create():
    """
    checks folder exists or not for CSV reports, else creates
    """
    try:
        path_name = r'/root/csv_reports/'
        path_checker = directory_checker(path_name)
        
        if path_checker == False:
            os.mkdir(path_name)
        print(path_checker)
        
        return path_name

    # if folder exists with that name, ask another name
    except:
        print("Folder Exist with that name!")


def channel_id_adder(name, id):
    """
    Rename channel links
    """
    if name != 'None':
        if 't.me' in name:
            return f'{name}/{id}'
        else:
            return f'https://t.me/s/{name}/{id}'
    else:
        return 'No link'


def hashid_converter(data) -> str:
    """
    Calculates MD5 hash for message objects
    """
    hashid_data = str({'date': data['date'],
                                   'message': data['message'], 'msgid': data['msgid']})
    hashasid = hashlib.md5(hashid_data.encode('UTF-8')).hexdigest()
    return hashasid


def data_generator(index_name,data):
            for line in data:
                try:
                    source = line
                    hash_id = hashid_converter(line)
                    print(f'creating index for {hash_id}')
                    yield{
                        "_index": index_name,
                        "_type": '_doc',
                        "_id": hash_id,
                        "_source": source
                    }
                except:
                    pass

def user_data_generator(index_name,data):
    """
    Generates user-data structure
    """
    for line in data:
        try:
            source = line
            hashid_data = str({"userid": data["userid"], "username": data["username"],
                    "userfirstname": data["userfirstname"], "userlastname": data["userlastname"]})
            hashasid = hashlib.md5(hashid_data.encode('UTF-8')).hexdigest()
            print(f'creating index for {hashasid}')
            yield{
                "_index": index_name,
                "_type": '_doc',
                "_id": hashasid,
                "_source": source
            }
        except:
            pass
                

def channel_basic_stats(obj):
    """
    Produce Channel Statistics
    """
    
    print('object', obj['conv_name'])

    files = 'None'
    links = 'None'
    channel_type = ''
    subs = 'None'

    media = 'None'
    obj['participants_count'] = str(obj['participants_count'])
    
    if 'subscriber' in obj['participants_count']:
        aud_inf = json.loads(obj['participants_count'])
        print(aud_inf)
        channel_type = 'Channel'

        try:
            if 'files' in aud_inf:
                files = aud_inf[0]['files']
            else:
                files = aud_inf[0]['file']
        except:
            pass
        
        try:
            if 'links' in aud_inf:
                links = aud_inf[0]['links']
            else:
                links = aud_inf[0]['link']
        except:
            pass
        
        try:
            if 'subscribers' in aud_inf:
                subs = aud_inf[0]['subscribers']
            else:
                subs = aud_inf[0]['subscriber']

        except:
            pass
        
        try:
            if 'photos' and 'videos' in aud_inf[0]:
                print(aud_inf[0]['photos'], aud_inf[0]['videos'], 'photos')
                new_photo = aud_inf[0]['photos']
                if 'K' in aud_inf[0]['photos']:
                    new_photo = aud_inf[0]['photos'].replace(
                        '.', '').replace('K', '000')
                new_video = aud_inf[0]['videos']
                if 'K' in aud_inf[0]['videos']:
                    new_video = aud_inf[0]['videos'].replace(
                        '.', '').replace('K', '000')
                media = str(int(new_photo)+int(new_video))
            
            elif 'photo' and 'video' in aud_inf[0]:

                new_photo = aud_inf[0]['photo']
                if 'K' in aud_inf[0]['photo']:
                    new_photo = aud_inf[0]['photo'].replace(
                        '.', '').replace('K', '000')
                new_video = aud_inf[0]['video']
                if 'K' in aud_inf[0]['video']:
                    new_video = aud_inf[0]['video'].replace(
                        '.', '').replace('K', '000')
                media = str(int(new_photo)+int(new_video))
            
            elif 'photos' and 'video' in aud_inf[0]:
                new_photo = aud_inf[0]['photos']
                if 'K' in aud_inf[0]['photos']:
                    new_photo = aud_inf[0]['photos'].replace(
                        '.', '').replace('K', '000')
                new_video = aud_inf[0]['video']
                if 'K' in aud_inf[0]['video']:
                    new_video = aud_inf[0]['video'].replace(
                        '.', '').replace('K', '000')
                media = str(int(new_photo)+int(new_video))
            
            elif 'photo' and 'videos' in aud_inf[0]:
                new_photo = aud_inf[0]['photo']
                
                if 'K' in aud_inf[0]['photo']:
                    new_photo = aud_inf[0]['photo'].replace(
                        '.', '').replace('K', '000')
                new_video = aud_inf[0]['videos']
                
                if 'K' in aud_inf[0]['videos']:
                    new_video = aud_inf[0]['videos'].replace(
                        '.', '').replace('K', '000')
                media = str(int(new_photo)+int(new_video))

        except:
            pass
        # try:
        #     channel_type = obj['is_group']
        # except:
        #     pass
    else:
        es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
        if 'member' in obj['participants_count']:
            subs = obj['participants_count'].split(' ')[0]
            channel_type = 'Group'

        else:
            subs = obj['participants_count']
            if obj['is_group'] == 'True':
                channel_type = 'Group'
            else:
                channel_type = 'Channel'

        try:
            file_cnt = es.count(index=all_index_name, body={
                "query": {
                    "bool": {
                        "must": [
                            {
                                "match_phrase": {
                                    "conv_name": obj['conv_name']
                                }
                            },

                        ],
                        'must_not': [
                            {'match': {'filename': 'None'}}
                        ]
                    }
                }
            })
            files = file_cnt['count']

        except:
            pass
        
        
        try:
            regexp_cnt = es.count(index=all_index_name, body={
                "query": {
                    "bool": {
                        "must": [
                            {
                                "match_phrase": {
                                    "conv_name": obj['conv_name']
                                }
                            },
                            {"regexp": {'message': {"value": 'http.*:?.*', "flags": "ALL",
                                                    "case_insensitive": "true", "max_determinized_states": 10000, "rewrite": "constant_score"}}}

                        ],

                    }
                }
            })
            links = regexp_cnt['count']
        except Exception as e:
            print('egexp error', e)
            pass
        
        
        try:
            media_cnt = es.count(index=all_index_name, body={
                "query": {
                    "bool": {
                        "must": [
                            {
                                "match_phrase": {
                                    "conv_name": obj['conv_name']
                                }
                            },

                        ],
                        'must_not': [
                            {'match': {'media': 'None'}}
                        ]
                    }
                }
            })
            media = media_cnt['count']
        
        except:
            pass

    return{'files': files, 'links': links, 'subs': subs, 'media': media, 'type': channel_type}



def channel_name_converter(channel_username: str) -> list:
    """
    Converts channel username into searchable format
    """
    qtext_filter = []
    default_qtext = channel_username
    if 't.me' in channel_username:
        default_qtext = channel_username.rsplit('/')[-1]
    default_qtext = default_qtext.lower()
    qtext_filter.append(
        f'https://t.me/s/{default_qtext}')
    qtext_filter.append(f'https://t.me/{default_qtext}')
    qtext_filter.append(default_qtext)
    return qtext_filter



def average_view(total_views, total_post):
    """
    Calculates average view for channels
    """
    avg_views = int(total_views)/int(total_post)
    return avg_views


def customer_engagement_calc(avg_views, subs):
    """
    Customer engagement per post 
    Logic: average views per subscriber
    """
    new_subs = subs
    if 'K' in subs:
        new_subs = subs.replace('.', '').replace('K', '000')

    cust_eng = (int(avg_views) / int(new_subs))
    return cust_eng


def channel_name_extractor_from_id(id):
    """
    Extract channel names from its ID
    """
    try:
        if str(id).isnumeric():
            es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
            res = es.search(index=all_index_name, size=1, body={
                'query': {
                    'term': {
                        'to_id': id
                    }
                }
            })
            return res["hits"]["hits"][0]["_source"]["conv_name"]
        else:
            return id
    except Exception as e:
        return id


def forwaded_channel_count(obj):
    """
    Counts No. of forwarded Channels
    """
    new_arr = []
    new_dict = defaultdict(int)
    
    for i in obj:
        print(i)
        default_key = 'forwardedfromchanid'
        obj_keys = i['_source'].keys()
        if 'forwardedromchanid' in obj_keys:
            default_key = 'forwardedromchanid'
        try:
            
            new_fd = json.loads(i['_source'][default_key])
            print(new_fd)
            fwd_name = new_fd['forwaded_from']

            new_dict[fwd_name] += 1
        except:
            print('exception triggered', i['_source'][default_key])
            key = channel_name_extractor_from_id( i['_source'][default_key])
            new_dict[key] += 1

    return new_dict


def date_stats_filter(obj):
    """
    Monthly data retrieval for statistics 
    """
    return obj['aggregations']['group_by_month']['buckets'][0]
    

def file_counter(obj):
    """
    Counts file extensions in a channel
    """
    callext = ['!bt', '!qb', '!ut', '#24', '#ib', '#sc', '#st', '$#!', '$$$', '$00', '$01', '$db', '$ed', '$er', '$o1', '$vm', '^^^', '__a', '__b', '_dd', '_eml', '_nws', '_p', '~$~', '~ap', '~de', '~hm', '~mn', '{pb', '201$201', '000',  '001',   '075', '085', '091', '096', '0b', '0xe', '1',  '10', '113', '123', '15u', '1pe', '1ph', '1st', '2', '264', '2d', '2da', '2dl', '3d', '3dl', '3dv', '301', '386', '3da', '3dd', '3dr', '3ds', '3dt', '3fx', '3g2', '3gp', '3gr', '3ko', '3me', '3mm', '3pe', '3t4', '411', '4c$', '4dv', '4mp', '4sw', '4th', '5cr', '669', '6cm', '777', '7z', '8', '8b?', '8ba', '8bf', '8bi', '8cm', '8li', '8m', '8pbs', '8u', 'a',  'a0?', 'a11', 'a2b', 'a3d', 'a3m', 'a3w', 'a4a', 'a4m', 'a4p', 'a4w', 'a5w', 'aa', 'aab', 'aac', 'aam', 'aax', 'ab2', 'ab6', 'ab8', 'aba', 'abc',   'abd',  'abf', 'abi',  'abk', 'abm',   'abr', 'abs',   'abw', 'abx', 'aby', 'ac3', 'aca',  'acb', 'acc', 'acd', 'ace', 'acf',  'aci', 'acl',   'acm',     'acorn', 'acs', 'acs2', 'acsm', 'act',   'acv',  'ad', 'ada', 'adb', 'adc', 'ade', 'adf',    'adi', 'adl', 'adm',     'adn', 'ado',  'adp',    'adr',     'ads', 'adt',  'adx', 'adz', 'aeh', 'aep', 'aex',  'af2', 'aff', 'afi', 'afl', 'afm',  'afs', 'aft', 'ag', 'agp', 'agw', 'ai', 'aiff', 'ain', 'aio', 'air',  'ais', 'aix', 'ajp', 'alb',   'albm',  'all',   'als',  'alt', 'alx', 'alz', 'amf', 'amff', 'amg',  'amp', 'amr',  'amv', 'amx', 'anc', 'ani', 'anm', 'ann', 'ans',  'aos',  'ap',   'apc', 'apd', 'ape', 'apf', 'api',   'apk', 'apl', 'apm', 'app',    'apr', 'aps',  'apx', 'arc',  'arf', 'arg', 'ari', 'arj', 'arl', 'ark',  'arr', 'ars', 'art',  'arv',  'arx', 'asa',  'asc',   'ascx', 'asd',   'asf',  'ash', 'asi', 'asl', 'asm',  'asmx', 'aso', 'asp',   'aspx', 'asr',  'asx', 'asx', 'at2', 'atm', 'atn', 'atr', 'att', 'aty', 'au', 'au3', 'aud', 'aut',         'aux',  'ava', 'avb',  'avd', 'avi', 'avr', 'avs',    'avx', 'aw',  'awb', 'awd',   'awe', 'awk', 'awm', 'awp', 'awr', 'aws', 'ax', 'axd',  'axe',   'axg', 'axl', 'axs',  'axt',  'axx', 'azw', 'azz', 'b', 'b&w', 'b~k',  'b00', 'b16', 'b1n', 'b1s', 'b30', 'b3d', 'b5i', 'b5t', 'b6i', 'b6t', 'b8', 'b_w', 'bad', 'bag',   'backup', 'bak', 'bal', 'ban', 'bar', 'bas',  'bat', 'bb', 'bba', 'bbl', 'bbm', 'bbs', 'bc!', 'bcf',   'bch',  'bck', 'bcm', 'bcn', 'bco', 'bcp', 'bct', 'bcw', 'bde', 'bdf',  'bdm', 'bdmv', 'bdr', 'bez', 'bf2', 'bff', 'bfm', 'bfs', 'bfx', 'bga', 'bgt', 'bgi', 'bgl', 'bgt', 'bib',   'bic', 'bid', 'bif', 'bik',  'bin', 'bio', 'bip', 'bit',   'bk', 'bk!', 'bk1', 'bk2', 'bk3', 'bk4', 'bk5', 'bk6', 'bk7', 'bk8', 'bk9', 'bkf', 'bkg',  'bkp', 'bkw', 'blb', 'bld', 'blend', 'blf',  'blg', 'blk',    'blob', 'blt',  'bm', 'bmf', 'bmi', 'bmk', 'bmp', 'bmx', 'bnd', 'bndl', 'bnk', 'bob',  'bom',   'boo', 'book',  'bot', 'box',  'bpc', 'bpl', 'bpt', 'bqy', 'br', 'brd', 'brf', 'brk', 'brn', 'bro', 'brp', 'brt', 'brx', 'bsa', 'bsb',  'bsc',   'bsdl', 'bsl', 'bsp',  'bst', 'bsv', 'bt!', 'btm', 'btn', 'bto', 'btr',  'btx', 'bud', 'bug', 'bun', 'bup', 'but', 'buy', 'bv1', 'bv2', 'bv3', 'bv4', 'bv5', 'bv6', 'bv7', 'bv8', 'bv9', 'bwa', 'bwb', 'bwi', 'bwr', 'bws', 'bwt', 'bxx', 'bz2', 'c',  'c++', 'c–', 'c00',  'c01', 'c2d', 'c4d', 'c60', 'c86', 'ca', 'cab', 'cache', 'cad', 'cac', 'cad', 'cag', 'cal',  'calb',  'cam', 'can', 'cap',  'car',   'cas', 'cat', 'cb',  'cbc', 'cbf', 'cbl', 'cbm', 'cbp', 'cbr', 'cbt', 'cbz', 'cc', 'cca', 'ccb', 'ccc', 'ccd',  'cce', 'ccf', 'cch', 'ccl', 'cco', 'cct', 'ccx', 'cda', 'cdb',  'cdd', 'cde', 'cdf',  'cdg', 'cdi',  'cdk', 'cdl',  'cdm',  'cdp',  'cdr', 'cdt', 'cdx',  'ce', 'ceb', 'ceg', 'cel', 'cf',  'cfb', 'cfc', 'cfg', 'cfl', 'cfm', 'cfn', 'cfo', 'cfp',  'cfr', 'cga', 'cgd', 'cge', 'cgi', 'cgm', 'ch', 'ch3', 'ch4', 'chd', 'chi', 'chk',  'chl', 'chm', 'chn', 'cho', 'chp', 'chr', 'cht',  'chw', 'cid', 'cif',  'ciff', 'cil', 'cit', 'cix', 'ckb', 'cl', 'cl3', 'cl4', 'cl5', 'class', 'clb',   'clg', 'cli', 'clm', 'clp',   'clpi', 'clr',  'cls', 'cm', 'cmd',   'cmf', 'cmg', 'cmk', 'cml', 'cmm', 'cmo', 'cmp',   'cmq', 'cmt', 'cms', 'cmv', 'cmx',    'cnc', 'cnd',  'cnf', 'cnt', 'cnv',  'cob', 'cod',    'col',  'com', 'con', 'conf', 'config', 'cor',   'cpd', 'cpe', 'cpf',  'cph', 'cpi',   'cpl',  'cpo', 'cpp',  'cpr', 'cps',  'cpt',    'cpx',  'cpy', 'cpz', 'cr2', 'crc', 'crd',   'crf', 'crh',  'crp', 'crs', 'crt',  'crtr', 'crtx', 'cru', 'crw', 'crx',  'crz', 'cs', 'csa',  'csf',  'csg', 'csh', 'csk', 'csm', 'cso', 'csp', 'css',   'cst',  'csv',  'ct', 'ctc', 'ctd',    'ctf', 'ctg',    'ctl',   'ctn', 'ctt',  'ctu', 'ctx',  'cty', 'cue', 'cuf', 'cul', 'cur', 'cut',  'cv4', 'cv5', 'cva',  'cvb', 'cvd', 'cvp', 'cvr',  'cvs', 'cvt', 'cvw', 'cwk', 'cwz', 'cxf', 'cxp', 'cxt', 'cxx', 'd',  'd00',  'd10',  'd2s', 'd3d',  'd64', 'dat',      'data', 'day', 'db',  'db$',  'db2', 'db3', 'dba',  'dbb',  'dbd',  'dbf',  'dbg', 'dbk', 'dbl', 'dbm',   'dbo', 'dbs',   'dbt',   'dbw', 'dbx',    'dca', 'dcf', 'dcm',  'dcp', 'dcr',  'dcs',  'dct',  'dcx',      'dd', 'ddat', 'ddb', 'ddc', 'ddf', 'ddi', 'ddp', 'de', 'de7', 'deb', 'dec', 'def',   'dem',  'des',     'dev', 'dfd', 'dff', 'dfi', 'dfl',   'dfm', 'dfs', 'dft',    'dfv', 'dfx', 'dgn', 'dgr',  'dgs', 'dh', 'dhp', 'dht', 'dhy', 'dia', 'dib', 'dic', 'dif',   'dig',   'dip', 'dir',    'dis',   '>', 'divx', 'diz', 'dje', 'djv', 'djvu', 'dkb', 'dl', 'dl_', 'dld', 'dlg', 'dll',  'dls', 'dmf',  'dmg', 'dml', 'dmo', 'dmp', 'dms', 'dmsk', 'dna', 'dnasym', 'dnax', 'dne', 'dng',  'dnl',  'do', 'doc', 'docm', 'docx', 'dog', 'doh', 'dol', 'dos',   'dot',  'dotx', 'dox', 'doz', 'dp',  'dpg', 'dpk', 'dpp', 'dpr', 'dps', 'dpt', 'dpx', 'dra', 'drs', 'drv', 'drw',  'ds', 'ds4', 'dsa', 'dsb', 'dsc', 'dsd', 'dsf',   'dsk',  'dsm', 'dsn',  'dsp',    'dsp2', 'dsr', 'dss',  'dst',  'dsw', 'dsy', 'dt_', 'dta', 'dtd', 'dtf', 'dtp',  'dup', 'dus', 'dvc', 'dvf', 'dvi', 'dvp',  'dvr',  'dvr-ms', 'dw2', 'dwc', 'dwd',  'dwf',  'dwg',  'dwk', 'dwl', 'dwt',   'dwz', 'dx', 'dxf', 'dxn', 'dxr',    'dyc', 'dylib', 'dyn', 'dz', 'e3p', 'e3s', 'e3t', 'e3v', 'eap', 'ear', 'eas', 'ebj', 'ebo', 'ebp', 'ecf',   'eco', 'ecw',  'edb',  'edl', 'edr', 'eds', 'edt', 'eeb', 'efe', 'eft', 'efx', 'ega', 'ek5', 'ek6', 'ekm', 'el', 'elc', 'elm', 'elt', 'email', 'emb', 'emd', 'emf', 'eml', 'emp', 'ems', 'emu', 'emx',  'emz', 'enc',  'end', 'eng',  'ens', 'env',  'eot', 'epd', 'epf',  'epi', 'epp', 'eps',  'epub', 'eqn', 'erd', 'erm', 'err',  'esp', 'esh', 'esl', 'ess', 'est', 'etf',  'eth', 'ets', 'etx', 'ev', 'evi', 'evl', 'evr', 'evt', 'evy', 'ewd', 'ewl',  'ex', 'ex_', 'ex3', 'exc',  'exd', 'exe', 'exm', 'exp',  'ext', 'ext2fs', 'exx', 'ezf', 'ezm', 'ezp', 'ezz', 'f',  'f_i', 'f01', 'f06', 'f07', 'f08', 'f09', 'f10', 'f11', 'f12', 'f13', 'f14', 'f16', 'f2', 'f2r', 'f3r', 'f4v', 'f77', 'f90', 'f96', 'fac', 'faq', 'far',  'fav', 'fax', 'fbc', 'fbk',  'fc', 'fcd',    'fcm', 'fcp', 'fcs',       'fcw', 'fd',  'fdb',   'fde', 'fdf', 'fdr',  'fdw', 'feb', 'fef', 'fes',  'fev', 'ff', 'ffa', 'fff', 'ffl', 'ffo', 'fft', 'ffx', 'fgd',   'fh3', 'fh4', 'fh5', 'fh6', 'fh7', 'fh8', 'fh9', 'fh10', 'fi', 'fif', 'fig',  'fil',   'fin', 'fio',  'fit',  'fix', 'fky', 'fla', 'flac', 'flb', 'flc', 'fld', 'fle', 'flf',     'fli',  'flk', 'flm', 'flo', 'flp',   'flt',           'flv', 'flx', 'fm',  'fm1', 'fm3',  'fmb', 'fmf', 'fmg', 'fmk', 'fmo', 'fmp',  'fmpp', 'fmt',  'fmv', 'fmz', 'fn3', 'fnt', 'fnx', 'fo1', 'fo2', 'fol', 'fon',   'for',  'fot', 'fp', 'fp3',  'fp4', 'fp5', 'fpb', 'fpc', 'fpk', 'fpr', 'fpt', 'fpw', 'fpx', 'fqy', 'fr3', 'frc', 'frd', 'fre',  'frf', 'frg', 'frl', 'frm',    'fro', 'frp', 'frs', 'frt', 'frx', 'fs', 'fsc', 'fsh', 'fsl', 'fsm', 'fst', 'fsproj', 'fsx', 'fsy', 'ftm', 'fts', 'ftw',  'ftp', 'fus', 'fvt', 'fw', 'fw2', 'fw3', 'fwp', 'fx',  'fxd', 'fxm', 'fxo', 'fxp', 'fxr', 'fxs', 'g', 'g3', 'g3f', 'g3n', 'g8', 'gab', 'gal', 'gam', 'gat', 'gb',  'gba',  'gbc', 'gbd', 'gbl', 'gbr',  'gbx', 'gc1', 'gc3', 'gcd', 'gcf', 'gdb',  'gdf', 'gdr', 'ged',     'gem', 'gen',   'geo', 'gfb', 'gft', 'gfx',  'gg', 'gho', 'ghs',  'gib', 'gid', 'gif', 'gig', 'giw', 'gl', 'glm', 'gls', 'gly', 'gmd', 'gmf', 'gml', 'gmp', 'gno', 'gnt', 'goc', 'goh', 'gp', 'gp3',  'gp4', 'gpd', 'gph', 'gpk', 'gpx', 'gr2', 'gra', 'grb', 'grd',  'grf',  'grl', 'grp',  'grx', 'gry', 'gs1', 'gsd',  'gsm',   'gsp', 'gsw', 'gtp',  'gts', 'gup', 'gwi', 'gwp', 'gxd',   'gxl', 'gxt', 'gym', 'gz', 'gzip', 'h', 'h!', 'h++', 'h–', 'ha', 'ham', 'hap', 'hbk', 'hbs', 'hcr', 'hdf',  'hdl', 'hdp',  'hdr',    'hds', 'hdw', 'hdx', 'hed', 'hex', 'hfi', 'hfx',  'hgl', 'hh', 'hhc',  'hhh', 'hhk', 'hhp', 'hht', 'hin', 'his',  'hlb', 'hlp', 'hlz', 'hm3', 'hmm', 'hnc', 'hof', 'hp8', 'hpf', 'hpg', 'hpi', 'hpj', 'hpk', 'hpm',  'hpp', 'hqx', 'hrf', 'hrm', 'hs2', 'hsi', 'hst',  'hta', 'htc', 'htf', 'hti', 'htm', 'html', 'htr', 'htt', 'htx', 'hus', 'hwd', 'hxm', 'hxx', 'hy1', 'hy2', 'hyc', 'hyd',
               'hyp', 'hyt', 'i', 'iaf', 'iax', 'ibm', 'ibd', 'ibp', 'ibq', 'ica', 'icb', 'icc',  'icd', 'icl', 'icm',  'icn', 'ico', 'ics', 'id',  'id2', 'idb',  'ide', 'idf',  'idl',  'idw', 'idx', 'ies', 'ifd', 'iff',    'ifo', 'ifp', 'ifs',  'igr', 'igs', 'igx', 'iif', 'ilb', 'ilk', 'im30', 'im8', 'ima', 'imb', 'imc', 'imd', 'imf', 'img', 'imm', 'imn', 'imp',  'imq', 'ims', 'imv',  'imw',  'imz', 'in$', 'in3', 'inb', 'inc', 'ind',  'indd', 'inf',   'ini', 'ink', 'inl', 'inp',   'ins',   'int',  'inv', 'inx', 'io', 'iob', 'ioc', 'ion', 'ipa', 'ipd',  'ipg', 'ipj', 'ipl', 'ipp', 'ips',  'ipsw', 'ipx', 'ipz', 'iri', 'irs', 'isd', 'ish', 'isk', 'iso',       'isr', 'iss',  'ist', 'isu',   'isz', 'it', 'itc2', 'itdb', 'itf', 'ith', 'itl', 'iv', 'iva', 'ivt', 'iw', 'iwa', 'iwd', 'iwp', 'izt', 'j01', 'jad', 'jar', 'jas', 'jav', 'java', 'jbc',  'jbd', 'jbf', 'jbk', 'jbr', 'jbx', 'jdt', 'jef', 'jet', 'jff', 'jfif', 'jfx', 'jhtml', 'jif',  'jmx', 'jnb', 'jnl', 'jnlp', 'jnt', 'job',    'jor', 'jou', 'jp2', 'jpc', 'jpeg', 'jpf', 'jpg', 'jps', 'jpx', 'js', 'jsd', 'jse', 'jsf', 'jsh', 'json', 'jsp', 'jtf',  'jtp', 'jup', 'jw', 'jwl', 'jwp',  'jxr', 'jzz', 'kar', 'kau', 'kb',  'kbd', 'kbm', 'kcl', 'kcp', 'kdc',  'keo', 'ket', 'kex', 'kext', 'key',    'kgb', 'kit', 'kix', 'kma',  'kml', 'kmp', 'kmx', 'kmz', 'kos', 'kp2', 'kpl',  'kpp', 'kps', 'kqb', 'kqe', 'kqp', 'krz', 'ksd', 'ktk', 'kwi', 'kwm', 'kyb', 'l',   'l01', 'lab',  'lang', 'lat', 'latex', 'lay', 'lbg', 'lbl', 'lbm',  'lbo', 'lbr',  'lbt', 'lbx', 'lcf', 'lck', 'lcl', 'lcn', 'lcs',  'lcw', 'ld', 'ld1', 'ldb', 'ldf',    'ldif', 'leg', 'les', 'let', 'lev', 'lex', 'lfa', 'lft', 'lg', 'lgc', 'lgo',  'lgx', 'lha', 'lhw', 'lib', 'lic',  'lid',       'lif',  'lim', 'lin', 'lis', 'lit', 'lix',  'lj', 'lko', 'll3', 'lmp', 'lmt',  'lnd', 'lng',   'lnk',  'loc',   'lod', 'log', 'lok', 'lpc', 'lpd',  'lpf', 'lpi', 'lpk', 'lrf', 'lrs', 'lse', 'lsf',  'lsl', 'lsp', 'lss', 'lst',    'lt2', 'ltm', 'ltr', 'lua', 'lvl', 'lvp',  'lwa', 'lwd', 'lwo', 'lwp', 'lwz', 'lx', 'lyr', 'lzd', 'lzh', 'lzs', 'lzw', 'lzx', 'm',   'm11', 'm1v', 'm2p', 'm2ts', 'm2v', 'm3', 'm3d', 'm3u', 'm4', 'm4a', 'm4b', 'm4p', 'm4r', 'm4v', 'm_u', 'ma3', 'mac',  'mad', 'maff', 'mag', 'mai', 'mak',  'man', 'map',     'mar',   'mas', 'mat',  'max',  'mb', 'mbf', 'mbk',  'mbx', 'mcc', 'mcd', 'mcf',    'mci', 'mcp',  'mcr', 'mcw', 'mcx', 'md', 'md5',  'mda', 'mdb', 'mde', 'mdf',     'mdi',  'mdk', 'mdl',  'mdm', 'mdmp', 'mdr', 'mdt', 'mdx', 'mdz', 'me', 'meb', 'med',  'mem',  'meq', 'mer', 'mes',  'met',    'meu', 'mex',   'mf', 'mfx', 'mgf', 'mgi', 'mgp', 'mhp', 'mht', 'mia', 'mib', 'mic', 'mid', 'mif', 'mii', 'mim', 'mio', 'mip', 'mis',   'mix', 'mk', 'mkd', 'mke', 'mki', 'mks', 'ml3', 'mlb', 'mlm', 'mm', 'mmc',  'mmd', 'mmf', 'mml', 'mmm', 'mmo', 'mmp', 'mmx',  'mmz', 'mnd', 'mng', 'mnt', 'mnu',  'mnx',  'mny', 'mob', 'mod',   'mol', 'mon', 'mov',   'mp2', 'mp3',    'mp4', 'mpa', 'mpc', 'mpd', 'mpe', 'mpeg', 'mpf',  'mpg', 'mpl', 'mpls', 'mpm', 'mpp',  'mpq', 'mpr', 'mps',  'mpt',  'mpv', 'mpw', 'mpx', 'mrb', 'mrc',  'mrk', 'mrs', 'msc', 'msd', 'msf', 'msg', 'msi', 'msm', 'msn', 'mso',   'msp', 'mspx', 'mss', 'mst',     'msu', 'msv', 'msw', 'mswmm', 'msx', 'mtd', 'mth', 'mtm', 'mts',  'mtv', 'mtw', 'mtx',   'mu', 'mu3', 'muf', 'mul', 'mus',  'mvb',   'mvc', 'mvd', 'mvf', 'mvi', 'mvw', 'mwf', 'mwp',  'mws', 'mwv', 'mxd', 'mxe',  'mxf',  'mxl', 'mxm', 'mxp',  'mxt', 'myp', 'myr', 'mys', 'myt', 'mzp', 'na2', 'nam', 'nap', 'nav', 'nb', 'nbf', 'nbu', 'nc',  'ncb', 'ncc', 'ncd',   'ncf',   'nch',  'nd5', 'ndb', 'nde', 'ndf', 'ndk', 'ndx', 'neb', 'ned', 'nef', 'neo', 'nes', 'net', 'new', 'nfo', 'ng', 'ngf', 'ngg', 'nh', 'nib', 'nif', 'njb', 'nlm', 'nls', 'nlx', 'nmd', 'nmi', 'nmo', 'nms',  'nnb', 'nob', 'nol', 'not',  'now', 'np', 'npa', 'npf', 'npi', 'nra', 'nrb', 'nrg',    'nri', 'nrl', 'nrw',  'nsc',  'nsf', 'nsi', 'nst', 'nt', 'ntf', 'nth', 'ntp', 'ntr', 'nts',  'ntx', 'ntz', 'nu4', 'nuf', 'numbers', 'nup', 'nvc', 'nvm', 'nwc', 'nws', 'nwr', 'nwt', 'nxt', 'nzb', 'o', 'o$$', 'oaz', 'ob', 'obd', 'obj', 'obr', 'obs', 'obv', 'oca', 'ocf', 'ocm',  'ocp',  'ocr', 'oct', 'ocx', 'odf',   'odg', 'odl', 'odp', 'ods', 'odt', 'oeb', 'oem', 'ofc', 'ofd', 'off', 'ofm', 'oft', 'ofx',  'ogg', 'ogm', 'ogv', 'okt', 'olb', 'old', 'ole', 'oli', 'oma', 'omf', 'omg', 'oms',   'ond', 'one', 'ont', 'oom', 'opd', 'opf',  'opl', 'opn', 'ops', 'opt', 'opw', 'opx', 'or2', 'or3', 'or4', 'or5', 'ora', 'org', 'osd', 'oss', 'ost', 'otf', 'otl', 'otx', 'out', 'ov1', 'ov2', 'ovd', 'ovl', 'ovr', 'ovw',   'ows', 'oxt', 'p',   'p16', 'p22', 'p65', 'p7m', 'pa', 'pa1', 'pab', 'pac',  'pack', 'pad', 'paf',  'pages', 'pak', 'pal',    'pan', 'par',   'pas', 'pat',  'pax', 'pb',   'pb1', 'pba', 'pbd', 'pbf',    'pbi',  'pbk', 'pbl', 'pbm',  'pbo', 'pbr', 'pbt', 'pc', 'pc3', 'pc8', 'pca', 'pcb',    'pcc', 'pcd',  'pcf',  'pch',  'pcj', 'pck',  'pcl', 'pcm', 'pcs', 'pct',    'pcw', 'pcx', 'pd', 'pda', 'pdb', 'pdc', 'pdd', 'pde',  'pdf',   'pdg', 'pdl', 'pdr', 'pds',       'pdt',  'pdv', 'pdw', 'pdx', 'pe4', 'pea', 'peb', 'ped', 'pem',  'peq', 'per', 'pes', 'pet', 'pf',  'pfa', 'pfb', 'pfc', 'pfg', 'pfk', 'pfl', 'pfm', 'pfs', 'pft', 'pg',  'pgi', 'pgm',  'pgp', 'pgs', 'ph',   'phb',    'phn', 'php',   'pho', 'phr', 'phtml', 'pic',   'pif',   'pim', 'pip', 'pit', 'pix', 'pj64', 'pj', 'pjt', 'pjx', 'pk', 'pk3',    'pka', 'pkd', 'pkg', 'pkk', 'pkt', 'pl',    'pl1', 'pl3', 'plb', 'plc', 'pll', 'pln', 'plr',  'pls',    'plt',     'pmv', 'pmx', 'pn3', 'pnf', 'png', 'pnm', 'pnt',  'pod', 'poh', 'poi', 'pop',  'pos',  'pot', 'potx', 'pov', 'pow', 'pp',  'ppa', 'ppb', 'ppd', 'ppf',    'ppg',  'ppl', 'ppm', 'ppo', 'ppp',  'pps',  'ppsx', 'ppt', 'ppz', 'pqa', 'pqi', 'pr2', 'pr2', 'pr3',  'prc',   'prd', 'pre',  'prf',   'prg',  'pri', 'prj', 'prm',  'prn',     'pro',  'prs',   'prt',        'prx',  'prz', 'ps', 'ps2', 'psb',  'psd',  'pse', 'psf',   'psi',  'psm',   'psmdoc', 'psp',   'psr', 'pst', 'psw', 'pt3',  'pt4', 'ptb', 'ptm',   'ptn', 'ptp', 'ptr', 'pts',  'ptx', 'pub',   'put', 'puz',  'pva', 'pvd', 'pvm', 'pvl', 'pvt', 'pw', 'pwd',  'pwf', 'pwi', 'pwl', 'pwm', 'pwp', 'pwz', 'px', 'pxl', 'pxv', 'py', 'pyc', 'pyd', 'pyw', 'pz2', 'pz3', 'pza', 'pzd', 'pzl',   'pzo', 'pzp',  'pzs', 'pzt', 'pzx', 'q05', 'q9q', 'qad', 'qag', 'qap', 'qbb', 'qbe', 'qbk', 'qbl', 'qbo', 'qbr', 'qbw', 'qcn', 'qcp',  'qd0', 'qd1', 'qd2', 'qd3', 'qd4', 'qd5', 'qd6', 'qd7', 'qd8', 'qd9', 'qdat', 'qdb', 'qdf', 'qdt',    'qdv', 'qe4', 'qef', 'qel', 'qfl', 'qfx',  'qhf', 'qic', 'qif',  'qix',  'qlb', 'qlc', 'qlf', 'qlp', 'qm4', 'qm', 'qml', 'qph', 'qpr',  'qpw', 'qpx', 'qrp',   'qrs', 'qrt', 'qru', 'qry', 'qsd', 'qsi', 'qst', 'qt', 'qtc', 'qtk', 'qtl', 'qtp',  'qts',  'qtx', 'que',  'qvm', 'qvs', 'qw', 'qwk', 'qxd', 'qxl', 'qxp', 'qxt', 'r', 'r33', 'r8', 'r8p', 'ra', 'ram', 'rar', 'ras', 'rat', 'raw', 'rb', 'rbf',  'rbn',  'rbs', 'rbx', 'rc',  'rcf', 'rcg', 'rcp', 'rcx', 'rdb',  'rdf', 'rdi', 'rds', 'rdx', 'rec',   'red', 'ref', 'reg',  'rels', 'rem',  'rep',  'req', 'res',  'rev', 'rex', 'rex', 'rez', 'rf', 'rfl', 'rft', 'rgb', 'rgi', 'rgp', 'rgs', 'rgx', 'rh', 'rhp', 'ri', 'rib', 'ric', 'rif', 'rip', 'rix', 'rl4', 'rl8', 'rla', 'rlb', 'rlc', 'rle', 'rlz', 'rm', 'rmf',  'rmi', 'rmj', 'rmk', 'rmm', 'rmr', 'rms', 'rmvb', 'rm', 'rmvb', 'rmx', 'rn', 'rnd', 'roi', 'rno', 'rol', 'rpd',   'rpl', 'rpm',   'rps', 'rpt', 'rrd', 'rs', 'rs_', 'rsb', 'rsc', 'rsm',   'rsp', 'rss', 'rst',  'rsw', 'rtc', 'rtf',  'rtl',  'rtp',  'rts', 'rtx',  'ru', 'rul', 'run', 'rv', 'rvb', 'rvp', 'rvw', 'rwg', 'rws', 'rwx', 'rwz', 'rzk', 'rzr', 'rzx',  's',  's$$', 's3m', 'sac', 'saf',   'sah', 'sal', 'sam', 'sar', 'sas', 'sas7bcat', 'sas7bdat', 'sas7bndx', 'sas7bpgm', 'sas7bvew', 'sas7mdb', 'sat', 'sav',   'sb', 'sbc', 'sbd', 'sbi', 'sbj', 'sbn', 'sbp', 'sbr', 'sbs', 'sbt', 'sbx', 'sc',  'sc3',  'sca', 'scc', 'scd', 'scf',   'sch',  'sci',  'scm',   'scn',  'sco', 'scp', 'scr',     'sct',  'scx',   'scy', 'sda', 'sdc', 'sdd', 'sdf', 'sdi',  'sdn', 'sdr', 'sds', 'sdt',   'sdu', 'sdw',   'sea', 'sec',   'sed', 'sep', 'seq',  'ses', 'set',   'sf',  'sf2', 'sfb', 'sfc', 'sff',   'sfi',  'sfl', 'sfn', 'sfo', 'sfp', 'sfs', 'sft', 'sfv',  'sfw', 'sfx', 'sg1', 'sgf',   'sgi', 'sgm',   'sgn', 'sgp', 'sgt', 'sh',  'sh3', 'sha', 'shb', 'shd',  'shg', 'shk', 'shm', 'shn', 'shp', 'shr', 'shs', 'shtml', 'shw',  'shx', 'sid',  'sif', 'sig',   'sik', 'sim',    'sis', 'sit', 'sitx', 'skb', 'skf', 'skin', 'skm', 'skn',  'skp', 'sl', 'slb', 'slc', 'sld', 'slf',  'sli', 'slk', 'sll', 'sln', 'slt', 'sm',    'smc', 'smd', 'smf', 'smi',  'smil', 'smk', 'smm', 'smp', 'sms',  'smt', 'smtmp', 'snd', 'sng', 'snm', 'sno', 'snp',    'snx',   'so', 'sol',  'som',  'son', 'sou', 'sp', 'spa',    'spc',   'spd', 'spf', 'spg', 'spi', 'spi', 'spl',     'spm', 'spo', 'spp', 'spr',   'sps',
               'spt',  'spv', 'spw', 'torrent','spx', 'sql', 'sqlite', 'sqm',  'sqz', 'src', 'srf',  'srp', 'srt',   'ss', 'ssa', 'ssb', 'ssd', 'ssf',  'ssm', 'ssp', 'st',   'st3', 'sta',   'stb', 'std',  'stf', 'stg',  'stl', 'stm',  'stn',  'sto', 'stp',    'str', 'sts',  'stt',  'stu',  'stw', 'stx',  'sty', 'sub', 'sui', 'sum', 'sun', 'sup', 'sv4', 'svd', 'svg',  'svgz', 'svp',   'svs', 'sw', 'swd',  'swf', 'swg', 'swi', 'swk', 'swp',  'sxc', 'sxw',  'sy1', 'sy3', 'syd', 'sym',   'syn',  'sys',  'syw', 'szc', 't',    't$m', 't04', 't05', 't06', 't07', 't08', 't09', 't10', 't11', 't12', 't2', 't44', 't64', 'ta0', 'tab',   'tag', 'tah', 'tal', 'tao', 'tar', 'tax', 'taz', 'tb1', 'tb2', 'tbf', 'tbh', 'tbk',  'tbl',  'tbs', 'tbx', 'tc', 'tch', 'tcl', 'tcp', 'tcw', 'td', 'td0', 'td2', 'tdb',  'tdf',  'tdh', 'tdk', 'tds', 'tdt',   'tdw', 'tee', 'tef', 'tel', 'tem',  'temp', 'test', 'tex',   'text', 'tf',  'tfa', 'tfc', 'tfh', 'tfm',  'tfs', 'tfw',  'tg1', 'tga', 'tgz', 'thb', 'thd', 'thm',   'thn', 'ths', 'tib', 'tif', 'tiff', 'til', 'tim',  'tis', 'tix',    'tjl', 'tlb',    'tlc', 'tlp', 'tlt', 'tmb', 'tmd', 'tmf', 'tmo', 'tmp', 'tmpl', 'tmq', 'tms', 'tmv', 'toc',  'tol', 'TOPC', 'tos', 'tp',   'tp3', 'tpb', 'tpf', 'tph', 'tpi', 'tpl',   'tpp',   'tps', 'tpu',  'tpw',  'tpz', 'tr',  'tr2', 'trace',     'trc', 'tre', 'trg', 'tri', 'trk',    'trm', 'trn', 'trp',  'trs', 'trw', 'trx',  'ts', 'tsk',  'tsp', 'tst', 'tsv', 'tt10', 'tta', 'ttc', 'ttf', 'tub', 'tut', 'tv', 'tv1', 'tv2', 'tv3', 'tv4', 'tv5', 'tv6', 'tv7', 'tv8', 'tv9', 'tvf', 'tvo', 'tvp', 'tvr', 'tvt', 'txd',  'txf', 'txi', 'txl', 'txt', 'tym', 'tz', 'tzb', 'uax', 'ub', 'uc2', 'ucn', 'ucs', 'udc', 'udf', 'udl', 'uds', 'ue2', 'ufo', 'uha', 'uhs', 'ui',  'uif',  'uih', 'uis', 'ul', 'uld', 'ult', 'umb', 'umd', 'umf', 'umx', 'uni',  'unl', 'unq', 'uns2', 'unx', 'upd',  'upg', 'upo', 'upx', 'url', 'urls', 'usb',  'user', 'usp', 'usr', 'utf', 'utl', 'utx',  'uu', 'uue', 'uvf', 'uvr', 'uw', 'uwl', 'v',  'v2', 'v64', 'val',  'van', 'var', 'vbc', 'vbd', 'vbe', 'vbn', 'vbp', 'vbs', 'vbw', 'vbx', 'vc',  'vc4', 'vcd',  'vce', 'vcf', 'vch', 'vcmf', 'vcs', 'vcw', 'vcx', 'vda', 'vdb',  'vdf',  'vdi', 'vdj', 'vdm', 'vdr', 'vdx',   'vem',  'ver', 'vew', 'vfm', 'vfn', 'vfp', 'vfs', 'vfx', 'vga',  'vgd', 'vgr', 'vhd', 'vi', 'vic', 'vid',    'vif', 'vik', 'vir', 'vis', 'viv', 'vlm',   'vlt', 'vm', 'vm1', 'vmc', 'vmdk', 'vmf',  'vmg', 'vml', 'vmo',   'vmp', 'vms', 'vmt', 'vmx', 'vnt', 'vo', 'vob', 'voc', 'vof', 'vol',      'vor', 'vox',    'vp6', 'vpa', 'vpd',  'vpg', 'vpk', 'vpl',  'vpp',  'vqe', 'vqf', 'vql', 'vrd', 'vrm', 'vro', 'vrp', 'vrs', 'vs', 'vsd', 'vsl',  'vsm', 'vsp',   'vss', 'vst', 'vtf', 'vts', 'vtx', 'vue',  'vw', 'vw3', 'vwl', 'vwr', 'vwt', 'vxd', 'vyd', 'w',  'w02', 'w30', 'w31', 'w3g', 'w3m', 'w44', 'w5v', 'wab', 'wac', 'wad',       'waf', 'wal',  'war',  'wav', 'wax', 'wb1', 'wb2', 'wb3', 'wba',  'wbc', 'wbf', 'wbk', 'wbmp', 'wbt', 'wbx', 'wbz', 'wcd', 'wcm',  'wcp', 'wd2',  'wdb', 'wdf',  'wdl', 'web', 'wer', 'wfc', 'wfm', 'wfn', 'wfx', 'wg1', 'wg2', 'wgt', 'wid', 'wim', 'win',   'wiz', 'wjp', 'wk1', 'wk3', 'wk4', 'wkb',  'wke', 'wkq', 'wks',  'wll', 'wlk', 'wlt',   'wma', 'wmc',   'wmf', 'wml', 'wmv', 'wmz', 'wn', 'wnf', 'wo4', 'wo7', 'woa', 'woc',  'wor', 'wot', 'wow', 'wp', 'wp3', 'wp5', 'wpd', 'wpf',  'wpg',  'wpj', 'wpk', 'wpl',      'wpm', 'wps', 'wpt',  'wpw', 'wq!', 'wq1', 'wr1', 'wrd', 'wrf', 'wri', 'wrk', 'wrl', 'wrml', 'wrp', 'wrs', 'ws', 'wsf', 'wss', 'ws2', 'wsc', 'wsd', 'wsf', 'wsh', 'wsp', 'wsr', 'wss', 'wst', 'wsx', 'wsz', 'wtd', 'wtr', 'wv', 'wve',  'wvx', 'wvw', 'wwb', 'wwk', 'wwp', 'wws', 'wwv', 'wxp', 'wxs', 'wzg', 'wzs', 'x',   'x01', 'x02', 'x03', 'x04', 'x05', 'x06', 'x07', 'x08', 'x09', 'x16', 'x32', 'xap', 'xbel', 'xbm', 'xcf', 'xdf',  'xdw', 'xef', 'xem', 'xep', 'xes', 'xet', 'xev', 'xez', 'xfd', 'xfdl', 'xfn', 'xft', 'xfx', 'xhtml', 'xi', 'xif',    'xla', 'xla', 'xlb', 'xlc', 'xlk', 'xll', 'xlm', 'xlr', 'xls',   'xlsm', 'xlsx', 'xlt',  'xlw', 'xlx', 'xm', 'xmi', 'xml', 'xmp', 'xnf', 'xpi',  'xnk', 'xpl', 'xpm', 'xpr', 'xps', 'xpt',  'xpw',  'xqt',  'xpv', 'xrf', 'xsd', 'xsf', 'xsl', 'xspf', 'xss', 'xtb', 'xtm', 'xtr',  'xul', 'xvb', 'xvid', 'xvl', 'xwd', 'xwk', 'xwp',  'xx', 'xxe', 'xxx',  'xy', 'xy3', 'xyw', 'xyz', 'xz', 'y',  'y01', 'y02', 'y03', 'y04', 'y05', 'y06', 'y07', 'y08', 'y09', 'yab', 'yal', 'ybk', 'ychat', 'yenc', 'ymg', 'yml', 'ync', 'yps', 'yuv', 'yz', 'yz1', 'z',  'z01', 'z02', 'z1', 'z3', 'zap',   'zbd',   'zdb', 'zdb', 'zdct', 'zdg', 'zdl', 'zdp', 'zer', 'zfx', 'zgm', 'zhtml', 'zi', 'zif', 'zip', 'zipx', 'zix',  'zl?',   'zl', 'zls', 'zmc', 'zom', 'zon', 'zoo', 'zpk', 'zpl', 'zst', 'ztd', 'zvd', 'zvz', 'zxp', 'zz', 'zzt']
    new_dict = defaultdict(int)
    total_calc = 0
    
    for i in obj:

        filename = i['_source']['filename']
        if i['_source']['filename'] == 'NA':
            try:
                new_file_ext = i['_source']['fileext'].replace('.', '')
                new_dict[new_file_ext] += 1
                total_calc += 1

            except:
                pass

        extension = i['_source']['filename'].rsplit('.')[-1]
        if extension in callext:
            new_dict[extension] += 1
            total_calc += 1

    sorted_tuples = sorted(
        new_dict.items(), key=operator.itemgetter(1), reverse=True)
    sorted_dict = {k: v for k, v in sorted_tuples}
    new_obj = {'data': sorted_dict, 'total': total_calc}

    return new_obj


def mentionscalc(obj, total_post):
    """
    Counts number of mentions in a channel
    """
    new_dict = defaultdict(int)
    total_mention_post = 0
    total_mention_post_percent = 0
    
    for i in obj:
        message = i['_source']['message']

        re_pattern = "s+(@w+)s+"
        required_output = re.sub(
            r'@[A-Za-z]*\.co', "", message)
        mention_regex = re.findall(r"\s@(\w+)", required_output)
        
        if len(mention_regex) >= 1:
            total_mention_post += 1
            
            for name in mention_regex:
                if name != 'mail' and name != 'hotmail' and name != 'gmail' and name != 'yahoo' and name != 'username':
                    new_dict[name] += 1
    
    sorted_tuples = sorted(
        new_dict.items(), key=operator.itemgetter(1), reverse=True)
    sorted_dict = {k: v for k, v in sorted_tuples}
    
    if total_mention_post != 0:
        total_mention_post_percent = (total_mention_post/total_post) * 100

    new_obj = {'data': sorted_dict, 'total_mention_post': total_mention_post,
               'total_mention_post_percent': total_mention_post_percent}
    
    return new_obj


def hashcalc(obj, total_post):
    """
    Counts hashtags in a channel
    e.g #tesseract present N times in a channel
    """
    new_dict = defaultdict(int)
    total_mention_post = 0
    total_mention_post_percent = 0
    
    for i in obj:
        message = i['_source']['message']

        mention_regex = re.findall(r"#(\w+)", message)
        if len(mention_regex) >= 1:
            total_mention_post += 1
            
            for name in mention_regex:
                print(name)
                new_dict[name] += 1
    
    sorted_tuples = sorted(
        new_dict.items(), key=operator.itemgetter(1), reverse=True)
    sorted_dict = {k: v for k, v in sorted_tuples}
    
    if total_mention_post != 0:
        total_mention_post_percent = (total_mention_post/total_post) * 100

    new_obj = {'data': sorted_dict, 'total_hash_post': total_mention_post,
               'total_hash_post_percent': total_mention_post_percent}
    return new_obj



def email_extractor(user_id):
    """
    Extracts Emails from client_database for a given Auth token
    """
    try:
        conn = psycopg2.connect(database='client_database', user=database_username,
                                password=database_password, host=host_name, port=db_port)
        conn.autocommit = True
        cursor = conn.cursor()
    except Exception as e:
        conn.close()
        print("Database connection failed.")
        return False
        
    try:

        cursor.execute(
            f"SELECT email from client_database where userid='{user_id}' and isauthorized='True';")
        conn.commit()
        uname = cursor.fetchall()
        user_email = uname[0][0]
        # print(f"email is {userid}")
        user_email = uname[0][0]
        return user_email
        conn.close()

    except:
        return False


def scroll_auth_extractor(username):
    """
    Validates whether a user has scroll authorization for search
    """
    try:
        conn = psycopg2.connect(database='client_database', user=database_username,
                                password=database_password, host=host_name, port=db_port)
        conn.autocommit = True
        cursor = conn.cursor()
    except Exception as e:
        conn.close()
        print("Database connection failed.")
        return False
        
    try:

        cursor.execute(
            f"SELECT scroll_authorization from client_database where username='{username}';")
        conn.commit()
        uname = cursor.fetchall()
        user_scroll_auth = uname[0][0]
        # print(f"email is {userid}")
      
        return user_scroll_auth

    except:
        return False



def multimedia_crawler(link, id):
    """
    Real time image scraping from Channels to add to search posts
    in case multimedia is present in posts
    """
    new_link = 'None'
    if 't.me' in link:
        if '/s' in link:
            rep_link = link.replace('/s', '')
            new_link = f'{rep_link}/{id}?embed=1'
        else:
            new_link = f'{link}/{id}?embed=1'
    else:
        new_link = f'https://t.me/{link}/{id}?embed=1'

    try:
        url = requests.get(new_link).text

        soup = BeautifulSoup(url, 'lxml')
        main_parent = "None"
        
        try:
            main_parent = soup.find(
                'a', {'class': 'tgme_widget_message_photo_wrap'})['style']
        except:
            main_parent = soup.find(
                'i', {'class': 'link_preview_image'})['style']

        style = cssutils.parseStyle(main_parent)

        src = style['background-image']

        new_src = src.replace('url(', '').replace(')', '')
        print('new_src', new_src)

        return new_src
    except Exception as e:
        print(e)
        return False



def cred_mail_sender(email, username, password, date,remaining_day_msg=None):
    """
    sends Emails with automatically generated user/credentials to new users as well as expiration notice
    """
    if email == None or username == None or date == None:
        return 'Please provide valid parameters for the function to be executed'
    sender = 'tesseract@tesseractintelligence.com'
    recipients = [email]
    default_msg =" Thank you for deciding to try our Threat Intelligence Platform."
    new_password = password
    default_header = 'Account Credetials'
    if password is None:
        new_password='*****(Please refer to previous mail for password.)'
    if remaining_day_msg == 'expiration_notice':
        default_msg = f"""<b>Hello {username}</b> <br>,This is an automated reminder. You have not logged in our platform since registration, please log in once to remove the expiration date from your account. Your account will expire automatically if you do not log in our system within the expiry date as stated below."""
        default_header='Account Expiration Reminder'
    msg = Message(default_header, sender=sender, html=f'''
   <html>
    <head>
        <title>Mail</title>
    </head>
    <body style='
    /* font-family: "Roboto", sans-serif; */
    font-size: 16px;
    font-weight: 400;
    line-height: 1.5;
    color: #0d0c22;
    word-wrap: break-word;
    word-break: break-word;
    text-align: left;
    box-sizing: border-box;
    background-color: #f2f3f9;
    min-height: 700px;
    font-family: "Source Sans Pro","Helvetica Neue",Helvetica,Arial,sans-serif;
    line-height: 1.2;
    
    '>
        <div style="
        display: flex;
        -ms-flex-wrap: wrap;
        flex-wrap: wrap;
        margin-right: -0.75rem;
        margin-left: -0.75rem;
        --bs-gutter-x: 1.5rem;
        --bs-gutter-y: 0;
        margin-top: calc(var(--bs-gutter-y) * -1);
        " class ='row'>
        <div style="flex: 0 0 100%;
        width: 100%;
        min-height: 1px;
        padding-right: 0.75rem;
        padding-left: 0.75rem;
        "

         class='maincol'>
         <div style='
        margin-bottom: 1.5rem;
        width: 500px;
        display: flex;
        -ms-flex-direction: column;
        flex-direction: column;
        min-width: 0;
        word-wrap: break-word;
        
        border: 1px solid transparent;
        background-clip: border-box;
        border-radius: 5px;
        margin:0 auto;
        width: 600px;
         ' class='card'>

        
         <div style='padding: 10px; flex: 1 1 auto;
         margin: 0;
         background-color: #fff;
         margin-top:100px
         '>


         <div style='display: flex;
                    -ms-flex-wrap: wrap;
                    flex-wrap: wrap;
                    margin-right: -0.75rem;
                    margin-left: -0.75rem;
                    
                    
                    '
                     class='child row'>


            <div style='
                        width: 150px;
                        min-height: 1px;
                        text-align: center;'
                         class='col-2'>


                        <div style='
                        position: relative;
                        display: inline-block;
                        width: 120px;
                        height: 120px;
                        line-height: 2em;
                        vertical-align: middle;
                        padding-top: 8px;
                        border-radius: 7px;
                        color: #fff;
                        position: relative;
                        /* background: #6259ca !important;
                        border-color: #6a62cc !important; */
                        border: 1px solid #eaedf1 !important;
                        /* background: #6259ca !important;
                        border-color: #6a62cc !important; */
                        font-size: 1.33333333em;
                        margin-top: 30%;
                        

                    ' class='box for icon'>
                      <img width="120px" height='120px' src='https://api.recordedtelegram.com/static/images/tesseract.jpg'>
        

        </div>
    
            
        
        </div>
        <div style='width: 450px;
                    min-height: 1px;
                    margin-bottom: 30px;
                    ' class='col-10'>
                    <div style='margin-top: 0.25rem !important;'>

                <h4 style='font-size: 1.125rem;'>{default_header}</h4>
                <span>{default_msg}. <br>Please use the following credentials to log in to our <a style='color:blue' href='https://api.recordedtelegram.com'> https://api.recordedtelegram.com</a> </span>
                <p>Login Credentials :</p>
                <ol>
                    <li><b>Email:</b> {email}</li>
                    <li><b>Username : </b>{username}</li>
                    <li><b>Password :</b> {new_password}</li>
                    <li><b>Expiry Date :</b> {date}</li>

                  </ol>
     

            </div>
            
                
            
        
        </div>
    </div>
    <div style='text-align: left;padding-left: 8px;'>

    <img style='width:24px; height:22px; vertical-align: middle;' src="https://img.icons8.com/color/48/000000/info--v1.png">
    <span style='vertical-align: middle;'>Please note that the username and password are automatically generated and you can change them as soon as you log in.</span><br>

</div>
<div style='text-align: left; margin-top: 10px;padding-left: 8px;'>

    <img style='width:24px; height:22px; vertical-align: middle;' src="https://img.icons8.com/color/48/000000/info--v1.png">
    <span style='vertical-align: middle;'>Please also note that if you do not log into platform before the Expiry Date as stated above, your account will be deactivated automatically.</span><br>

</div>
<div style='text-align: left; margin-top: 10px;padding-left: 8px;'>

    <span style='vertical-align: middle;'>We are looking forward to talk to you soon.</span></div>


    <div style='text-align: left; margin-top: 10px; padding-left: 8px;'>

        <span style='vertical-align: middle;'>Regards,</span>
    
    </div>
    <div style='text-align: left; margin-top: 10px;padding-left: 8px;'>

        <span style='vertical-align: middle;'>Tesseract Intelligence</span><br>
        <span style='vertical-align: middle;'>Sofia, Bulgaria.</span><br>
        <span style='vertical-align: middle;'>www.tesseractintelligence.com</span><br>
    
    </div>
</div>

            </div>

        </div>

        </div>
        
    </body>
</html>
    ''',
                  recipients=recipients, )
    mail.send(msg)
    return True



def delete_id_mail(id):
    """
    deletes all user data from email_notification if the user's data has been deleted from databse permanently
    """
    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True) # include hostnames if different Elasticserver, e.g Elasticsearch(['192.168.1.20'])
    res = es.search(index='user_notification', size=10, body={
        "query": {
                    "term": {
                        "userid": id,
                    },

                    }
    })

    user_data = res['hits']['hits']
    
    if len(user_data) >= 1:
        try:
            delete_res = es.delete_by_query(index='user_notification', body=({
                "query": {
                    "term": {
                        "userid": {"value": id}

                    }
                }
            }))
            print(delete_res)

            return {'message': 'Data of the user was sucesfully deleted'}
        except:
            return {'message': 'Sorry could not delete the record of the user'}

    else:
        print({'message': 'No data of the user was found'})
        return {'message': 'No data of the user was found'}


def unique_channel_count(index_name, group='False'):
    """
    counts total No. of unique channels of the given index_name
    """
    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
    all_data = []
    for i in range(20):
        channel_query = es.search(index=index_name, size=0, body={
            'query': {
                "match": {
                    "is_group": group
                }
            },
            "aggs": {
                "unique_channels": {
                    "terms": {"field": "link.keyword",
                              "include": {
                                  "partition": i,
                                  "num_partitions": 20
                              },
                              "size": 10000}
                }
            }


        })
        response = channel_query
        new_res = response['aggregations']["unique_channels"]['buckets']
        for i in new_res:
            all_data.append(i)

    # print(viewed['aggregations']['group_by_month']['buckets'])

    return len(all_data)


def file_count_func(index_name, group='False'):
    """
    counts total No. of file posts of the given index_name
    """
    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
    file_count = es.count(index=index_name, body={
        "query": {
            "bool": {

                "must_not": {
                    "match": {
                        "filename": "None",

                    }
                },
                "must": {
                    "match": {
                        "is_group": group
                    }

                }
            }
        }
    }
    )
    return file_count['count']


def forwarded_data_count(index_name, group='False'):
    """
    counts total no of forwarded channels of the given index_name
    """
    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
    forwarded_count = es.count(index=index_name, body={
        "query": {
            "bool": {
                "must_not": {
                    "match": {
                        "forwardedfromchanid": "None"
                    }
                },
                "must": {
                    "match": {
                        "is_group": group
                    }

                }
            }
        }
    })
    return forwarded_count['count']


def generate_auth_header(abs_path,http_method,private_key,public_key,time_stamp):
    """
    Generates Auth header
    """
    string2hash = http_method + abs_path + time_stamp
    bkey = bytes(source=private_key, encoding='UTF-8')
    bpayload = bytes(source=string2hash, encoding='UTF-8')
    hmacsha1 = hmac.new(bkey, bpayload, hashlib.sha1).digest()
    base64encoded = base64.b64encode(hmacsha1).decode('UTF-8')
    auth_header = f'OWL {public_key}:{base64encoded}'
    return auth_header

def json_filter(data) -> dict:
    all_data = json.load(data)
    for i in range(len(all_data['data']['results'])):
        del all_data['data']['results'][i]['headers']
        del all_data['data']['results'][i]['hackishness']
    return all_data

def v2_perform_query_search(payload):
    """
    Darkowl API query for auth generation
    """
    host = 'api.darkowl.com'
    endpoint = '/api/v1/search'

    # Generate search string
    # search = payloadToString(payload)
    url = f'https://{host}{endpoint}{payload}'
    absPath = endpoint + payload

    date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')

    auth = generate_auth_header(absPath, 'GET', privateKey, publicKey, date)
    headers = {'Authorization': auth,
               'X-VISION-DATE': date, 'Accept': 'application/json'}
    r = requests.get(url, headers=headers)
    if r.status_code == 200:
        return r.json()
        # return_data = json_filter(json_data)
        # return return_data
    

def value_adder(bool_checker: bool, value: str, query: str, logical_value) -> str:
    mod_query = query
    if bool_checker is True:
        if logical_value == 'AND' or logical_value == 'OR' or logical_value == 'NOT':
            mod_query = f'{query} {logical_value} {value}'
        else:
            mod_query = f'{query}{logical_value}{value}'
    else:
        mod_query = f'{query}={value}'
    return mod_query



def additional_value_checker(name: str, value: str, logical_val: str) -> str:
    """
    structures the multiple input to the required format
    """
    new_value = f'{name}:{value}'
    logical_value = 'AND'
    if logical_val == '|':
        logical_value = 'OR'
    if name == 'query':
        new_value = f'{value}'
    print(type(value), name)
    if ',' in value or type(value) is list:
        multi_value = value
        if type(value) is str:
            value = value.replace('[', '').replace(']', '')
            multi_value = value.split(',')
        all_val = []

        for i in range(len(multi_value)):
            if i == 0:

                all_val.append(multi_value[i])
            else:
                all_val.append(logical_value)
                all_val.append(f'{multi_value[i]}')
        new_str = ' '.join(all_val)
        if name == 'query':
            new_value = f'({new_str})'
        else:
            new_value = f'{name}:({new_str})'
        print(new_value)
    return new_value


def multi_value_checker(regex: str, multi_val: list):
    """
    Validates a list on the basis of provided regex params and value
    """
    return_val = True
    for data in multi_val:
        if re.match(regex, data):
            print('Values is valid. so proceding to next value')
        else:
            return_val = False
    return return_val


def ip_validator(ip_add) -> bool:
    """
    Validate IP Address
    """

    regexIP = r'^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( [0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)'
    if type(ip_add) is list:
        return multi_value_checker(regexIP, ip_add)
    if re.match(regexIP, ip_add):
        return True

    else:
        return False


def email_validator(email) -> bool:
    """
    Validate Email
    """

    regex = re.compile(
        r'([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+')

    if type(email) is list:
        return multi_value_checker(regex, email)
    if re.match(regex, email):
        return True

    else:
        return False

def redis_data_saver(object, user_id, search):
    try:
        r = redis.Redis(db=1)
        curr_time = datetime.datetime.now()
        key_str = f'{user_id}-{curr_time}${search}'
        encode_code = cryptocode.encrypt(str(key_str), '#random_pass1&*$@')
        r.setex(key_str, datetime.timedelta(minutes=10), str(object))
        print(encode_code)
        return encode_code

    # r.setex('hats', timedelta(minutes=1), str(hats))
    except:
        return 'None'


def stats_decorator(func):
    """
    decorator function for stats
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        search_type = request.json.get('search_type', None)
        qtext = request.json.get('qtext', None)
        if qtext is None:
            return jsonify({'errormsg': 'Please send valid parameters'}), 403
       

        default_query = {
            "terms": {
                "link": [qtext]
            }
        }
        if search_type == 'link' or search_type == None:
            qtext_filter = channel_name_converter(qtext)
            default_query = {
                "terms": {
                    "link": qtext_filter
                }
            }
        elif search_type == 'channel name':
            qtext = qtext.lower()
            default_query = {
                "match_phrase": {
                    "conv_name": qtext
                }
            }
        elif search_type == 'id':
            default_query = {
                "term": {
                    "to_id": qtext
                }
            }
        result = func(default_query, *args, **kwargs)
        return result
    return wrapper


def maxResults_decorator(func):
    """
    decorator function for max_results
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        maxResults = request.json.get('max', None)
        
        if str(maxResults).isnumeric():
            if maxResults < 0:
                return jsonify({"errormsg":"Please enter a numeric value greater than 0."}),403
        else:
            return jsonify({"errormsg":"Please enter a numeric value greater than 0. Strings not allowed."}),403

        # Access the identity of the current user with get_jwt_identity
        jwt_all = get_jwt_identity()
        current_user = jwt_all[0]
        
        # connecting to the database
        try:
            conn = psycopg2.connect(database= 'client_database' , user= database_username , password= database_password , host= host_name, port= db_port)
            conn.autocommit = True
            cursor = conn.cursor()
        except Exception as e:
            conn.close()
            print("Database connection failed.")

        cursor.execute(f"SELECT max_results from client_database where username='{current_user}';")
        conn.commit()
        dBmax_Results = cursor.fetchall()[0][0]
        print(dBmax_Results)

        if maxResults > dBmax_Results:
            return jsonify({"errormsg":"Your search limit quota should not exceed than what is provided with your subscription. Please try a lower value, or contact us at tesseract@tesseractintelligence.com"}),403

        result = func(*args, **kwargs)
        return result
    return wrapper


def category_mapper(category_name):
    """
    Maps category to the ES server
    """
    if category_name == 'hacking':
        return "telegram2_alias"
    elif category_name == "extremepolitical":
        return "extremepolitical2_alias"
    else:
        return category_name
'''
Converts the old_index to new_index
'''
def old_to_new_category(index_name):
    if '_v2' not in index_name and '_alias' not in index_name:
        if index_name == 'hacking':
            return "telegram2_alias"
        elif index_name == "extremepolitical":
            return "extremepolitical2_alias"
        new_index = f'{index_name}_alias'
        return new_index
    else:
        return index_name
def reverse_category_mapper(category_name):
    """
    Reverses Category Map
    """
    if category_name == 'telegram2_alias' or category_name == 'telegram2_v2' or category_name == 'telegram2':
            return "hacking"
    elif category_name == "extremepolitical2_alias" or category_name == "extremepolitical2_v2" or category_name == 'extremepolitical2':
            return "extremepolitical"
    else:
            try:
                if '_alias' in category_name:
                    new_category = category_name.replace('_alias','')
                    return new_category
                elif '_v2' in category_name:
                    new_category = category_name.replace('_v2','')
                    return new_category
                else:
                    return category_name
            except:
                return category_name 



def category_access_decorator(func):
    """
    decorator function for category_access
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        # Access the identity of the current user with get_jwt_identity
        jwt_all = get_jwt_identity()
        current_user = jwt_all[0]
        
        # connecting to the database
        try:
            conn = psycopg2.connect(database= 'client_database' , user= database_username , password= database_password , host= host_name, port= db_port)
            conn.autocommit = True
            cursor = conn.cursor()
        except Exception as e:
            conn.close()
            print("Database connection failed.")

        # fetch categories a customer has access to
        cursor.execute(f"SELECT category_access from client_database where username='{current_user}';")
        conn.commit()
        cat_access = cursor.fetchall()[0][0]

        # fetch customer type
        cursor.execute(f"SELECT customer_type from client_database where username='{current_user}';")
        conn.commit()
        customer_type_ = cursor.fetchall()[0][0]
        
        # customer category input
        index_name_user = request.json.get('selectCategory', 'all')   
        
        if cat_access != 'all' and index_name_user != 'all':

            # checks if the input list of categories matches with those stored in the database
            # if a match, just pass, else throw an error that the customer isn't allowed to access that particular category.
            cat_access = ast.literal_eval(cat_access)
            print(cat_access)
            
            for every_cat in index_name_user:
                new_every_cat = category_mapper(every_cat)
                print(new_every_cat)
                new_category = f'{new_every_cat}'.replace('_alias','')
                if new_category not in cat_access:
                    return jsonify({"errormsg":f"You do not have access to the {every_cat} category. Please contact {COMPANY_EMAIL} to add this category to your subscription."}), 403
        
        # empty index list to hold all index names for search
        index_name = [] 
            
        try:
            # only allow those categories for the paid customer that are bought by them, if they select "all"
            if customer_type_ == 'PAID_CUSTOMER' and (index_name_user == None or index_name_user == 'all'):
                if cat_access == 'all':
                    index_name = all_index_name
                else:
                    all_user_index = ast.literal_eval(cat_access)
                    index_name =  [f'{x}_alias' for x in all_user_index]
            
            # by default trial accounts will have all category access, if they select "all"
            elif cat_access == 'all' and customer_type_ == 'TRIAL_CUSTOMER' and (index_name_user == None or index_name_user == 'all'):
                    index_name = all_index_name
            
            elif cat_access != 'all' and customer_type_ == 'TRIAL_CUSTOMER' and index_name_user == 'all':
                    all_user_index = ast.literal_eval(cat_access)
                    index_name =  [f'{x}_alias' for x in all_user_index]
            
            else:
                # if the customer hasn't selected "all", then change the index names according to the category names
                # TODO: reduce this step by mapping the category names provided to what is available in the server later.
                
                if "hacking" not in index_name_user and "financials" not in index_name_user and "extremepolitical" not in index_name_user and "religion_spirituality" not in index_name_user and "pharma_drugs" not in index_name_user and "criminal_activities" not in index_name_user and "information_technology" not in index_name_user and "cyber_security" not in index_name_user and "science_index" not in index_name_user and "betting_gambling" not in index_name_user and "adult_content" not in index_name_user and "movies" not in index_name_user and "blogs_vlogs" not in index_name_user and "education" not in index_name_user and "travelling" not in index_name_user and "gaming" not in index_name_user  and "music" not in index_name_user and "lifestyle" not in index_name_user and "books_comics" not in index_name_user and "fashion_beauty" not in index_name_user and "design_arch" not in index_name_user and "humor_entertainment" not in index_name_user and "culture_events" not in index_name_user:
                    return jsonify({"errormsg":"Uh oh, careful with the fields in your request. It has to be exact. Refer the API documentation provided to you. Error from category access verification module."}),403
                
                if "hacking" in index_name_user:
                    index_name.append("telegram2_alias")
                
                if "financials" in index_name_user:
                    index_name.append("financials_alias")

                if "extremepolitical" in index_name_user:
                    index_name.append("extremepolitical2_alias")
                
                if "religion_spirituality" in index_name_user:
                    index_name.append("religion_spirituality_alias")
                
                if "pharma_drugs" in index_name_user:
                    index_name.append("pharma_drugs_alias")
                
                if "criminal_activities" in index_name_user:
                    index_name.append("criminal_activities_alias")

                if "information_technology" in index_name_user:
                    index_name.append("information_technology_alias")

                if "cyber_security" in index_name_user:
                    index_name.append("cyber_security_alias")

                if "science_index" in index_name_user:
                    index_name.append("science_index_alias")

                if "betting_gambling" in index_name_user:
                    index_name.append("betting_gambling_alias")

                if "adult_content" in index_name_user:
                    index_name.append("adult_content_alias")
                
                if "blogs_vlogs" in index_name_user:
                    index_name.append("blogs_vlogs_alias")
                
                if "education" in index_name_user:
                    index_name.append("education_alias")
                
                if "movies" in index_name_user:
                    index_name.append("movies_alias")
                
                if "travelling" in index_name_user:
                    index_name.append("travelling_alias")
                
                if "gaming" in index_name_user:
                    index_name.append("gaming_alias")
                
                if "music" in index_name_user:
                    index_name.append("music_alias")
                
                if "lifestyle" in index_name_user:
                    index_name.append("lifestyle_alias")
                
                if "books_comics" in index_name_user:
                    index_name.append("books_comics_alias")
                
                if "fashion_beauty" in index_name_user:
                    index_name.append("fashion_beauty_alias")
                
                if "design_arch" in index_name_user:
                    index_name.append("design_arch_alias")
                
                if "humor_entertainment" in index_name_user:
                    index_name.append("humor_entertainment_alias")
                
                if "culture_events" in index_name_user:
                    index_name.append("culture_events_alias")

            
            
        except Exception as e:
            if customer_type_ == 'PAID_CUSTOMER':
                index_name =  cat_access
            else:
                index_name =  all_index_name
        

        result = func(index_name,*args, **kwargs)
        return result
    return wrapper


def index_decorator(func):
    """
    decorators that verifies valid values and param before any ingestion activities
    """
    @wraps(func)
    def inner_func(*args, **kwargs):
        if not request.is_json:
            return jsonify({"errormsg": "Missing JSON in request"}), 403
         # Logging for /v2/indexer
        f = open("indexerlogs.txt", "a", encoding='UTF-8')
        #data_to_log = f'''DATETIME:{datetime.datetime.utcnow()}\nIPADDRESS:{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}\nUsername:{username}\n\n'''
        data_to_log = {"DATETIME": f"{datetime.datetime.utcnow().isoformat()+'+00:00'}",
                       "IPADDRESS": f"""{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}""", "ENDPOINT": "/v2/indexer/education_index "}
        f.write(str(data_to_log))
        f.write('\n')
        f.close()

        secret_code = request.json.get('passcode', None)
        idx = request.json.get('id', None)
        data = request.json.get('data', None)

        if secret_code == None:
            return jsonify({"errormsg": "Uh oh, careful with the fields in your request. It has to be exactly 'secret_code'."}), 403

        if idx == None:
            return jsonify({"errormsg": "Uh oh, careful with the fields in your request. It has to be exactly 'id'."}), 403

        if data == None:
            return jsonify({"errormsg": "Uh oh, careful with the fields in your request. It has to be exactly 'data'."}), 403

        if idx.isalnum() and len(idx) == 32:  # For MD5 hashes
            pass
        else:
            return jsonify({"errormsg": "Hashes should be alphanumberic and length should be 32, i.e MD5."}), 403

        if secret_code == '@lazlxEtIcS3A9rchIydzXiqg2u21fr0m':
            pass
        else:
            return jsonify({"errormsg": "Please enter the correct secret_code"}), 403
        return_val = func(idx, data, *args, **kwargs)
        return return_val

    return inner_func


def regex_validator(qtext, params):
    """
    verifies Regex input
    qtext -> regex query
    params -> e.g field names like message, date etc.
    """
    checks = re.compile('[`=<>?/\|@#]')
    
    checkkey = len(re.findall(checks, qtext))
    if  checkkey > 0 and params == 'message':
        print('activated')
        return f'{params}.raw'
    if ' ' in qtext:
        return f'{params}.keyword'
    else:
        return params
    
def search_validator(qtext, params):
    """
    Verifies Search regex input
    """
    print(qtext)
    
    checks = re.compile('[`=<>?/\|@#,]')
    checkkey = len(re.findall(checks, qtext))
    print(checkkey,'<---validator--->')
    if  checkkey > 0 and params == 'message':
        print('activated')
        return f'{params}.raw'
    else:
        return params
    
def alert_validator(txt):
    if txt is None:
        return False    

    double_space_remover = re.sub(re.compile('\s{2,}'),' ',txt)
    open_braket_space_remover = re.sub(re.compile('\([^\w+]'),'(',double_space_remover)
    close_bracket_space_remover = re.sub(re.compile('[^\w+]\)'),')',open_braket_space_remover)

    if '(' in close_bracket_space_remover or ')' in close_bracket_space_remover:
        if len(re.findall('[\(]',close_bracket_space_remover)) != len(re.findall('[\)]',close_bracket_space_remover)):
            return False

    print(close_bracket_space_remover)
    return close_bracket_space_remover

def logical_checker(arr):
    for i in range(len(arr)):
        if (i%2 != 0):
            if arr[i] != 'AND' and arr[i] != 'OR':
                return False
                
    return True

def logical_conv(txt):
    new_word = txt
    if 'or'  in new_word:
        new_word='OR'
    if 'and' in new_word:
        new_word='AND'
    return new_word
           

def logical_alert(qtext,double_brac= False):
    try:
        filtered_text = alert_validator(qtext)
        new_obj = None
        if filtered_text == False:
            new_obj = {'message':'Invalid input/parameter for the route /v2/posts mode3. Refer the documentation for more information on parameters. API v2.0.3 '}
            return new_obj

        try:
            if double_brac is False:
                if len(filtered_text.split('(')) > 2:
                    new_obj = {'message':'Only one conditional bracket is allowed. Refer the documentation for more information . API v2.0.3 '}
                    return new_obj
        except:
            pass

        conv_arr = filtered_text.split(' ')
        new_arr = [logical_conv(data) for data in conv_arr]
        new_cp = new_arr.copy()
        operator_validator = logical_checker(new_cp)
        print(operator_validator)
        if operator_validator == False:
            new_obj = {'message':'Invalid parameter for the route. Refer the documentation for more information on parameters. API v2.0.3 '}
            return new_obj
        conv_str = ' '.join(new_cp)
        qtext = conv_str
        new_obj = {'query':qtext}
        return new_obj
    except:
        new_obj = {'message':'Invalid parameter for the route. Refer the documentation for more information on parameters. API v2.0.3 '}
        return new_obj


def account_category_returner(userid):
    index_name = all_index_name
    try:
        conn = psycopg2.connect(database= 'client_database' , user= database_username , password= database_password , host= host_name, port= db_port)
        conn.autocommit = True
        cursor = conn.cursor()
    except Exception as e:
        conn.close()
        print("Database connection failed.")
    
    # fetch categories a customer has access to
    cursor.execute(f"SELECT category_access from client_database where userid='{userid}';")
    conn.commit()
    cat_access = cursor.fetchall()[0][0]

    cursor.execute(f"SELECT customer_type from client_database where userid='{userid}';")
    conn.commit()
    customer_type_ = cursor.fetchall()[0][0]

    if customer_type_ == 'PAID_CUSTOMER':
        if cat_access == 'all':
            index_name = all_index_name
        else:
            index_name =  ast.literal_eval(cat_access)

    elif cat_access == 'all' and customer_type_ == 'TRIAL_CUSTOMER':
            index_name = all_index_name
    
    elif cat_access != 'all' and customer_type_ == 'TRIAL_CUSTOMER':
            index_name = ast.literal_eval(cat_access)
    return index_name

#function to return userid from the provided parameter
def user_id_returner(username):
    try:
        conn = psycopg2.connect(database='client_database', user=database_username,
                                    password=database_password, host=host_name, port=db_port)
        try:
            conn.autocommit = True
            cursor = conn.cursor()
            cursor.execute(
                f"SELECT userid from client_database where username='{username}';")
            conn.commit()
            uname = cursor.fetchall()
            user_id = uname[0][0]
            # print(f"email is {userid}")
            user_id = uname[0][0]
            conn.close()
            return user_id
        except:
            conn.close()
            return False
    except:
        return False
def email_validator(email):
    regex = re.compile(
        r"([-!#-'*+/-9=?A-Z^-~]+(\.[-!#-'*+/-9=?A-Z^-~]+)*|\"([]!#-[^-~ \t]|(\\[\t -~]))+\")@([-!#-'*+/-9=?A-Z^-~]+(\.[-!#-'*+/-9=?A-Z^-~]+)*|\[[\t -Z^-~]*])")
    try:
        if re.match(regex, email):
            return True
    except:
        return False
    return False


def pagination_checker_limiter(username):
    try:
        #avoiding pagination reduction for administrator
        if username == 'administrator':
            return True
 
        conn = psycopg2.connect(database='client_database', user=database_username,
                                    password=database_password, host=host_name, port=db_port)
        try:
            cursor = conn.cursor()
            cursor.execute(
                f"SELECT pagination_limit,company_name from client_database where username='{username}';")
            uname = cursor.fetchall()
            page_limit = uname[0][0]
            company_name = uname[0][1]
            
            if int(page_limit) < 1:
                conn.close()
                return False
            
            else:
                try:
                    new_page_limit = int(page_limit) - 1

                    db_obj  = f"UPDATE client_database set pagination_limit={new_page_limit} where username='{username}';"
                    
                    if company_name != 'None': 
                        db_obj = f"UPDATE client_database set pagination_limit={new_page_limit} where company_name='{company_name}';"
                    
                    cursor.execute(db_obj)
                    conn.commit()
                    conn.close()
                    return page_limit
                except:
                    conn.close()
                    return False
        except:
            conn.close()
            return False
    except:
        return False
#########################################################################################################

@app.route("/", methods=['GET','POST'])
def my_index():
    """
    Main Index route
    """
    return flask.render_template('index.html')

@app.route("/dashboard", methods=['GET','POST'])
#@jwt_required  # check from the frontend if /dashboard is accessible without login
def my_ind():
    return flask.render_template('index.html')

@app.route("/notification", methods=['GET','POST'])
def notification_frontend():
    return flask.render_template('index.html')

@app.route("/signup", methods=['GET','POST'])
def my_i():
    return flask.render_template('index.html')

@app.route("/admin")
def adminadmin():
    return flask.render_template('index.html')

@app.route("/prof")
def profadmin():
    return flask.render_template('index.html')

# User Profile
@app.route("/userprof")
def front_userprof():
    return flask.render_template('index.html')

@app.route("/side")
def side_channels():
    return flask.render_template('index.html')

@app.route("/indv_page")
def indv_page():
    return flask.render_template('index.html')

@app.route("/channel")
def front_channel():
    return flask.render_template('index.html')

@app.route("/page")
def page():
    return flask.render_template('index.html')

@app.route("/admin/custom")
def customage():
    return flask.render_template('index.html')

@app.route("/custom")
def user_custom():
    return flask.render_template('index.html')

@app.route("/users", methods=['GET','POST'])
def user_stats_front_end():
    return flask.render_template('index.html')

# API to get list of IP addresses that are attacking SSH 22 port of the server
@app.route('/v2/accessdenylogs', methods=['GET'])
#@jwt_required
def sshdenylogs():
    try:
        b = subprocess.run("cat /var/log/auth.log | grep 'DENY'",shell=True, capture_output=True)
        list_data = str(b.stdout,'UTF-8').split('\n')[::-1]
        
        print(list_data)
        
        master_list = []

        for m in list_data:
            if m == '':
                pass
            else:
                master_list.append(re.findall('DENY sshd connection from [0-9.]+ \\([A-Z]+\\)',m)[0])

        print(master_list)

        return json.dumps(master_list,ensure_ascii=False, indent=0, sort_keys=False).encode('utf-8'), 200, {'Content-Type': 'application/json'}
    except Exception as e:
        return "Something happened. Are you trying to hack me?"



@app.route('/v2/acceptedlogs', methods=['GET'])
#@jwt_required
def sshacceptedlogs():
    """
    Checks if any unauthorized usernames gained access to the server through SSH. 
    This API can be used to create alerts for the server.
    """
    
    try:
        b = subprocess.run('cat /var/log/auth.log | grep "Accepted password for [a-z]* from [0-9.]*"',shell=True, capture_output=True)
        list_data = str(b.stdout,'UTF-8').split('\n')[::-1]
        
        print(list_data)
        
        master_list = []

        userlist = {} 

        for m in list_data:
            if 'root' in m:
                userlist["SUPERMAN"] = 'He was there.'
            elif 'nataliewise' in m:
                userlist["SUPERWOMAN"] = 'She was there.'
            elif m == '':
                pass
            else:
                master_list.append(f"UNAUTHORZIED ACCESS FROM : {m}")

        print(master_list)

        if userlist == []:
            userlist = "Also nobody familiar had logged in past few days."
        
        if master_list == []:
            return json.dumps(f"No unauthorized access so far. P.S. {userlist} ",ensure_ascii=False, indent=0, sort_keys=False).encode('utf-8'), 200, {'Content-Type': 'application/json'}
        else:
            return json.dumps(master_list,ensure_ascii=False, indent=0, sort_keys=False).encode('utf-8'), 200, {'Content-Type': 'application/json'}
    except Exception as e:
        return "Something happened. Are you trying to hack me?"

##################################################################################################################
"""
Get all Client ids
"""
# curl
# curl -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MzA5MTQyMTIsIm5iZiI6MTYzMDkxNDIxMiwianRpIjoiZTk1YzIzOWQtZDNlOC00MjEzLWE0ZmMtODM0MWIyMjI5MGIyIiwiZXhwIjoxNjMwOTM1ODEyLCJpZGVudGl0eSI6ImFkbWluaXN0cmF0b3IiLCJmcmVzaCI6ZmFsc2UsInR5cGUiOiJhY2Nlc3MifQ.39FKtfz0kvE8_kfgcgD67RX7ie2N3IffGE4TcD9cBKs' -H "Content-Type: application/json" -X POST http://localhost:5000/v2/admin/getallclients
@app.route('/v2/admin/getallclients', methods=['POST'])
@jwt_required
def getallclients():
    # Access the identity of the current user with get_jwt_identity
    jwt_all = get_jwt_identity()
    current_user = jwt_all[0]
    print(f"""{colors.green} User {current_user} has successfully logged. Accessing /v2/admin/getallclients API from IP: {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} {colors.default}""")
    if current_user == 'administrator':
        # connecting to the database
        try:
            conn = psycopg2.connect(database= 'client_database' , user= database_username , password= database_password , host= host_name, port= db_port)
            conn.autocommit = True
            cursor = conn.cursor()
        except Exception as e:
            conn.close()
            print("Database connection failed.")

        try:
            cursor.execute(f"SELECT userid, username, email, isauthorized, isunlimited, ratelimit, tokengen, dateofregistration, ipaddress, lastloginipaddress, last_logged_in_at,customer_type,account_expiry_date  from client_database;")
            conn.commit()
            uname = cursor.fetchall()
            return_list = []
            for m in uname:
                data = {"userid":m[0],"username" : f"{m[1]}",  "email" : f"{m[2]}", "authorization": f"{m[3]}", "superadmin" : f"{m[4]}", "ratelimit" : f"{m[5]}", "tokensgenerated": f"{m[6]}", "dateofregistration":f"{m[7]}", "signupip":f"{m[8]}", "lastloginip":f"{m[9]}", "lastlogin_at":f"{m[10]}","customer_type":f"{m[11]}","acc_expiry_date":f"{m[12]}"}
                return_list.append(data)

            conn.close()
            return jsonify(return_list), 200, {'Content-Type': 'application/json'}
        except Exception as e:
            conn.close()
            return jsonify("Something happened while selecting lists of clients. at /v2/admin/getallclients"), 200, {'Content-Type': 'application/json'}
    else:
        return jsonify("administrator is not logged in."), 200, {'Content-Type': 'application/json'}



"""
Get individual client id 
"""
# curl
# curl -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MzA5MTQyMTIsIm5iZiI6MTYzMDkxNDIxMiwianRpIjoiZTk1YzIzOWQtZDNlOC00MjEzLWE0ZmMtODM0MWIyMjI5MGIyIiwiZXhwIjoxNjMwOTM1ODEyLCJpZGVudGl0eSI6ImFkbWluaXN0cmF0b3IiLCJmcmVzaCI6ZmFsc2UsInR5cGUiOiJhY2Nlc3MifQ.39FKtfz0kvE8_kfgcgD67RX7ie2N3IffGE4TcD9cBKs' -H "Content-Type: application/json" -d '{"id":"1"}' -X POST http://localhost:5000/v2/admin/getallclients
@app.route('/v2/getclient', methods=['POST'])
@jwt_required
def getclient():

    id = request.json.get('id', None)
    if not id:
        return jsonify({"errormsg": "Missing or broken 'id' parameter"}), 403
    
    print("ID...",id)
    if str(id).isnumeric() == True or id== 'None' :
        pass
    else:
        return jsonify({"errormsg": "id should be a positive number."}), 403

    # Access the identity of the current user with get_jwt_identity
    jwt_all = get_jwt_identity()
    current_user = jwt_all[0]
    print(f"""{colors.green} User {current_user} has successfully logged. Accessing /v2/getclient API from IP: {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} {colors.default}""")
    
    # connecting to the database
    try:
        conn = psycopg2.connect(database= 'client_database' , user= database_username , password= database_password , host= host_name, port= db_port)
        conn.autocommit = True
        cursor = conn.cursor()
    except Exception as e:
        conn.close()
        print("Database connection failed.")

    try:
        if current_user == 'administrator' and id != 'None':
            cursor.execute(f"SELECT userid, username, email, isauthorized, isunlimited, ratelimit, tokengen, dateofregistration, ipaddress, lastloginipaddress, persistent_dailylimit, breached_ratelimit, forums_ratelimit, reportgenerator_ratelimit, darkowl_ratelimit, max_results,channelsearch_ratelimit, category_access, customer_type, company_name, pagination_limit from client_database where userid='{id}';")
            conn.commit()
            uname = cursor.fetchall()
            return_list = []

            for m in uname:
                data = {"userid": m[0],"username" : f"{m[1]}",  "email" : f"{m[2]}", "authorization": f"{m[3]}", "superadmin" : f"{m[4]}", "ratelimit" : f"{m[5]}", "tokensgenerated": f"{m[6]}", "dateofregistration":f"{m[7]}", "signupip":f"{m[8]}", "lastloginip":f"{m[9]}", "persistent_daily":f"{m[10]}", "breached_access_limit":f"{m[11]}", "forums_access_limit":f"{m[12]}", "reportgenerator_ratelimit":f"{m[13]}", "darkweb_ratelimit":f"{m[14]}", "max_results_per_search_query":f"{m[15]}","max_changroup_search_ratelimit":f"{m[16]}","category_access":f"{m[17]}", "customer_type":f"{m[18]}","company_name":f"{m[19]}","pagination_limit":f"{m[20]}"}
                return_list.append(data)

            if return_list == []:
                conn.close()
                return jsonify({"Error":"The requested id does not exist."}), 404 , {'Content-Type': 'application/json'}

            conn.close()
            return jsonify(return_list), 200, {'Content-Type': 'application/json'}
        
        else:
            cursor.execute(f"SELECT userid, username, email, isauthorized, isunlimited, ratelimit, tokengen, dateofregistration, ipaddress, lastloginipaddress, darkowl_ratelimit, max_results, channelsearch_ratelimit, category_access, customer_type, company_name, pagination_limit from client_database where username='{current_user}';")
            conn.commit()
            uname = cursor.fetchall()
            print(uname)
            return_list = ''

            for m in uname:
                data = {"userid":m[0],"username" : f"{m[1]}",  "email" : f"{m[2]}", "authorization": f"{m[3]}", "superadmin" : f"{m[4]}", "ratelimit" : f"{m[5]}", "tokensgenerated": f"{m[6]}", "dateofregistration":f"{m[7]}", "signupip":f"{m[8]}", "lastloginip":f"{m[9]}", "darkweb_ratelimit":f"{m[10]}", "max_results_per_search_query":f"{m[11]}", "max_changroup_search_ratelimit":f"{m[12]}","category_access":f"{m[13]}","customer_type":f"{m[14]}","company_name":f"{m[15]}","pagination_limit":f"{m[16]}"}
                return_list = data

            if return_list == '':
                conn.close()
                return jsonify({"Error":"You can't access other user details except your own."}), 200, {'Content-Type': 'application/json'}

            return jsonify(return_list), 200, {'Content-Type': 'application/json'}
        
    except Exception as e:
        conn.close()
        return jsonify("Something happened while selecting lists of clients. at /v2/getclient"), 200, {'Content-Type': 'application/json'}


"""
Delete Individual Clients
"""
# curl
# curl -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MzA5MTQyMTIsIm5iZiI6MTYzMDkxNDIxMiwianRpIjoiZTk1YzIzOWQtZDNlOC00MjEzLWE0ZmMtODM0MWIyMjI5MGIyIiwiZXhwIjoxNjMwOTM1ODEyLCJpZGVudGl0eSI6ImFkbWluaXN0cmF0b3IiLCJmcmVzaCI6ZmFsc2UsInR5cGUiOiJhY2Nlc3MifQ.39FKtfz0kvE8_kfgcgD67RX7ie2N3IffGE4TcD9cBKs' -H "Content-Type: application/json" -d '{"id":"1"}' -X POST http://localhost:5000/v2/admin/getallclients
@app.route('/v2/admin/deleteclient', methods=['POST'])
@jwt_required
def deleteclient():

    id = request.json.get('id', None)
    if not id:
        return jsonify({"errormsg": "Missing or broken 'id' parameter"}), 403
    
    print("ID...",id)
    if str(id).isnumeric() == True :
        pass
    else:
        return jsonify({"errormsg": "id should be a positive number."}), 403

    # Access the identity of the current user with get_jwt_identity
    jwt_all = get_jwt_identity()
    current_user = jwt_all[0]
    print(f"""{colors.green} User {current_user} has successfully logged. Accessing /v2/deleteclient API from IP: {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} {colors.default}""")
    
    # connecting to the database
    try:
        conn = psycopg2.connect(database= 'client_database' , user= database_username , password= database_password , host= host_name, port= db_port)
        conn.autocommit = True
        cursor = conn.cursor()
    except Exception as e:
        conn.close()
        print("Database connection failed.")

    try:
        if current_user == 'administrator':
            cursor.execute(f"SELECT userid from client_database where username='administrator';")
            conn.commit()
            uname = cursor.fetchall()
            useridadmin = uname[0][0]
            print(f"admin id is {useridadmin}")

            print(useridadmin, id , type(useridadmin), type(id))
            if useridadmin != int(id) :
                cursor.execute(f"DELETE from client_database where userid='{id}';")
                conn.commit()
                conn.close()

                try:
                    delete_user_mail = delete_id_mail(id)
                    if delete_user_mail['message'] == 'Sorry could not delete the record of the user':
                        return jsonify({"Error":"Sorry, Could not delete users record from other databses ..."}), 403 , {'Content-Type': 'application/json'}

                except:
                    return jsonify({"Error":"Sorry, Could not delete users record from other databses ..."}), 403 , {'Content-Type': 'application/json'}

                

                try:
                    # log deletion
                    with open("deleteaccountslogs.txt","a") as deletelogs:
                        ipadd = str(request.environ.get("HTTP_X_REAL_IP", request.remote_addr))
                        deletedby = current_user
                        dateandtime = datetime.datetime.now(timezone.utc).isoformat()
                        logs_data = f"Deleted useriD {id} from {ipadd} by {current_user} on {dateandtime} "
                        deletelogs.write(logs_data)
                        deletelogs.write("\n")
                except Exception as e:
                    with open("accounterrors_deletion.txt","a") as deletionlogs:
                        deletionlogs.write(str(e))
                        deletelogs.write("\n")

                return jsonify({"Success":"The requested user has been deleted from the system."}), 200 , {'Content-Type': 'application/json'}
            else:
                conn.close()
                return jsonify({"Error":"You can't delete yourself from the system. Delete yourself manually from the server."}), 403 , {'Content-Type': 'application/json'}
        else:
            conn.close()
            return jsonify({"Error":"You can't access other user details except your own."}), 200, {'Content-Type': 'application/json'}

    except Exception as e:
        conn.close()
        return jsonify("Something happened while selecting lists of clients. at /v2/admin/deleclient"), 200, {'Content-Type': 'application/json'}

######################################################################################################################################################

"""
Get id of oneself
"""
# curl
# curl -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MzA5MTQyMTIsIm5iZiI6MTYzMDkxNDIxMiwianRpIjoiZTk1YzIzOWQtZDNlOC00MjEzLWE0ZmMtODM0MWIyMjI5MGIyIiwiZXhwIjoxNjMwOTM1ODEyLCJpZGVudGl0eSI6ImFkbWluaXN0cmF0b3IiLCJmcmVzaCI6ZmFsc2UsInR5cGUiOiJhY2Nlc3MifQ.39FKtfz0kvE8_kfgcgD67RX7ie2N3IffGE4TcD9cBKs' -H "Content-Type: application/json" -X POST http://localhost:5000/v2/getselfid
@app.route('/v2/getselfid', methods=['POST'])
@jwt_required
def getselfid():

    # Access the identity of the current user with get_jwt_identity
    jwt_all = get_jwt_identity()
    current_user = jwt_all[0]
    print(f"""{colors.green} User {current_user} has successfully logged. Accessing /v2/getselfid API from IP: {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} {colors.default}""")
    
    # connecting to the database
    try:
        conn = psycopg2.connect(database= 'client_database' , user= database_username , password= database_password , host= host_name, port= db_port)
        conn.autocommit = True
        cursor = conn.cursor()
    except Exception as e:
        conn.close()
        print("Database connection failed.")

    try:
        if current_user != 'administrator':

            cursor.execute(f"SELECT userid from client_database where username='{current_user}';")
            conn.commit()
            uname = cursor.fetchall()
            userid_not_admin = uname[0][0]
            print(f"userid is {userid_not_admin}")
            conn.close()
            results = {"username":f"{current_user}", "id":f"{userid_not_admin}"}
            return jsonify(results), 200 , {'Content-Type': 'application/json'}
        
        else:
            conn.close()
            return jsonify({"Unauthorized":"Super users should use another API. message from /v2/getselfid"}), 403 , {'Content-Type': 'application/json'}

    except Exception as e:
        conn.close()
        print(e)
        return jsonify("Something happened while fetching profile ID."), 200, {'Content-Type': 'application/json'}

###########################################################################################################################################################
"""
Get account_type of user
"""
# curl
# curl -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MzA5MTQyMTIsIm5iZiI6MTYzMDkxNDIxMiwianRpIjoiZTk1YzIzOWQtZDNlOC00MjEzLWE0ZmMtODM0MWIyMjI5MGIyIiwiZXhwIjoxNjMwOTM1ODEyLCJpZGVudGl0eSI6ImFkbWluaXN0cmF0b3IiLCJmcmVzaCI6ZmFsc2UsInR5cGUiOiJhY2Nlc3MifQ.39FKtfz0kvE8_kfgcgD67RX7ie2N3IffGE4TcD9cBKs' -H "Content-Type: application/json" -X POST http://localhost:5000/v2/getselfid
@app.route('/v2/getaccounttype', methods=['POST'])
@jwt_required
def getaccounttype_fromDB():

    # Access the identity of the current user with get_jwt_identity
    jwt_all = get_jwt_identity()
    current_user = jwt_all[0]
    print(f"""{colors.green} User {current_user} has successfully logged. Accessing /v2/getaccounttype API from IP: {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} {colors.default}""")
    
    # connecting to the database
    try:
        conn = psycopg2.connect(database= 'client_database' , user= database_username , password= database_password , host= host_name, port= db_port)
        conn.autocommit = True
        cursor = conn.cursor()
    except Exception as e:
        conn.close()
        print("Database connection failed.")
        return jsonify({"errormsg":"FATAL ERROR from v2/getaccounttype."}), 500 , {'Content-Type': 'application/json'}

    try:

        cursor.execute(f"SELECT customer_type from client_database where username='{current_user}';")
        conn.commit()
        uname = cursor.fetchall()
        usertype = uname[0][0]
        conn.close()
        results = {"customer_type":f"{usertype}"}
        return jsonify(results), 200 , {'Content-Type': 'application/json'}
    
    except Exception as e:
        conn.close()
        print(e)
        return jsonify({"errormsg":"Something happened while fetching customer_type. Error from /v2/getaccounttype"}), 200, {'Content-Type': 'application/json'}


"""
Update password self
"""
# curl
# curl -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MzA5MTQyMTIsIm5iZiI6MTYzMDkxNDIxMiwianRpIjoiZTk1YzIzOWQtZDNlOC00MjEzLWE0ZmMtODM0MWIyMjI5MGIyIiwiZXhwIjoxNjMwOTM1ODEyLCJpZGVudGl0eSI6ImFkbWluaXN0cmF0b3IiLCJmcmVzaCI6ZmFsc2UsInR5cGUiOiJhY2Nlc3MifQ.39FKtfz0kvE8_kfgcgD67RX7ie2N3IffGE4TcD9cBKs' -H "Content-Type: application/json" -d '{"id":"1","newpassword":"None"}' -X POST http://localhost:5000/v2/admin/updateself
@app.route('/v2/updateself', methods=['POST'])
@jwt_required
def updateself():

    id = request.json.get('id', None)
    if not id:
        return jsonify({"errormsg": "Missing or broken 'id' parameter"}), 403

    if str(id).isnumeric() == True :
        pass
    else:
        return jsonify({"errormsg": "id should be a positive number."}), 403
    
    newpassword = request.json.get('newpassword', None)
    if not newpassword:
        return jsonify({"errormsg": "Missing or broken 'newpassword' parameter"}), 403

    # password sanitize
    if newpassword != 'None':
        try:
            if "'" in newpassword or '"' in newpassword:
                return jsonify({"errormsg":"The password should be alphanumberic without special characters. Please only use valid characters."}), 403 , {'Content-Type': 'application/json'}
            
            if len(newpassword) <= 6:
                return jsonify({"errormsg":"The password length should be more than 6."}), 403 , {'Content-Type': 'application/json'}

        except Exception as e:
            print('Error from password sanitization /v2/admin/updateself')

    # Access the identity of the current user with get_jwt_identity
    jwt_all = get_jwt_identity()
    current_user = jwt_all[0]
    print(f"""{colors.green} User {current_user} has successfully logged. Accessing /v2/updateself API from IP: {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} {colors.default}""")
    
    # connecting to the database
    try:
        conn = psycopg2.connect(database= 'client_database' , user= database_username , password= database_password , host= host_name, port= db_port)
        conn.autocommit = True
        cursor = conn.cursor()
    except Exception as e:
        conn.close()
        print("Database connection failed.")

    # Function to block usage of old tokens after change of password.
    if check_tokens(jwt_all) != 'successful':
        return check_tokens(jwt_all)[0]

    try:
        if current_user != 'administrator':

            cursor.execute(f"SELECT userid from client_database where username='{current_user}';")
            conn.commit()
            uname = cursor.fetchall()
            userid_not_admin = uname[0][0]
            print(f"userid is {userid_not_admin}")

            if userid_not_admin == int(id) :
                cursor.execute(f"SELECT userid,ratelimit,isauthorized from client_database where userid='{id}';")
                conn.commit()
                uname = cursor.fetchall()
                print(uname)

                results = []
                
                try:
                    if newpassword != 'None':
                        sha1password = hashlib.sha256(newpassword.encode('utf-8')).hexdigest()
                        cursor.execute(f"UPDATE client_database set password='{sha1password}' where userid='{id}';")
                        conn.autocommit = True
                        cursor.execute(f"SELECT * from client_database where password='{sha1password}' and userid='{id}';")
                        conn.autocommit = True
                        m = cursor.fetchall()
                        print(m)

                        # recording time of password update so that old tokens will not work any longer
                        date_to_log = datetime.datetime.utcnow().isoformat()+"+00:00"
                        cursor.execute(f"UPDATE client_database set password_updated_on='{date_to_log}' where userid='{id}';")
                        conn.autocommit = True

                except Exception as e:
                    print(e)
                    return jsonify({"errormsg":"Failed to authorize. From /v2/updateself"}), 403 , {'Content-Type': 'application/json'}
                    print("Error from updating password at /v2/updateself")

                if results == []:
                    results = {"Success":"Your request has been successfully processed."}
                
                conn.close()
                return jsonify(results), 200 , {'Content-Type': 'application/json'}
            
            else:
                conn.close()
                return jsonify({"errormsg":"You can't change other user data. Forbidden.  /v2/admin/updateself"}), 403 , {'Content-Type': 'application/json'}
        else:
            conn.close()
            return jsonify({"Unauthorized":"Super users should use another API.  /v2/admin/updateself"}), 403 , {'Content-Type': 'application/json'}

    except Exception as e:
        conn.close()
        return jsonify({"errormsg":"Something happened while updating profile data. Check if your data is correct.  /v2/admin/updateself"}), 403, {'Content-Type': 'application/json'}

"""
Update Emails
"""
@app.route('/v2/update_email', methods=['POST'])
@jwt_required
def updateself_email():

    id = request.json.get('id', None)
    if not id:
        return jsonify({"errormsg": "Missing or broken 'id' parameter"}), 403

    if str(id).isnumeric() == True :
        pass
    else:
        return jsonify({"errormsg": "id should be a positive number."}), 403
    
    newemail = request.json.get('newemail', None)
    print(newemail)

    if not newemail:
        return jsonify({"errormsg": "Missing or broken 'newemail' parameter"}), 403
    
    checks = re.compile('[`!#$%^&()<>?/\|}{~:,+\]\[]')
    checkemail = len(re.findall(checks,newemail))

    if checkemail != 0:
        return jsonify({"errormsg":"The email must not contain quotes or invalid characters. Please only use valid characters."}), 403 , {'Content-Type': 'application/json'}

    try:
        if "'" in newemail or '"' in newemail:
            return jsonify({"errormsg":"The email must not contain quotes or invalid characters. Please only use valid characters."}), 403 , {'Content-Type': 'application/json'}

        if ("@" not in newemail) or ('.' not in newemail):
            return jsonify({"errormsg":"The email must contain @ and a at least dot. Please only use valid characters."}), 403 , {'Content-Type': 'application/json'}  

        if len(re.findall('@',newemail)) > 1:
            return jsonify({"errormsg":"The email must contain only one @ and a at least dot. Please only use valid characters."}), 403 , {'Content-Type': 'application/json'} 

    except Exception as e:
        print('Error from email sanitization /v2/update_email')

    # Access the identity of the current user with get_jwt_identity
    jwt_all = get_jwt_identity()
    current_user = jwt_all[0]
    print(f"""{colors.green} User {current_user} has successfully logged. Accessing /v2/update_email API from IP: {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} {colors.default}""")
    
    # connecting to the database
    try:
        conn = psycopg2.connect(database= 'client_database' , user= database_username , password= database_password , host= host_name, port= db_port)
        conn.autocommit = True
        cursor = conn.cursor()
    except Exception as e:
        conn.close()
        print("Database connection failed.")

    # Function to block usage of old tokens after change of password.
    if check_tokens(jwt_all) != 'successful':
        return check_tokens(jwt_all)[0]

    try:
        if current_user != 'administrator':

            cursor.execute(f"SELECT userid from client_database where username='{current_user}';")
            conn.commit()
            uname = cursor.fetchall()
            userid_not_admin = uname[0][0]
            print(f"userid is {userid_not_admin}")

            if userid_not_admin == int(id) :
                cursor.execute(f"SELECT userid from client_database where userid='{id}';")
                conn.commit()
                uname = cursor.fetchall()
                print(uname)

                results = []
                
                try:
                    if newemail != 'None':
                        cursor.execute(f"UPDATE client_database set email='{newemail}' where userid='{id}';")
                        conn.autocommit = True
                        cursor.execute(f"SELECT * from client_database where userid='{id}';")
                        conn.autocommit = True
                        m = cursor.fetchall()
                        print(m)
                except Exception as e:
                    print(e)
                    print("Error from updating password at /v2/admin/update_email")
                    return jsonify({"errormsg":"Please use another E-mail address."}), 403 , {'Content-Type': 'application/json'}

                if results == []:
                    results = {"Success":"Your request to change email address has been successfully processed."}
                
                conn.close()
                return jsonify(results), 200 , {'Content-Type': 'application/json'}
            
            else:
                conn.close()
                return jsonify({"errormsg":"You can't other user data. Forbidden. From /v2/update_email"}), 403 , {'Content-Type': 'application/json'}
        else:
            conn.close()
            return jsonify({"errormsg":"Unauthorized. Super users should use another API. From /v2/update_email"}), 403 , {'Content-Type': 'application/json'}

    except Exception as e:
        conn.close()
        return jsonify({"errormsg":"Something happened while updating profile data. Check if your data is correct. From /v2/update_email"}), 403, {'Content-Type': 'application/json'}


"""
Update Individual Client Data by Administrator
"""
# curl
# curl -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MzA5MTQyMTIsIm5iZiI6MTYzMDkxNDIxMiwianRpIjoiZTk1YzIzOWQtZDNlOC00MjEzLWE0ZmMtODM0MWIyMjI5MGIyIiwiZXhwIjoxNjMwOTM1ODEyLCJpZGVudGl0eSI6ImFkbWluaXN0cmF0b3IiLCJmcmVzaCI6ZmFsc2UsInR5cGUiOiJhY2Nlc3MifQ.39FKtfz0kvE8_kfgcgD67RX7ie2N3IffGE4TcD9cBKs' -H "Content-Type: application/json" -d '{"id":"1","ratelimit":"1203","isauthorized":"True","newpassword":"None"}' -X POST http://localhost:5000/v2/admin/updateclient
@app.route('/v2/admin/updateclient', methods=['POST'])
@jwt_required
def updateclient():

    id = request.json.get('id', None)
    if not id:
        return jsonify({"errormsg": "Missing or broken 'id' parameter"}), 403

    if str(id).isnumeric() == True :
        pass
    else:
        return jsonify({"errormsg": "id should be a positive nuumber."}), 403
    

    ratelimit = request.json.get('ratelimit', None)
    if not ratelimit:
        return jsonify({"errormsg": "Missing or broken 'ratelimit' parameter"}), 403

    ratelimit_update_status = False
    if str(ratelimit).isnumeric() == True or str(ratelimit) == 'None':
        ratelimit_update_status = True
    else:
        return jsonify({"errormsg": "ratelimit should be a positive number."}), 403

    darkowl_ratelimit_status = False
    darkowl_ratelimit = request.json.get('ratelimit_darkweb_breach', None)
    if not darkowl_ratelimit:
        return jsonify({"errormsg": "Missing or broken 'ratelimit_darkweb_breach' parameter"}), 403

    if str(darkowl_ratelimit).isnumeric() == True or str(darkowl_ratelimit) == 'None':
        darkowl_ratelimit_status = True
    else:
        return jsonify({"errormsg": "darkowl_ratelimit should be a positive number."}), 403


    maxSearch_ratelimit_status = False
    maxSearch_ratelimit = request.json.get('ratelimit_maxsearch', None)
    if not maxSearch_ratelimit:
        return jsonify({"errormsg": "Missing or broken 'ratelimit_maxsearch' parameter"}), 403

    if str(maxSearch_ratelimit).isnumeric() == True or str(maxSearch_ratelimit) == 'None':
        maxSearch_ratelimit_status = True
    else:
        return jsonify({"errormsg": "ratelimit_maxsearch should be a positive number."}), 403


    customer_type_status = False
    customer_account_type = request.json.get('customer_type', None)
    if not customer_account_type:
        return jsonify({"errormsg": "Missing or broken 'customer_type' parameter"}), 403

    if customer_account_type == 'TRIAL_CUSTOMER' or customer_account_type == 'PAID_CUSTOMER':
        customer_type_status = True
    else:
        return jsonify({"errormsg": "Please send valid parameters to update client type."}), 403

    company_name_status = True
    company_name = request.json.get('company_name', "None")

    pagination_status = False
    pagination = request.json.get('pagination', None)
    
    if not pagination:
        return jsonify({"errormsg": "Missing or broken 'pagination' parameter"}), 403

    if isinstance(pagination,int) == True:
        pagination_status = True
    else:
        return jsonify({"errormsg": "Please send valid pagination ( int ) to update pagination value."}), 403

    maxChannelSearch_ratelimit_status = False
    maxChannelSearch_ratelimit = request.json.get('ratelimit_maxchannelsearch', None)
    if not maxChannelSearch_ratelimit:
        return jsonify({"errormsg": "Missing or broken 'ratelimit_maxchannelsearch' parameter"}), 403

    if str(maxChannelSearch_ratelimit).isnumeric() == True or str(maxChannelSearch_ratelimit) == 'None':
        maxChannelSearch_ratelimit_status = True
    else:
        return jsonify({"errormsg": "ratelimit_maxchannelsearch should be a positive number."}), 403

    category_access = request.json.get('category_access', None)

    if category_access == None :
        return jsonify({"errormsg": "Missing or broken 'category_access' parameter"}), 403

    category_access_update = False
    if category_access == 'all':   
        category_access_update = True 
    else:
        if isinstance(category_access, list):
            category_access_update = True
            new_category_access = []
            for some_chan in category_access:
                conv_chan_name = category_mapper(some_chan)
                conv_category_acess = f'{conv_chan_name}_alias'
                if conv_category_acess not in all_index_name:
                    return jsonify({"errormsg":"Please enter a valid category."}), 403
                
                if conv_chan_name not in new_category_access:
                    new_category_access.append(conv_chan_name)
            category_access = new_category_access
        else:
            return jsonify({"errormsg":"Please send a list of categories."}), 403


    isauthorized = request.json.get('isauthorized', None)
    if not isauthorized:
        return jsonify({"errormsg": "Missing or broken 'isauthorized' parameter"}), 403

    if isauthorized == 'True' or isauthorized == 'False' or isauthorized == 'None':
        pass
    else:
        return jsonify({"errormsg": "isauthorized should be either of True or False."}), 403
    
    newpassword = request.json.get('newpassword', None)
    if not newpassword:
        return jsonify({"errormsg": "Missing or broken 'newpassword' parameter"}), 403

    persistent_daily = request.json.get('persistent_daily', None)
    if not persistent_daily:
        return jsonify({"errormsg": "Missing or broken 'persistent_daily' parameter"}), 403

    persistent_daily_status = False 
    if str(persistent_daily).isnumeric() or str(persistent_daily) == 'None':
        persistent_daily_status = True
    else:
        return jsonify({"errormsg": "persistent_daily should be either an integer or None"}), 403

    breached_ratelimits = request.json.get('breached_ratelimit', None)
    if not breached_ratelimits:
        return jsonify({"errormsg": "Missing or broken 'breached_ratelimit' parameter"}), 403

    breached_ratelimits_status = False 
    if str(breached_ratelimits).isnumeric() or str(breached_ratelimits) == 'None':
        breached_ratelimits_status = True
    else:
        return jsonify({"errormsg": "breached_ratelimit should be either an integer or None"}), 403

    forums_ratelimits = request.json.get('forums_ratelimit', None)
    if not forums_ratelimits:
        return jsonify({"errormsg": "Missing or broken 'forums_ratelimit' parameter"}), 403

    forums_ratelimits_status = False 
    if str(forums_ratelimits).isnumeric() or str(forums_ratelimits) == 'None':
        forums_ratelimits_status = True
    else:
        return jsonify({"errormsg": "forums_ratelimit should be either an integer or None"}), 403

    reportgen_ratelimits = request.json.get('reportgen_ratelimit', None)
    if not reportgen_ratelimits:
        return jsonify({"errormsg": "Missing or broken 'reportgen_ratelimit' parameter"}), 403

    reportgen_ratelimits_status = False 
    if str(reportgen_ratelimits).isnumeric() or str(reportgen_ratelimits) == 'None':
        reportgen_ratelimits_status = True
    else:
        return jsonify({"errormsg": "reportgen_ratelimit should be either an integer or None"}), 403

    # password sanitize
    if newpassword != 'None':
        try:
            if not re.match("^[.A-Za-z0-9_-]*$", newpassword):
                return jsonify({"Error":"The password should be alphanumberic without special characters. Please only use valid characters."}), 403 , {'Content-Type': 'application/json'}
            
            if len(newpassword) <= 6:
                return jsonify({"Error":"The password length should be more than 6."}), 403 , {'Content-Type': 'application/json'}

        except Exception as e:
            print('Error from password sanitization /v2/admin/updateclient')

    if isauthorized == 'True' or isauthorized == 'False' or isauthorized == 'None':
        pass
    else:
        return jsonify({"errormsg": "isauthorized should be either of True or False."}), 403

    # Access the identity of the current user with get_jwt_identity
    jwt_all = get_jwt_identity()
    current_user = jwt_all[0]
    print(f"""{colors.green} User {current_user} has successfully logged. Accessing /v2/admin/updateclient API from IP: {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} {colors.default}""")
    #logging for user acessing routes
    f = open("apilogs.txt", "a", encoding='UTF-8')
    #data_to_log = f'''DATETIME:{datetime.datetime.utcnow()}\nIPADDRESS:{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}\nUsername:{username}\n\n'''
    data_to_log = {"DATETIME":f"{datetime.datetime.utcnow().isoformat()+'+00:00'}","IPADDRESS":f"""{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}""","ENDPOINT":"/v2/admin/updateclient","User": f"{current_user}"}
    f.write(str(data_to_log))
    f.write('\n')
    f.close()
    # connecting to the database
    try:
        conn = psycopg2.connect(database= 'client_database' , user= database_username , password= database_password , host= host_name, port= db_port)
        conn.autocommit = True
        cursor = conn.cursor()
    except Exception as e:
        conn.close()
        print("Database connection failed.")

    # Function to block usage of old tokens after change of password.
    if check_tokens(jwt_all) != 'successful':
        return check_tokens(jwt_all)[0]

    try:
        if current_user == 'administrator':

            cursor.execute(f"SELECT userid from client_database where username='administrator';")
            conn.commit()
            uname = cursor.fetchall()
            useridadmin = uname[0][0]
            print(f"admin id is {useridadmin}")

            if useridadmin != int(id) :
                cursor.execute(f"SELECT userid,ratelimit,isauthorized from client_database where userid='{id}';")
                conn.commit()
                uname = cursor.fetchall()
                print(uname)

                results = []
                try:
                    if ratelimit_update_status == True:
                        cursor.execute(f"UPDATE client_database set ratelimit= {int(ratelimit)} where userid='{id}';")
                except Exception as e:
                    results.append("Failed to update ratelimit.")

                try:
                    if isauthorized == 'True':
                        cursor.execute(f"UPDATE client_database set isauthorized='{isauthorized}' where userid='{id}';")
                    if isauthorized == 'False':
                        cursor.execute(f"UPDATE client_database set isauthorized='{isauthorized}' where userid='{id}';")
                except Exception as e:
                    results.append("Failed to update authorization.")

                try:
                    if persistent_daily_status == True:
                        cursor.execute(f"UPDATE client_database set persistent_dailylimit='{persistent_daily}' where userid='{id}';")
                except Exception as e:
                    pass

                try:
                    if breached_ratelimits_status == True:
                        cursor.execute(f"UPDATE client_database set breached_ratelimit='{breached_ratelimits}' where userid='{id}';")
                except Exception as e:
                    pass
                
                try:
                    if forums_ratelimits_status == True:
                        cursor.execute(f"UPDATE client_database set forums_ratelimit='{forums_ratelimits}' where userid='{id}';")
                except Exception as e:
                    pass

                try:
                    if reportgen_ratelimits_status == True:
                        cursor.execute(f"UPDATE client_database set reportgenerator_ratelimit='{reportgen_ratelimits}' where userid='{id}';")
                except Exception as e:
                    pass

                try:
                    if darkowl_ratelimit_status == True:
                        cursor.execute(f"UPDATE client_database set darkowl_ratelimit={darkowl_ratelimit} where userid='{id}';")
                except Exception as e:
                    pass

                try:
                    if maxSearch_ratelimit_status == True:
                        cursor.execute(f"UPDATE client_database set max_results={maxSearch_ratelimit} where userid='{id}';")
                except Exception as e:
                    pass

                try:
                    if maxChannelSearch_ratelimit_status == True:
                        cursor.execute(f"UPDATE client_database set channelsearch_ratelimit={maxChannelSearch_ratelimit} where userid='{id}';")
                except Exception as e:
                    pass

                try:
                    if customer_type_status == True:
                        cursor.execute(f"UPDATE client_database set customer_type='{customer_account_type}' where userid='{id}';")
                except Exception as e:
                    pass

                try:
                    if company_name_status == True:
                        cursor.execute(f"UPDATE client_database set company_name='{company_name}' where userid='{id}';")
                except Exception as e:
                    pass

                try:
                    if pagination_status == True:
                        cursor.execute(f"UPDATE client_database set pagination_limit='{pagination}' where userid='{id}';")
                except Exception as e:
                    pass

                try:
                    if category_access_update == True:
                        temp_json = {}
                        category_access = str(category_access).replace("'",'"')
                        cursor.execute(f"UPDATE client_database set category_access='{category_access}' where userid='{id}';")
                        print("triggered")
                except Exception as e:
                    print(e)
                
                try:
                    if newpassword != 'None':
                        sha1password = hashlib.sha256(newpassword.encode('utf-8')).hexdigest()
                        cursor.execute(f"UPDATE client_database set password='{sha1password}' where userid='{id}';")

                        # recording time of password update so that old tokens will not work any longer
                        date_to_log = datetime.datetime.utcnow().isoformat()+"+00:00"
                        cursor.execute(f"UPDATE client_database set password_updated_on='{date_to_log}' where userid='{id}';")

                except Exception as e:
                    results.append("Failed to update authorization.")
                    print("Error from updating password at /v2/admin/updateclient")

                if results == [] and ratelimit =='None' and isauthorized == 'None' and newpassword == 'None' and persistent_daily == 'None':
                    results = {"Success":"Your request has been successfully processed. It was empty though. Please change something!"}
                elif results == []:
                    results = {"Success":"Your request has been successfully processed."}
                
                return jsonify(results), 200 , {'Content-Type': 'application/json'}
            
            else:
                return jsonify({"Info":"You are the administrator. Your ratelimit is unlimited and you are authorized. /v2/admin/updateclient"}), 200 , {'Content-Type': 'application/json'}
        else:
            return jsonify({"Unauthorized":"Only superadmin can access this API. /v2/admin/updateclient"}), 403 , {'Content-Type': 'application/json'}

    except Exception as e:
        print(f"Error at /v2/admin/updateclient {e}")
        return jsonify("Something happened while updating the client list. Check if your data is correct. /v2/admin/updateclient"), 200, {'Content-Type': 'application/json'}



"""
Update Username : Customer access
"""

@app.route('/v2/update_username', methods=['POST'])
@jwt_required
def updateself_username():

    # alter table client_database add constraint username unique (username)

    # Access the identity of the current user with get_jwt_identity
    jwt_all = get_jwt_identity()
    current_user = jwt_all[0]
    print(f"""{colors.green} User {current_user} has successfully logged. Accessing /v2/update_username API from IP: {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} {colors.default}""")
    
    new_username = request.json.get('new_username', None)
    print(new_username)

    checks = re.compile('[@!#$%^&()<>?/\|}{~:,+\]\[]')
    check_username = len(re.findall(checks,new_username))

    if check_username != 0:
        return jsonify({"errormsg":"The username must not contain quotes or invalid characters. Please only use valid characters. You can choose to use alphabets(small,big), numbers, underscore '_' and a hyphen '-' sign as your username."}), 200 , {'Content-Type': 'application/json'}

    try:
        if "'" in new_username or '"' in new_username:
            return jsonify({"errormsg":"The username must not contain quotes or invalid characters. Please only use valid characters. You can choose to use alphabets(small,big), numbers, underscore '_' and a hyphen '-' sign as your username."}), 200 , {'Content-Type': 'application/json'}
    except Exception as e:
        print(e)

    # connecting to the database
    try:
        conn = psycopg2.connect(database= 'client_database' , user= database_username , password= database_password , host= host_name, port= db_port)
        conn.autocommit = True
        cursor = conn.cursor()
    except Exception as e:
        conn.close()
        print("Database connection failed.")

    # Function to block usage of old tokens after change of password.
    if check_tokens(jwt_all) != 'successful':
        return check_tokens(jwt_all)[0]

    try:
        if current_user != 'administrator':

            cursor.execute(f"SELECT userid from client_database where username='{current_user}';")
            conn.commit()
            uname = cursor.fetchall()
            userid_not_admin = uname[0][0]
            print(f"userid is {userid_not_admin}")

            results = []
                
            try:
                cursor.execute(f"UPDATE client_database set username='{new_username}' where userid='{userid_not_admin}';")
                conn.autocommit = True
                conn.close()
                return jsonify({"Success":f"Your request to change username has been successfully processed."}), 200 , {'Content-Type': 'application/json'}

            except Exception as e:
                print(e)
                print("Error from updating username at /v2/update_username")
                return jsonify({"errormsg":"This request is not allowed. Please choose another username."}), 200 , {'Content-Type': 'application/json'}
    
        else:
            conn.close()
            return jsonify({"Unauthorized":"Super users not allowed. Please change username manually from server."}), 403 , {'Content-Type': 'application/json'}

    except Exception as e:
        conn.close()
        return jsonify({"errormsg":"Something happened while updating profile data. Check if your token is valid.  /v2/update_username"}), 200, {'Content-Type': 'application/json'}


########################################################################
#                           UPDATE PASSWORD API                        #
########################################################################
#
# Test command 
# curl -d '{"username":"test_account", "password":"abcdefghi", "reset_token":"some_secret_token_code_here"}' -H "Content-Type: application/json" -X POST http://localhost:5000/updatepassword
# The above command responds with a success message if everything is fine.
#

@app.route('/updatepassword', methods=['POST'])
@jwt_required
def forgot_password():
    #
    # secret token
    # 
    secret_token = 'some_secret_token_code_here'

    if not request.is_json:
        return jsonify({"errormsg": "Missing JSON in request"}), 400

    # username, password and reset_token parameters received from POST 
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    token_for_reset = request.json.get('reset_token', None )

    if not username:
        return jsonify({"errormsg": "Missing username parameter"}), 400
    if not password:
        return jsonify({"errormsg": "Missing password parameter"}), 400
    if not token_for_reset:
        return jsonify({"errormsg": "Missing reset token parameter"}), 400

    # fetch from databases 
    # connecting to the database
    try:
        conn = psycopg2.connect(database= 'client_database' , user= database_username , password= database_password , host= host_name, port= db_port)
        conn.autocommit = True
        cursor = conn.cursor()
    except Exception as e:
        print("Database connection failed.")

    try:
        cursor.execute(f"SELECT username from client_database where username='{username}'")
        conn.commit()
        uname = cursor.fetchall()
        print(uname)
        if len(uname[0][0]) > 0:
            print(f"{colors.green} {uname[0][0]} {colors.default}")
        
        try:
            # check if the user has passed the reset token her
            #
            #
            if(token_for_reset == secret_token):
                cursor.execute(f"UPDATE client_database SET password='{str(hashlib.sha256(password.encode('utf-8')).hexdigest())}' WHERE username='{username}'")
                print(f"{colors.green} Password is updated. {colors.default}")
                conn.commit()
            
                cursor.execute(f"select password from client_database WHERE username='{username}'")
                conn.commit()
                upassword = cursor.fetchall()
                print(upassword)

            else:
                return jsonify("Reset token incorrect, please check it again."), 200, {'Content-Type': 'application/json'}

        except Exception as e:
            return jsonify("Password seems incorrect, please check it again."), 200, {'Content-Type': 'application/json'}

    except Exception as e:
        return jsonify("Unauthorized. Username incorrect."), 200, {'Content-Type': 'application/json'}

    access_token = {"message":"your password has been updated. Please login to access the access token"} 
    return access_token, 200


"""

API v2.0.1
Signup : New Accounts

"""

# curl -H 'Content-Type: application/json' -d '{"username":"testac123","password":"testac123","email":"test@test.com"}' -XPOST http://localhost:5000/v2/signup
@app.route('/v2/signup', methods=['POST'])
def index():

    print(f"{colors.cyan} starting.... {colors.default}")
    
    if request.method == "POST":
        details = request.get_json()

        # username, password and reset_token parameters received from POST 
        username = request.json.get('username', None)
        password = request.json.get('password', None)
        email = request.json.get('email', None )

        # DO NOT document this parameter in the API Documentation
        secret_parameter = request.json.get('secret_parameter', None)

        if not secret_parameter:
            secret_param = "None"

        if not username:
            return jsonify({"errormsg": "Missing username parameter API v2.0.1"}), 400 , {'Content-Type': 'application/json'}
        if not password:
            return jsonify({"errormsg": "Missing password parameter API v2.0.1"}), 400 , {'Content-Type': 'application/json'}
        if not email:
            return jsonify({"errormsg": "Missing email parameter API v2.0.1"}), 400 , {'Content-Type': 'application/json'}

        # username sanitize 
        try:
            if not re.match("^[.A-Za-z0-9_-]*$", details['username']):
                return jsonify({"Error":"The username should be alphanumberic without special characters. Please only use valid characters. API v2.0.1"}), 403 , {'Content-Type': 'application/json'}

            if details['username'] == 'administrator' and secret_parameter != 'secretparameter_admin_account_first_setup_!93@3^79)[{)-_]{|':
                return jsonify({"errormsg":"This user account has been permanently blocked for registration. Please choose another name."}), 403 , {'Content-Type': 'application/json'}

            username = details['username']
        except Exception as e:
            print(e)
        
        # block usernames with autoprefix
        try:
            return_value = autocred_prefix_username_blocker(username)
            if return_value != None:
                return return_value
            else:
                pass
        except Exception as e:
            print(e)

        # password sanitize
        try:

            if len(details['password']) <= 6 or len(details['password']) > 30 :
                return jsonify({"Error":"The password length should be more than 6 and less than 30. API v2.0.1"}), 403 , {'Content-Type': 'application/json'}

            if "'" in details['password'] or '"' in details['password']:
                print(details['password'])
                return jsonify({"Error":"The password should not contain any quotes. Please only use valid characters. API v2.0.1"}), 403 , {'Content-Type': 'application/json'}

            password = details['password']
        except Exception as e:
            print(e)

        email = details['email']

        if "'" in email or '"' in email or ":" in email:
            errortext = {"errormsg":"Email is invalid. API v2.0.1"}
            return jsonify(errortext), 200, {'Content-Type': 'application/json'}
        
        if "@" not in email and "." not in email:
            errortext = {"errormsg":"Email is invalid. API v2.0.1"}
            return jsonify(errortext), 200, {'Content-Type': 'application/json'}

        # Signup Logs : Passwords redacted [ WARNING: SIGNUP DATA IS LOGGED IN PLAINTEXT. ]
        f = open("signuplogs.txt", "a", encoding='UTF-8')
        #data_to_log = f'''DATETIME:{datetime.datetime.utcnow()}\nIPADDRESS:{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}\nUsername:{username}\n\n'''
        data_to_log = f'''DATETIME:{datetime.datetime.utcnow().isoformat()+'+00:00'}\nIPADDRESS:{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}\nUsername:{username}\n\n'''
        f.write(data_to_log)
        f.close()

        sha1password = hashlib.sha256(password.encode('utf-8')).hexdigest()
        #print(sha1password)

        # detecting IP Address and the request header of the calling entity : IP ADDRESS IS NOT LOGGED IN THE DATABASE 
        liste = [str(request.environ.get("HTTP_X_REAL_IP", request.remote_addr)),str(request.user_agent)]
        print(liste)
        
        """
        If you need to log IP Addresses and other request parameters, do it inside the codeblocls below
        """

        """
        # connect to the database to log IP Address (database hasn't been designed yet)
        # log IP Address and date/time of accessing the API
        # Check and block IP if required.

        """

    try:
        conn = psycopg2.connect(database= 'client_database' , user= database_username , password= database_password , host= host_name, port= db_port)
        conn.autocommit = True
        cursor = conn.cursor()

        # check if username already exists
        cursor.execute(f"SELECT username from client_database where username='{username}'")
        check_username = cursor.fetchall()

        if len(check_username) > 0:
            print(check_username)
            username_db = check_username[0][0]
            user_exists_error = {"Error":f"User {username_db} already exists! Forgot your password?"}
            return jsonify(user_exists_error), 200, {'Content-Type': 'application/json'}
            
        else:
            date_of_registration = datetime.datetime.utcnow().isoformat()+'+00:00'

            ipaddress = request.environ.get("HTTP_X_REAL_IP", request.remote_addr)
            cursor.execute(f"INSERT INTO client_database (USERNAME, PASSWORD, EMAIL, ISAUTHORIZED, ISUNLIMITED, DATE, RATELIMIT, PERSISTENT_DAILYLIMIT, BREACHED_RATELIMIT, FORUMS_RATELIMIT, TOKENGEN, TOKENLIMIT , DATEOFREGISTRATION, IPADDRESS, SCROLL_AUTHORIZATION, REPORTGENERATOR_RATELIMIT, LAST_LOGGED_IN_AT, DARKOWL_RATELIMIT, MAX_RESULTS, CHANNELSEARCH_RATELIMIT, CATEGORY_ACCESS, CUSTOMER_TYPE, COMPANY_NAME, PAGINATION_LIMIT ) values ('{username}','{sha1password}','{email}', 'False','False','1989-11-10T12:34:56+00:00',100, 100, 10, 20, 0, 100, '{date_of_registration}', '{ipaddress}','False', 10, '1989-11-10T12:34:56+00:00', 10, 1000, 100, 'all', 'TRIAL_CUSTOMER', 'None', 10 )")
            conn.commit()

        # fetch the token from the database 
        cursor.execute(f"SELECT username,userid from client_database where username='{username}'")
        conn.commit()
        xx = cursor.fetchall()
        print(xx)
        print(f"Username: {colors.blue} {xx[0][0]}\n{colors.default}UserID:{colors.blue} {xx[0][1]}{colors.default}")
        user_from_db = xx[0][0]
        user_id = xx[0][1]
    
    except Exception as e:
        print(f"{colors.red}Database connection failed. {colors.yellow}{e} {colors.default}")
        
        if 'duplicate key value violates unique constraint ' in str(e) and 'email' in str(e):
            return jsonify({"errormsg":"This Email is not authorized for sign-up. Please use another Email."}), 403, {'Content-Type': 'application/json'}
    
    return {"message":"success","username":user_from_db,"user_id":user_id}, 200, {'Content-Type': 'application/json'}



"""
API v2.0.1_ADMINISTRATOR
Signup : New Accounts AUTOMATICALLY : Administrator Access only
NOTE : DO NOT DOCUMENT THIS API for Customers
"""

@app.route('/v2/autocredentials', methods=['POST'])
@jwt_required
def auto_credentials():
    random_username = ''
    random_password = ''

    print(f"{colors.cyan} starting.... {colors.default}")

    # Access the identity of the current user with get_jwt_identity
    jwt_all = get_jwt_identity()
    current_user = jwt_all[0]

    # Function to block usage of old tokens after change of password.
    if check_tokens(jwt_all) != 'successful':
        return check_tokens(jwt_all)[0]
    
    if current_user != "administrator":
        return jsonify({"errormsg": "You are not authorized to access this API. Error from API v2.0.1_ADMINISTRATOR at route /v2/autocredentials"}), 403 , {'Content-Type': 'application/json'}

    print(f"""{colors.green} User {current_user} has successfully logged. Accessing v2.0.1_ADMINISTRATOR /v2/autocredentials API from IP: {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} {colors.default}""")
    
    # Logging
    f = open("apilogs.txt", "a", encoding='UTF-8')
    data_to_log = {"DATETIME":f"{datetime.datetime.utcnow().isoformat()+'+00:00'}","IPADDRESS":f"""{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}""","ENDPOINT":"/v2/autocredentials","User": f"{current_user}"}
    f.write(str(data_to_log))
    f.write('\n')
    f.close()
    
    if request.method == "POST":
        details = request.get_json()
        email = request.json.get('email', None )

        if not email:
            return jsonify({"errormsg": "Missing email parameter in API v2.0.1_ADMINISTRATOR at route /v2/autocredentials"}), 400 , {'Content-Type': 'application/json'}

        email = details['email']

        if "'" in email or '"' in email or ":" in email:
            errortext = {"errormsg":"Email is invalid. API v2.0.1_ADMINISTRATOR"}
            return jsonify(errortext), 200, {'Content-Type': 'application/json'}
        
        if "@" not in email and "." not in email:
            errortext = {"errormsg":"Email is invalid. API v2.0.1_ADMINISTRATOR"}
            return jsonify(errortext), 200, {'Content-Type': 'application/json'}

        # auto-generate username and password
        random_username = AUTOCRED_ACCOUNT_PREFIX + ''.join(random.sample('abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVXYZ', 12))
        random_password = AUTOCRED_ACCOUNT_PREFIX + ''.join(random.sample('abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVXYZ', 12))
        
        print(random_username, random_password)

        sha1password = hashlib.sha256(random_password.encode('utf-8')).hexdigest()
        print(sha1password)


        #----------------------------------------- just checks if a username exists -----------------------#
        def check_username(random_username):
            print("Checking username...")
            connt = psycopg2.connect(database= 'client_database' , user= database_username , password= database_password , host= host_name, port= db_port)
            connt.autocommit = True
            cursort = connt.cursor()

            # check if username already exists
            cursort.execute(f"SELECT username from client_database where username='{random_username}'")
            
            check_usernamet = ''
            try:
                check_usernamet = cursort.fetchall()[0][0]
                print(f"From database username is: {check_usernamet}")
            except Exception as e:
                print(e)

            if check_usernamet != random_username:
                connt.close()
                return "successful"
            else:
                connt.close()
                return "unsuccessful"

        #----------------------------------------- just checks if a username exists -----------------------#
        def check_email(email):
            print("Checking Email...")
            connt2 = psycopg2.connect(database= 'client_database' , user= database_username , password= database_password , host= host_name, port= db_port)
            connt2.autocommit = True
            cursort2 = connt2.cursor()

            # check if email already exists
            cursort2.execute(f"SELECT email from client_database where email='{email}'")
            
            check_emailt = ''

            try:
                check_emailt = cursort2.fetchall()[0][0]
                print(f"From database Email is : {check_emailt}")
            except Exception as e:
                print(e)
            
            print(f"EMAIL ------- {check_emailt}")

            if check_emailt != email :
                pass
            else:
                return "unsuccessful"

        try:
            conn = psycopg2.connect(database= 'client_database' , user= database_username , password= database_password , host= host_name, port= db_port)
            conn.autocommit = True
            cursor = conn.cursor()

            while True:
                if 'unsuccessful' == check_username(random_username):
                    pass
                else:
                    break
            
            if 'unsuccessful' == check_email(email):
                return jsonify({"errormsg": "This email is already registered. Please use another Email. API /v2/autocredentials"}), 403 , {'Content-Type': 'application/json'}
            
            date_of_registration = datetime.datetime.utcnow()
            
            # Account expiration date for accounts set to 7 days. Change to adjust.
            account_expiration_date = date_of_registration + timedelta(days=7)
            account_expiration_date = account_expiration_date.isoformat()+ '+00:00'

            email_sent_boolean = 'False'

            ipaddress = request.environ.get("HTTP_X_REAL_IP", request.remote_addr)
            cursor.execute(f"INSERT INTO client_database (USERNAME, PASSWORD, EMAIL, ISAUTHORIZED, ISUNLIMITED, DATE, RATELIMIT, PERSISTENT_DAILYLIMIT, TOKENGEN, TOKENLIMIT , DATEOFREGISTRATION, IPADDRESS, ACCOUNT_EXPIRY_DATE, EMAIL_SENT, BREACHED_RATELIMIT, FORUMS_RATELIMIT, REPORTGENERATOR_RATELIMIT, LAST_LOGGED_IN_AT, DARKOWL_RATELIMIT, MAX_RESULTS, CHANNELSEARCH_RATELIMIT, CATEGORY_ACCESS, CUSTOMER_TYPE, COMPANY_NAME, PAGINATION_LIMIT ) values ('{random_username}','{sha1password}','{email}', 'True','False','1989-11-10T12:34:56+00:00',100, 100, 0, 100, '{date_of_registration}', '{ipaddress}','{account_expiration_date}', '{email_sent_boolean}',10, 10, 10, '1989-11-10T12:34:56+00:00', 10, 1000, 100, 'all', 'TRIAL_CUSTOMER', 'None', 10 )")
            conn.commit()

            # fetch the token from the database 
            cursor.execute(f"SELECT username,userid,email,account_expiry_date,password,isauthorized from client_database where username='{random_username}'")
            conn.commit()
            xx = cursor.fetchall()
            print(xx)
            print(f"Username: {colors.blue} {xx[0][0]}\n{colors.default}UserID:{colors.blue} {xx[0][1]}{colors.default}\nEmail:{colors.blue} {xx[0][2]}{colors.default}\nAccount Expiry Date:{colors.blue} {xx[0][3]}{colors.default}\n")
            user_from_db = xx[0][0]
            user_id = xx[0][1]
            email_address = xx[0][2]
            account_expiration_on = xx[0][3]

            passworde = xx[0][4]
            isauthorized = xx[0][5]
            # checking if passwords match

            print(passworde, random_password)

            if passworde == hashlib.sha256(random_password.encode('utf-8')).hexdigest():
                print("password-hash stored in the database matches the hash of plaintext password in local variable.")
            else:
                return {"errormsg":"Something has gone wrong with password hashing. Please contact your service provider. API /v2/autocredentials"}, 500, {'Content-Type': 'application/json'}

        except Exception as e:
            print(f"{colors.red}Database connection failed. {colors.yellow}{e} {colors.default}")
            
            if 'duplicate key value violates unique constraint "email"' in str(e):
                return jsonify({"errormsg":"This Email is not authorized for sign-up. Please use another Email. /v2/autocredentials"}), 403, {'Content-Type': 'application/json'}
        
        # send Emails to users with account credentials 
        try:
            cred_mail_sender(email_address, user_from_db , random_password , account_expiration_on)
        
            try:
                cursor.execute(f"UPDATE client_database set email_sent='True' where username='{random_username}'")
                conn.commit()
            
            except Exception as e:
                print(f"{colors.red}Error at changing status code for sent emails. /v2/autocredentials/ {e} {colors.red}")
            
                with open('mail_send_error.txt','a') as error:
                    mailsender = f"Could not change email_sent field for {email} on {datetime.datetime.utcnow().isoformat}+00:00 "
                    error.write(mailsender)
                    error.write("\n")

        except Exception as e:
            print(f"{colors.red}Error at sending credentials through Email. /v2/autocredentials/ {e} {colors.red}")
            
            with open('mail_send_error.txt','a') as error:
                mailsender = f"Could not send email to {email} on {datetime.datetime.utcnow().isoformat}+00:00 "
                error.write(mailsender)
                error.write("\n")

        return {"message":"success","username":user_from_db,"password":random_password,"user_id":user_id,"email_address":email_address,"account_expiration_on":account_expiration_on,"account_activation_status":isauthorized}, 200, {'Content-Type': 'application/json'}

@app.route('/admin/resetacc',methods=['POST'])
@jwt_required
def resetacc():
    try:
        user_id = request.json.get('user_id',None)
        
        jwt_all = get_jwt_identity()
        current_user = jwt_all[0]
        
        if check_tokens(jwt_all) != 'successful':
            return check_tokens(jwt_all)[0]
        
        if current_user != "administrator":
            return jsonify({"errormsg": "You are not authorized to access this API. Error from API v2.0.1_ADMINISTRATOR at route /v2/autocredentials"}), 403 , {'Content-Type': 'application/json'}
        
        if user_id is None:
            return jsonify({'errormsg':'Please send userd id in the parameter'}),403

        # Logging
        f = open("apilogs.txt", "a", encoding='UTF-8')
        data_to_log = {"DATETIME":f"{datetime.datetime.utcnow().isoformat()+'+00:00'}","IPADDRESS":f"""{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}""","ENDPOINT":"/v2/autocredentials","User": f"{current_user}"}
        f.write(str(data_to_log))
        f.write('\n')
        f.close()
        
        #extracting user data
        user_email = ''
        try:
            conn = psycopg2.connect(database= 'client_database' , user= database_username , password= database_password , host= host_name, port= db_port)
            conn.autocommit = True
            cursort = conn.cursor()

            # check if username already exists
            cursort.execute(f"SELECT email from client_database where userid='{user_id}'")

            try:
                user_email = cursort.fetchall()[0][0]
                print(f"From database email is: {user_email}")
            except Exception as e:
                print(e)
            conn.close()
        except:
            conn.close()

        #validating user for further update
        username_identifier = ''
        
        try:
            conn = psycopg2.connect(database= 'client_database' , user= database_username , password= database_password , host= host_name, port= db_port)
            conn.autocommit = True
            cursort = conn.cursor()

            # check if username already exists
            cursort.execute(f"SELECT username from client_database where userid='{user_id}'")

            try:
                username_identifier = cursort.fetchall()[0][0]
                print(f"From database username is: {username_identifier}")
            except Exception as e:
                print(e)
            conn.close()
        except:
            conn.close()
        try:
            print("Checking account_status...")
            connt = psycopg2.connect(database= 'client_database' , user= database_username , password= database_password , host= host_name, port= db_port)
            connt.autocommit = True
            cursort = connt.cursor()
            cursort.execute(f"SELECT account_expiry_date from client_database where userid='{user_id}'")
            account_status = cursort.fetchall()[0][0]
            if account_status is None:
                return jsonify({'errormsg':'The user has allready logged in and the account is also authenticated. Please try with other account'}),403    
                
            print(account_status,'<---user--account---expiry--status--->')
            connt.close()
        except Exception as e:
            print(e)
            connt.close()


        if email_validator(user_email) is False:
            return jsonify({'errormsg':'The registered email dosent seems to be valid of the user. '}),403
        if user_email == '' or username_identifier=='':
            return jsonify({'errormsg':'Please send valid user_id as a parameter.'}),403
        if username_identifier == 'administrator':
            return jsonify({'errormsg':'Updating any administrator priviliges is forbidden.'}),403    
        
        
        update_date_of_registration = datetime.datetime.utcnow()
                
        # Account expiration date for accounts set to 7 days. Change to adjust.
        account_expiration_date = update_date_of_registration + timedelta(days=7)
        account_expiration_date = account_expiration_date.isoformat()+ '+00:00'
        
        # auto-generate username and password
        random_username = AUTOCRED_ACCOUNT_PREFIX + ''.join(random.sample('abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVXYZ', 12))
        random_password = AUTOCRED_ACCOUNT_PREFIX + ''.join(random.sample('abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVXYZ', 12))
        print(random_username,random_password)
        #encrypted password
        sha1password = hashlib.sha256(random_password.encode('utf-8')).hexdigest()
        
        if sha1password == hashlib.sha256(random_password.encode('utf-8')).hexdigest():
                    print("password-hash stored in the database matches the hash of plaintext password in local variable.")
        else:
            return {"errormsg":"Something has gone wrong with password hashing. Please contact your service provider. API /v2/autocredentials"}, 500, {'Content-Type': 'application/json'}
        
        def check_username(random_username):
            print("Checking username...")
            connt = psycopg2.connect(database= 'client_database' , user= database_username , password= database_password , host= host_name, port= db_port)
            connt.autocommit = True
            cursort = connt.cursor()

            # check if username already exists
            cursort.execute(f"SELECT username from client_database where username='{random_username}'")
            
            check_username = ''
            try:
                check_username = cursort.fetchall()[0][0]
                print(f"From database username is: {check_username}")
            except Exception as e:
                print(e)

            if check_username != random_username:
                connt.close()
                return "successful"
            else:
                connt.close()
                return "unsuccessful"
        try:
            while True:
                    if 'unsuccessful' == check_username(random_username):
                        pass
                    else:
                        break
        except:
            pass
        #updating userinfo on the database
        try:
            conn = psycopg2.connect(database= 'client_database' , user= database_username , password= database_password , host= host_name, port= db_port)
            conn.autocommit = True
            cursor = conn.cursor()
            cursor.execute(f"UPDATE client_database set username='{random_username}',password='{sha1password}',account_expiry_date='{account_expiration_date}' where userid='{user_id}';")
            conn.commit()
            conn.close()
        except Exception as e:
            print(e)
            conn.close()
            return {"errormsg":"Something has gone wrong while updating user info. Please contact your service provider. API /v2/autocredentials"}, 403, {'Content-Type': 'application/json'}
        
        try:
            cred_mail_sender(user_email, random_username , random_password , account_expiration_date)
        
            try:
                conn = psycopg2.connect(database= 'client_database' , user= database_username , password= database_password , host= host_name, port= db_port)
                conn.autocommit = True
                cursor = conn.cursor()
                cursor.execute(f"UPDATE client_database set email_sent='True' where username='{random_username}'")
                conn.commit()
                conn.close()
            
            except Exception as e:
                conn.close()
                print(f"{colors.red}Error at changing status code for sent emails. /v2/autocredentials/ {e} {colors.red}")
            
                with open('mail_send_error.txt','a') as error:
                    mailsender = f"Could not change email_sent field for {user_email} on {datetime.datetime.utcnow().isoformat}+00:00 "
                    error.write(mailsender)
                    error.write("\n")

        except Exception as e:
            print(f"{colors.red}Error at sending credentials through Email. /v2/autocredentials/ {e} {colors.red}")
            
            with open('mail_send_error.txt','a') as error:
                mailsender = f"Could not send email to {user_email} on {datetime.datetime.utcnow().isoformat}+00:00 "
                error.write(mailsender)
                error.write("\n")

        
        return jsonify({'message':'The account has been sucesffully reset. New username and password has been sent to user email.'}),200
    except:
        return {"errormsg":"Something has gone wrong while updating user info. Please contact your service provider. API /v2/autocredentials"}, 403, {'Content-Type': 'application/json'}
    
    
    
    
    
    

"""

API v2.0.2  LOGIN TO ACCOUNT

"""
# curl -d '{"username":"test123","password":"test_password"}'  -H "Content-Type: application/json" -X POST http://localhost:5000/v2/login
@app.route('/v2/login', methods=['POST'])
def login():

    details = request.get_json()
    
    if not request.is_json:
        return jsonify({"errormsg": "Missing JSON in request"}), 400

    username = request.json.get('username', None)
    password = request.json.get('password', None)
    try:
        username= username.strip()
    except:
        pass
    try:
        password= password.strip()
    except:
        pass
    
    if not username:
        return jsonify({"errormsg": "Missing or broken 'username' parameter API v2.0.2 "}), 400
    if not password:
        return jsonify({"errormsg": "Missing or broken 'password' parameter API v2.0.2 "}), 400

    # Logs login attempts.
    f = open("loginlogs.txt", "a", encoding='UTF-8')
    data_to_log = f'''DATETIME:{datetime.datetime.utcnow().isoformat()+'+00:00'}\nIPADDRESS:{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}\nUsername:{username}\n\n'''
    f.write(data_to_log)
    f.close()

    """
    Username and Password Sanitization while login
    """
    # username sanitize
    try:
        if not re.match("^[.A-Za-z0-9_-]*$", username):
            return jsonify({"errormsg":"The username contains invalid characters. Please only use valid characters. API v2.0.2 "}), 200, {'Content-Type': 'application/json'}
    except Exception as e:
        print(e)

    # password sanitize
    try:
            if len(details['password']) <= 6 or len(details['password']) > 30 :
                return jsonify({"Error":"The password length should be more than 6 and less than 30. API v2.0.2"}), 403 , {'Content-Type': 'application/json'}

            if "'" in details['password'] or '"' in password:
                print(details['password'])
                return jsonify({"Error":"The password should not contain any quotes. Please only use valid characters. API v2.0.2"}), 403 , {'Content-Type': 'application/json'}
    except Exception as e:
        print(e)

    # detecting IP Address and the request header of the calling entity : IP ADDRESS IS NOT LOGGED IN THE DATABASE 
    liste = [str(request.environ.get("HTTP_X_REAL_IP", request.remote_addr)),str(request.user_agent)]
    print(liste)
    
    """
    If you need to log IP Addresses and other request parameters, do it inside the codeblocls below
    """

    """
    # connect to the database to log IP Address (database hasn't been designed yet)
    # log IP Address and date/time of accessing the API
    # Check and block IP if required.

    """

    # fetch from databases 
    # connecting to the database
    try:
        conn = psycopg2.connect(database= 'client_database' , user= database_username , password= database_password , host= host_name, port= db_port)
        conn.autocommit = True
        cursor = conn.cursor()
    except Exception as e:
        conn.close()
        print("Database connection failed.")

    try:
        cursor.execute(f"SELECT username from client_database where username='{username}';")
        conn.commit()
        uname = cursor.fetchall()
        #print(uname)
        
        if len(uname[0][0]) > 0:
            print(f"{colors.green} Username Logged in: {uname[0][0]} {colors.default}")
        
        
        # check for authorization
        try:
            cursor.execute(f"SELECT username from client_database where username='{username}' and isauthorized='True';")
            conn.commit()
            upassword = cursor.fetchall()
            #print(upassword[0][0])
            if len(upassword[0][0]) > 0:
                print(f"{colors.green}Status:\tAuthorized.{colors.default}")
            
        except Exception as e:
            conn.close()
            return jsonify({"errormsg":"You are not yet authorized to login. Please contact Support. API v2.0.2 "}), 200, {'Content-Type': 'application/json'}

        # check for password errors
        try:
            cursor.execute(f"SELECT username,password from client_database where password='{hashlib.sha256(password.encode('utf-8')).hexdigest()}' and username='{username}';")
            conn.autocommit = True
            upassword = cursor.fetchall()
            #print(upassword)
            #print(upassword[0][0])
            if len(upassword[0][0]) > 0:
                print(f"{colors.green} with matching password hash: {upassword[0][1]} {colors.default}")
            
        except Exception as e:
            conn.close()
            print(e)
            return jsonify({"errormsg":"Password seems incorrect, please check it again. API v2.0.2"}), 200, {'Content-Type': 'application/json'}

    except Exception as e:
        conn.close()
        return jsonify({"errormsg":"Username Incorrect. Please try again. API v2.0.2"}), 200, {'Content-Type': 'application/json'}

    
    cursor.execute(f"SELECT tokengen from client_database where username='{username}';")
    conn.commit()
    count_token = cursor.fetchall()
    tokenc = int(count_token[0][0])

    # cursor.execute(f"SELECT tokenlimit from client_database where username='{username}';")
    # conn.commit()
    # tokenlimit = cursor.fetchall()
    # tokenlim = int(tokenlimit[0][0])
    # print(tokenlim)

    # if tokenc >= tokenlim:
    #     conn.close()
    #     return jsonify({"Error":"You have already generated excess tokens. Please try again after they expire."}), 403, {'Content-Type': 'application/json'}
    
    admin_status = False
    try:
        """
        change account_expiry_date to None. This try-catch block below is only for accounts those created with /v2/autocredentials
        after the user has successfully logged in the for the first time.

        Also, this will allow the users to log in the for the first time, but will check if the account expiry date has been exceeded.
        In this case, although the username and the password is correct, the user is returned with a message that his credentials are correct, but
        the account has already expired.
        """

        cursor.execute(f"select row_to_json(client_database) from client_database where username='{username}'")
        
        try:
            acc_exp_date = cursor.fetchall()[0][0]['account_expiry_date']
            print(acc_exp_date)

            if acc_exp_date == None :
                print("no expiry date set.") 
            else:
                # if expiration date is over 7 days , block login 
                # use dateutil.parse library # from dateutil import parse
                if dateutil.parser.parse(acc_exp_date) < datetime.datetime.now(datetime.timezone.utc):
                    cursor.execute(f"UPDATE client_database set isauthorized='False' where username='{username}'")
                    conn.commit()
                    return jsonify({"errormsg":"Credentials matched! but your account has expired. Please contact your service provider to activate your account. API v2.0.2"}), 200, {'Content-Type': 'application/json'}
                else: # if the login takes places within the account expiration deadline, remove the account expiration date.
                    cursor.execute(f"UPDATE client_database set account_expiry_date=null where username='{username}'")
                    conn.commit()

        except Exception as e:
            print(e)
            with open("error_at_expiry_date_update.txt","a") as errorwrite:
                errorwrite.write(str(e))
                errorwrite.write("\n")
        
        # The parameter 'identity' can be any data that is json serializable
        access_token = create_access_token(identity=[username,datetime.datetime.utcnow().isoformat()+'+00:00'])
        
        print(f"{colors.green} Created Access Token for the user {colors.blue} {username} {colors.default}")
        
        cursor.execute(f"UPDATE client_database set tokengen={ tokenc + 1 } where username='{username}'")
        conn.commit()

        """
        Log the customer's last IP address of login.
        """
        ipaddress = request.environ.get("HTTP_X_REAL_IP", request.remote_addr)
        cursor.execute(f"UPDATE client_database set lastloginipaddress='{ipaddress}' where username='{username}'")
        conn.commit()
        
        """
        check if the account is administrator account
        """
        cursor.execute(f"SELECT isunlimited from client_database where username='{username}'")
        conn.commit()
        p = cursor.fetchall()
        admin_status = p[0][0]
        categories=[]
        try:
            cursor.execute(f"SELECT category_access from client_database where username='{username}'")
            conn.commit()
            catg = cursor.fetchall()
            catg_list = catg[0][0]
            if catg_list != 'all':
                conv_list = ast.literal_eval(catg_list)
                for data in conv_list:
                    new_data = reverse_category_mapper(data)
                    categories.append(new_data)
            else:
                categories =  catg_list
                    

        except:
            pass
        
        print(f"IsUnlimited: {admin_status}{colors.blue}{colors.default}")
        
        # log the login time
        last_logged_in_at = datetime.datetime.utcnow().isoformat()+'+00:00'
        cursor.execute(f"UPDATE client_database set last_logged_in_at='{last_logged_in_at}' where username='{username}'")
        conn.commit()        
        conn.close()

    except Exception as e:
        conn.close()
        return jsonify("Fatal Error at token generation. API v2.0.2"), 500


    return jsonify(access_token=access_token, admin_status = admin_status,enabled_categories = categories), 200, {'Content-Type': 'application/json'}

#######################################################


"""
API v2.0.3 

Search API for searching posts and groups in Telegram
    
        Usage:
            
            =============
            API MODE 1
            =============

                
            1. Queries Posts and Groups

                API Client code (localhost):
                
                curl -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MzA1NzExMjIsIm5iZiI6MTYzMDU3MTEyMiwianRpIjoiMDRhZGJiNGItMTI3Ny00MjM0LWEzZGUtOWMzNDBjYzU5ZTEyIiwiZXhwIjoxNjMwNTkyNzIyLCJpZGVudGl0eSI6InRlc3RhcGkiLCJmcmVzaCI6ZmFsc2UsInR5cGUiOiJhY2Nlc3MifQ.Ff9kFur853l9zFXIH_VeG6y9UZzyyj0d59w9rrsKJ4s' -H "Content-Type: application/json" -d '{"api_mode":"1","qtext":"python","max":2, "fuzzing":"AUTO","start_date":"2021-07-03", "end_date":"now","sort_order":"desc","select_field":"None"}' -X POST http://localhost:5000/v2/posts
                
                from Internet, example,
                curl -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MzA1NzExMjIsIm5iZiI6MTYzMDU3MTEyMiwianRpIjoiMDRhZGJiNGItMTI3Ny00MjM0LWEzZGUtOWMzNDBjYzU5ZTEyIiwiZXhwIjoxNjMwNTkyNzIyLCJpZGVudGl0eSI6InRlc3RhcGkiLCJmcmVzaCI6ZmFsc2UsInR5cGUiOiJhY2Nlc3MifQ.Ff9kFur853l9zFXIH_VeG6y9UZzyyj0d59w9rrsKJ4s' -H "Content-Type: application/json" -d '{"api_mode":"1","qtext":"python","max":2, "fuzzing":"AUTO","start_date":"2021-07-03", "end_date":"None","sort_order":"desc","select_field":"conv_name"}' -X POST https://api.recordedtelegram.com/v2/posts
                
                Elasticsearch search code:
                curl -H 'Content-Type: application/json' -XPOST localhost:9200/telegram/_search?pretty -d '{"size":5,  "query": { "bool":{ "must" : [{ "multi_match": { "query" : "python", "fields" : ["message","conv_name"] }},   {"range":{"date":{"gte":"2019-01-01","lte":"2021-01-01"}}}, {"fuzzy":{"message":{"value": "python","fuzziness":"AUTO"}}} ] }}, "sort" : [{"date": {"order":"asc"}}]}'

            =============
            API MODE 2
            =============

            1. Queries posts and grouptitles in REGEX mode
            
            Example:

            API Client code:
                Regex on 'message' field
                curl -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MzA1NzExMjIsIm5iZiI6MTYzMDU3MTEyMiwianRpIjoiMDRhZGJiNGItMTI3Ny00MjM0LWEzZGUtOWMzNDBjYzU5ZTEyIiwiZXhwIjoxNjMwNTkyNzIyLCJpZGVudGl0eSI6InRlc3RhcGkiLCJmcmVzaCI6ZmFsc2UsInR5cGUiOiJhY2Nlc3MifQ.Ff9kFur853l9zFXIH_VeG6y9UZzyyj0d59w9rrsKJ4s' -H "Content-Type: application/json" -d '{"api_mode":"2","qtext":"python","max":12, "field_name":"message","fuzzing":3,"start_date":"2017-07-03", "end_date":"now","sort_order":"desc"}' -X POST http://localhost:5000/v2/posts

                Regex on 'conv_name' field
                just change field_name to 'conv_name' in the request above

                from internet,
                curl -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MzA1NzExMjIsIm5iZiI6MTYzMDU3MTEyMiwianRpIjoiMDRhZGJiNGItMTI3Ny00MjM0LWEzZGUtOWMzNDBjYzU5ZTEyIiwiZXhwIjoxNjMwNTkyNzIyLCJpZGVudGl0eSI6InRlc3RhcGkiLCJmcmVzaCI6ZmFsc2UsInR5cGUiOiJhY2Nlc3MifQ.Ff9kFur853l9zFXIH_VeG6y9UZzyyj0d59w9rrsKJ4s' -H "Content-Type: application/json" -d '{"api_mode":"2","qtext":"python","max":12, "field_name":"message","fuzzing":3,"start_date":"2017-07-03", "end_date":"now","sort_order":"desc"}' -X POST https://api.recordedtelegram.com/v2/posts

                Elasticsearch search code:
                curl -H 'Content-Type: application/json' -XPOST 127.0.0.1:9200/telegram/_search?pretty -d '{"size":5,"query": { "bool":{"must":[{"regexp": {"conv_name": {"value": "Python","flags": "ALL","case_insensitive": "true","max_determinized_states": 10000,"rewrite": "constant_score"}}},   {"range":{"date":{"gte":"2020-01-01","lte":"now"}}}, {"fuzzy":{"message":{"value": "Python","fuzziness":"5"}}}]}},"sort" : [{"date": {"order":"asc"}}]}'
"""

@app.route('/v2/posts', methods=['POST','GET'])
@jwt_required
@maxResults_decorator
@category_access_decorator
def v2_postsearch(index_name):
    
    # Access the identity of the current user with get_jwt_identity
    jwt_all = get_jwt_identity()
    current_user = jwt_all[0]

    # Function to block usage of old tokens after change of password.
    if check_tokens(jwt_all) != 'successful':
        return check_tokens(jwt_all)[0]

    print(f"""{colors.green} User {current_user} has successfully logged. Accessing /v2/posts API from IP: {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} {colors.default}""")
    
    # Logging for /v2/users
    f = open("apilogs.txt", "a", encoding='UTF-8')
    #data_to_log = f'''DATETIME:{datetime.datetime.utcnow()}\nIPADDRESS:{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}\nUsername:{username}\n\n'''
    data_to_log = {"DATETIME":f"{datetime.datetime.utcnow().isoformat()+'+00:00'}","IPADDRESS":f"""{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}""","ENDPOINT":"/v2/posts","User": f"{current_user}"}
    f.write(str(data_to_log))
    f.write('\n')
    f.close()

    
    if 'jndi' in str(request.headers):
        data_to_log = str({"DATETIME":f"{datetime.datetime.utcnow().isoformat()+'+00:00'}","IPADDRESS":f"""{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}"""})
        header = '\n'+ str(request.headers)

        with open('LOG4Jattack.txt','a') as writer:
            writer.write(data_to_log +  header)
            writer.write('\n')
        
        return jsonify({"Error":"Unauthorized"}), 403


    """
    ____________________________________________________________________________________
    RATE_LIMITING CODE
    ____________________________________________________________________________________
    """
    funcall = rate_limiter(current_user)
    print(funcall)

    try:
        if int(funcall) >= 0:
            #print(type(funcall))
            print(f"{colors.green}No restrictions so far.{colors.default}")
    except Exception as e:
        #print(type(funcall))
        print(f"{colors.red}Restrictions in effect. {funcall[0]} {colors.default}")
        return funcall 

    #####################################################################################      
    
    print(f"{colors.yellow} Request received at /v2/posts {colors.default}")

    # check if a json request was made
    if not request.is_json:
        return jsonify({"errormsg": "Missing JSON in request"}), 400
    
    api_mode = int(request.json.get('api_mode',None))

    """
    =============
    API MODE 1
    =============

    1. Queries posts and grouptitles
    
    Example:

        API Client code (localhost):
        
        curl -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MzA1NzExMjIsIm5iZiI6MTYzMDU3MTEyMiwianRpIjoiMDRhZGJiNGItMTI3Ny00MjM0LWEzZGUtOWMzNDBjYzU5ZTEyIiwiZXhwIjoxNjMwNTkyNzIyLCJpZGVudGl0eSI6InRlc3RhcGkiLCJmcmVzaCI6ZmFsc2UsInR5cGUiOiJhY2Nlc3MifQ.Ff9kFur853l9zFXIH_VeG6y9UZzyyj0d59w9rrsKJ4s' -H "Content-Type: application/json" -d '{"api_mode":"1","qtext":"bank logs","max":20, "fuzzing":5,"start_date":"1989-07-03", "end_date":"now","sort_order":"desc","select_field":"conv_name"}' -X POST http://localhost:5000/v2/posts
        
        from Internet, example,
        curl -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MzA1NzExMjIsIm5iZiI6MTYzMDU3MTEyMiwianRpIjoiMDRhZGJiNGItMTI3Ny00MjM0LWEzZGUtOWMzNDBjYzU5ZTEyIiwiZXhwIjoxNjMwNTkyNzIyLCJpZGVudGl0eSI6InRlc3RhcGkiLCJmcmVzaCI6ZmFsc2UsInR5cGUiOiJhY2Nlc3MifQ.Ff9kFur853l9zFXIH_VeG6y9UZzyyj0d59w9rrsKJ4s' -H "Content-Type: application/json" -d '{"api_mode":"1","qtext":"bank logs","max":20, "fuzzing":5,"start_date":"1989-07-03", "end_date":"now","sort_order":"desc","select_field":"conv_name"}' -X POST https://api.recordedtelegram.com/v2/posts
        
    """

    if api_mode == 1:
        print(index_name)

        qtext = request.json.get('qtext', None)
        max_results = request.json.get('max', None)
        fuzzie = request.json.get('fuzzing', 0)
        start_date = request.json.get('start_date', None)
        end_date = request.json.get('end_date', None)
        sort_order = request.json.get('sort_order', None)
        select_group = request.json.get('select_field', None)
        search_type = request.json.get('search_type', None)
        multimedia_option = request.json.get('multimedia_option', None)
        search_filter = request.json.get('search_filter', None)
        search_after_id = request.json.get('search_after_id', None)
        spam_filter = request.json.get('spam_filter', None)
        print(f"{colors.green}API mode:\t{api_mode}{colors.default}\nQuery:\t{qtext}\nMax results requested:\t{max_results}\nFuzzing value:\t{fuzzie}\n")
        
        es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True) # include hostnames if different Elasticserver, e.g Elasticsearch(['192.168.1.20'])
        

        if qtext == None or max_results == None or fuzzie == None or start_date == None or end_date == None or sort_order  == None or select_group  == None:
            return jsonify({"errormsg":"Uh oh, careful with the fields in your request. It has to be exact. Refer the API documentation provided to you for API v2.0.3  Mode 1"}),403

        #-------------------------------------------------------------------------------------------------------------------------------#
        """
        Sanitizes all input parameters
        """
        
        # if not str(max_results).isnumeric():
        #     return jsonify({"errormsg":"Only positive integers allowed. API v2.0.3 Mode 1"}),403
        
        if max_results < 1:
            return jsonify({"errormsg":"Results can't be less than 1. API v2.0.3 MODE 1"}),403

        if str(fuzzie).isnumeric():
            if fuzzie > 5 or fuzzie < 0:
                return jsonify({"errormsg":"Fuzzing only allowed up to 1-5 characters or it should be set to AUTO. API v2.0.3 Mode 1"}),403
        else:
            if str(fuzzie) == 'AUTO':
                pass
            else:
                return jsonify({"errormsg":"Only AUTO keyword is possible if you do not specify a number to Fuzzing. API v2.0.3 Mode 1"}),403
        #slop for boith conatins and exact search
        default_slop = 0

        if ' ' in qtext and search_filter == 'contains':
            default_slop = 100
        
        #regex filter to remove htpps and www. from the qtext
        if search_filter == 'contains':
            url_regex = re.compile(r"https?://(www\.)?")
            qtext = url_regex.sub('', qtext).strip().strip('/')
        
        qtext = qtext.lower()
           

        if start_date == "None":
            start_date = "1989-11-10T12:34:00"
        
        if end_date == "None" or end_date == "now":
            end_date = "now"
        
        fields_selected = "message"
        
        fuzzy_selected = "message"
        
        

        # '''fuzziness update based on the post/title filter '''
        # if select_group == 'conv_name':
        #     fuzzy_selected = "conv_name"
            
        ''' fields filter based on post/title/userid/username filter'''
        user_list = []
        if select_group == 'conv_name':
            fields_selected = "conv_name"
        elif select_group == 'user_id':
            fields_selected = "id"
        elif select_group == 'username':
            #extracting partial match user id from the username provided by the users 
            user_res = es.search(index='onlineusers', body={
                "query": {
                    "match": {
                        "username": {
                            "query": qtext,
                            "fuzziness": 1
                        }
                    }
                }
            })

            for hit in user_res['hits']['hits']:
                user_list.append(hit["_source"]['userid'])
            qtext = user_list
            fields_selected = "id"
            print(user_list)
        
        #by Deafult the search query will be for exact anjd slop will be 0
        default_search_query = {"match_phrase": {
        fields_selected: {
            'query': qtext, 'slop': default_slop
                }
            }}

        default_search_filter = {'terms': {"is_group.keyword":  ["True", "False"]}}
        
        if search_type == 'group':
            default_search_filter = {
                'term': {"is_group.keyword": {"value": "True"}}}
        
        elif search_type == 'channel':
            default_search_filter = {
                'term': {"is_group.keyword": {"value": "False"}}}

        if select_group == 'None':
            default_search_query = {"multi_match": {
                "query": qtext, "type": "phrase", "fields": ["message", "conv_name"], "slop": default_slop}}
        
        #contains filter for regex and partial match
        if search_filter == 'contains' and ' ' not in qtext:
            default_query = 'prefix'
            if '*' in qtext:
                default_query = 'wildcard'

            default_search_query = {
                default_query: {
                    fields_selected: qtext

                }
            }

            if select_group == 'None':
                default_search_query = {"bool": {
                    "should": [
                        {default_query: {
                            "message": qtext

                        }},
                        {default_query: {
                            "conv_name": qtext

                        }}
                    ]
                }}
            try:
                contains_count_quer = {"query": {"bool": {"must": [default_search_query,default_search_filter, {"range": {"date": {"gte": f"{start_date}", "lte": f"{end_date}"}}}]}}}
                contains_doc_count = es.count(index=index_name,
                            body=contains_count_quer)
                
                if contains_doc_count['count'] <= 0:
                    default_field=[search_validator(qtext,fields_selected)]
                    if select_group == 'None':
                        default_field=[search_validator(qtext,"message"),search_validator(qtext,"conv_name")]
                    print(default_field,'<----defrault params --->')
                    default_search_query = {
                        "query_string": {
                                "query": f"*{qtext}*",
                                "fields": default_field
                            }
                        }
                    new_contains_count_quer = {"query": {"bool": {"must": [default_search_query,default_search_filter, {"range": {"date": {"gte": f"{start_date}", "lte": f"{end_date}"}}}]}}} 
                    new_contains_doc_count = es.count(index=index_name,
                            body=new_contains_count_quer)
                    if new_contains_doc_count['count'] <= 0:
                        if select_group == 'None':
                            default_search_query = {"multi_match": { "query": qtext, "type": "phrase", "fields": ["message", "conv_name"], "slop": default_slop}}
                        else:
                             default_search_query = {"match_phrase": {
                                            fields_selected: {
                                                'query': qtext, 'slop': default_slop
                                                    }
                                                }}
                    

            except Exception as e:
                print('query string not activated')
        
        if select_group == 'username':
            default_search_query = {"terms": {
                "id.keyword": user_list}}
        elif select_group == 'user_id':
            print('user id filter activated')

        # end of input sanitization
        #-------------------------------------------------------------------------------------------------------------------------------#

        try:
            # Curl 
            # curl -H 'Content-Type: application/json' -XPOST 127.0.0.1:9200/telegram/_search?pretty -d '{"size":2,"query": { "bool":{ "must" : [{ "multi_match": { "query" : "Python", "fields" : ["message","conv_name"] }}, {"range":{"date":{"gte":"2020-01-01","lte":"2021-01-01"}}}]}}}'
            
            if qtext == 'None':
                max_results = 20
            
            if sort_order != 'desc' and sort_order != 'asc':
                return jsonify({"errormsg":"sort_order can only be either asc or desc. API v2.0.3 MODE 1"}),403

            # if search_logging == True:
            #     with open('searchlogs.txt','a') as searchlog:
            #         searchlog.write(f"{qtext}")
            #         searchlog.write('\n')
            
            quer = {"size": max_results, "query": {"bool": {"must": [default_search_query,default_search_filter, {"range": {"date": {"gte": f"{start_date}", "lte": f"{end_date}"}}}]}}, "sort": [{"date": {"order": f"{sort_order}"}}]}
            count_quer = {"query": {"bool": {"must": [default_search_query,default_search_filter, {"range": {"date": {"gte": f"{start_date}", "lte": f"{end_date}"}}}]}}}
            print(quer)
            if spam_filter == 'True':
                #adding spam filters
                quer = {"size": max_results, "query": {"bool": {"must": [default_search_query, default_search_filter, {"range": {
                "date": {"gte": f"{start_date}", "lte": f"{end_date}"}}}]}},"collapse": {
                            "field": "message.keyword",
                            "inner_hits": {
                                "name": "latest",
                                        "size": 1
                            }
                    }, "sort": [{"date": {"order": f"{sort_order}"}}]}

            #Adding decoded search after key to query if it passed on the api 
            decode_key = "None"
            try:
                if search_after_id != None and search_after_id != 'None':
                    search_after_validator = pagination_checker_limiter(current_user)
                    if search_after_validator is False:
                        return jsonify({'errormsg':f'Your Pagination limit is reached. Please contact at {COMPANY_EMAIL} for more information.'}), 403

                    decode_key = cryptocode.decrypt(
                        str(search_after_id), '#random_pass1&*$@')
            except:
                print('could not decrypt the provided search after key')
            
            if decode_key != 'None':
                try:
                    print('activated')
                    quer['search_after'] = [decode_key]
                except:
                    print('search after could not ')

            res = es.search(index= index_name ,body= quer)
            doc_count = es.count(index=index_name,
                         body=count_quer)
            total_doc_count = 0
            try:
                total_doc_count = doc_count['count']
            except:
                pass
            
            #encrypting search_after key for passing it on frontend
            encoded_key = 'None'
            try:
                if len(res['hits']['hits']) > 1:
                    encoded_key = cryptocode.encrypt(
                        str(res['hits']['hits'][-1]['sort'][0]), '#random_pass1&*$@')
            except:
                print('could not encrypr/add search after key')
           
            #return str(res['hits']['hits'])
            scroll_auth = scroll_auth_extractor(current_user)
            
            return_list = [] 
            
            if spam_filter == 'True':
                for hit in res['hits']['hits']:
                    category = reverse_category_mapper(hit['_index'])
                    hit['_source']['category'] = category
                    return_list.append(hit["_source"])
            else:
                for hit in res['hits']['hits']:
                    try:
                        if multimedia_option == 'enabled':
                            if hit["_source"]['media'] == 'True' and hit["_source"]['fileext'] == '.jpg':
                                img_src = multimedia_crawler(
                                    hit["_source"]['link'], hit["_source"]['msgid'])
                                print(img_src)
                                if img_src != False:
                                    hit["_source"]['multimedia_link'] = img_src
                                else:
                                    hit["_source"]['multimedia_link'] = 'None'
                            else:
                                hit["_source"]['multimedia_link'] = 'None'
                        else:
                            hit["_source"]['multimedia_link'] = 'None'
                    except:
                        hit["_source"]['multimedia_link'] = 'None'
                    #category mapping for route and api
                    category = reverse_category_mapper(hit['_index'])
                    hit['_source']['category'] = category

                    return_list.append(hit["_source"])
            redis_file_saver = 'None'
            if len(return_list) > 1:
                redis_file_saver = redis_data_saver({'data': return_list}, 1, qtext)
            
            if return_list == []:
                return_list = ['No results. Please try again after some time. API v2.0.3 Mode 2 ']

                
            return json.dumps({'data': return_list, 'total_db_data': total_doc_count,'search_id': encoded_key,'scroll_auth':scroll_auth,"ratelimit":funcall,'file_id': redis_file_saver},ensure_ascii=False, indent=0, sort_keys=False).encode('utf-8'), 200, {'Content-Type': 'application/json'}

        except Exception as e:
            with open('errorAPIlogs.txt','a',encoding='UTF-8') as securitylogs:
                securitylogs.write(f"""Error detected at /v2/posts. API v2.0.3 MODE 1 Accessed by user {current_user} on {datetime.datetime.utcnow().isoformat()+'+00:00'} from IP: {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}. Error Message: {e} \n""")
            return jsonify({"errormsg": "Please check if you are requesting the correct indices, or contact your service provider. ERROR_CODE: API v2.0.3 Mode 1."}), 403

        """
        =============
        API MODE 2
        =============

        1. Queries posts and grouptitles in REGEX mode
        
        Example:

        API Client code:
            Regex on 'message' field
            curl -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MzA1NzExMjIsIm5iZiI6MTYzMDU3MTEyMiwianRpIjoiMDRhZGJiNGItMTI3Ny00MjM0LWEzZGUtOWMzNDBjYzU5ZTEyIiwiZXhwIjoxNjMwNTkyNzIyLCJpZGVudGl0eSI6InRlc3RhcGkiLCJmcmVzaCI6ZmFsc2UsInR5cGUiOiJhY2Nlc3MifQ.Ff9kFur853l9zFXIH_VeG6y9UZzyyj0d59w9rrsKJ4s' -H "Content-Type: application/json" -d '{"api_mode":"2","qtext":"python","max":12, "field_name":"message","fuzzing":3,"start_date":"2017-07-03", "end_date":"now", "sort_order":"desc"}' -X POST http://localhost:5000/v2/posts

            Regex on 'conv_name' field
            just change field_name to 'conv_name' in the request above

            from internet,
            curl -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MzA1NzExMjIsIm5iZiI6MTYzMDU3MTEyMiwianRpIjoiMDRhZGJiNGItMTI3Ny00MjM0LWEzZGUtOWMzNDBjYzU5ZTEyIiwiZXhwIjoxNjMwNTkyNzIyLCJpZGVudGl0eSI6InRlc3RhcGkiLCJmcmVzaCI6ZmFsc2UsInR5cGUiOiJhY2Nlc3MifQ.Ff9kFur853l9zFXIH_VeG6y9UZzyyj0d59w9rrsKJ4s' -H "Content-Type: application/json" -d '{"api_mode":"2","qtext":"python","max":12, "field_name":"message","fuzzing":3,"start_date":"2017-07-03", "end_date":"now", "sort_order":"desc"}' -X POST https://api.recordedtelegram.com/v2/posts

            Elasticsearch search code:
            curl -H 'Content-Type: application/json' -XPOST 127.0.0.1:9200/telegram/_search?pretty -d '{"size":5,"query": { "bool":{"should":[{"regexp": {"conv_name": {"value": "Python","flags": "ALL","case_insensitive": "true","max_determinized_states": 10000,"rewrite": "constant_score"}}},   {"range":{"date":{"gte":"2020-01-01","lte":"now"}}}, {"fuzzy":{"message":{"value": "Python","fuzziness":"5"}}}]}}}'
            
        """

    elif api_mode == 2:
        
        qtext = request.json.get('qtext', None)
        max_results = request.json.get('max', None)
        fuzzie = request.json.get('fuzzing', None)
        regex_field_name = request.json.get('field_name', None)
        search_after_id = request.json.get('search_after_id', None)
        start_date = request.json.get('start_date', None)
        end_date = request.json.get('end_date', None)
        sort_order = request.json.get('sort_order', None)
        logical_opertaor = 'must'
        default_search_query = {"regexp": {regex_validator(qtext, regex_field_name): {"value": f"""{qtext}""", "flags": "ALL","case_insensitive": "true", "max_determinized_states": 10000, "rewrite": "constant_score"}}}
        search_type = request.json.get('search_type', None)

        print(f"{colors.green}API mode:\t{api_mode}{colors.default}\nQuery:\t{qtext}\nMax results requested:\t{max_results}\n")

        if qtext == None or max_results == None or fuzzie == None or regex_field_name == None or start_date == None or end_date == None or sort_order  == None:
            return jsonify({"errormsg":"Uh oh, careful with the fields in your request. It has to be exact. Refer the API documentation provided to you for API v2.0.3  Mode 2"}),403

        #-------------------------------------------------------------------------------------------------------------------------------#
        
        """
        Sanitizes all input parameters
        """
        try:
            qtext = qtext.strip()
        except:
            pass
        
        if start_date == "None":
            start_date = "1989-11-10T12:34:00"
        
        if end_date == "None" or end_date == "now":
            end_date = "now"

        # if not str(max_results).isnumeric() or max_results > 1000:
        #     return jsonify({"errormsg":"You can not enter special characters inside the field that needs a number, or you want more than 1000 results, which is forbidden. API v2.0.3 Mode 2 "}),403
        
        if max_results < 1:
            return jsonify({"errormsg":"Results can't be less than 1. API v2.0.3 Mode 2 "}),403

        if str(fuzzie).isnumeric():
            if fuzzie > 5 or fuzzie < 0:
                return jsonify({"errormsg":"Fuzzing only allowed up to 1-5 characters or it should be set to AUTO. API v2.0.3 Mode 2 "}),403
        else:
            if str(fuzzie) == 'AUTO' or str(fuzzie) =='auto':
                pass
            else:
                return jsonify({"errormsg":"Only AUTO keyword is possible if you do not specify a number to Fuzzing. API v2.0.3 Mode 2 "}),403
        
        
        if sort_order != 'desc' and sort_order != 'asc':
            return jsonify({"errormsg":"sort_order can only be either asc or desc. API v2.0.3 Mode 2 "}),403
        
        #seperating groups and channel query
        default_search_filter = {'terms': {"is_group.keyword":  ["True", "False"]}}
        if search_type == 'group':
            default_search_filter = {
                'term': {"is_group.keyword": {"value": "True"}}}
        elif search_type == 'channel':
            default_search_filter = {
                'term': {"is_group.keyword": {"value": "False"}}}
        decode_key = "None"
        
        try:
            if search_after_id != None and search_after_id != 'None':
                search_after_validator = pagination_checker_limiter(current_user)
                if search_after_validator is False:
                        return jsonify({'errormsg':f'Your Pagination limit is reached. Please contact at {COMPANY_EMAIL} for more information.'}), 403
                        
                decode_key = cryptocode.decrypt(str(search_after_id), '#random_pass1&*$@')
        except:
            print('could not decrypt the provided search after key')
        # end of input sanitization
        #-------------------------------------------------------------------------------------------------------------------------------#

        try:
            es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True) # include hostnames if different Elasticserver, e.g Elasticsearch(['192.168.1.20'])

            # if search_logging == True:
            #     with open('searchlogs.txt','a', encoding='UTF-8') as searchlog:
            #         searchlog.write(qtext)
            #         searchlog.write('\n')

            if qtext == 'None':
                max_results = 20
               
            if regex_field_name != 'message' and regex_field_name != 'conv_name':
                new_query = {"size": max_results,
                     "query": {
                         "bool": {
                             "should": [
                                 {
                                     "bool": {
                                         "must": [
                                             {"regexp": {regex_validator(qtext, 'message'): {"value": f"""{qtext}""", "flags": "ALL",
                                                                     "case_insensitive": "true", "max_determinized_states": 10000, "rewrite": "constant_score"}}}, default_search_filter,{"range": {"date": {
                                                                         "gte": f"{start_date}", "lte": f"{end_date}"}}}
                                         ]
                                     }
                                 },
                                 {
                                     "bool": {
                                         "must": [
                                             {"regexp": {regex_validator(qtext, 'conv_name'): {"value": f"""{qtext}""", "flags": "ALL",
                                                                       "case_insensitive": "true", "max_determinized_states": 10000, "rewrite": "constant_score"}}}, default_search_filter,{"range": {"date": {
                                                                           "gte": f"{start_date}", "lte": f"{end_date}"}}}
                                         ]

                                     }
                                 }
                             ]
                         }
                     },
                      "sort": [{"date": {"order": f"{sort_order}"}}]
                     }
                print(new_query)
                if decode_key != 'None':
                    try:
                        print('activated')
                        new_query['search_after'] = [decode_key]
                    except:
                        print('search after could not ')

                res = es.search(index= index_name ,body=new_query) 

                count_quer = {
                     "query": {
                         "bool": {
                             "should": [
                                 {
                                     "bool": {
                                         "must": [
                                             {"regexp": {regex_validator(qtext, 'message'): {"value": f"""{qtext}""", "flags": "ALL",
                                                                     "case_insensitive": "true", "max_determinized_states": 10000, "rewrite": "constant_score"}}}, default_search_filter,{"range": {"date": {
                                                                         "gte": f"{start_date}", "lte": f"{end_date}"}}}
                                         ]
                                     }
                                 },
                                 {
                                     "bool": {
                                         "must": [
                                             {"regexp": {regex_validator(qtext, 'conv_name'): {"value": f"""{qtext}""", "flags": "ALL",
                                                                       "case_insensitive": "true", "max_determinized_states": 10000, "rewrite": "constant_score"}}}, default_search_filter,{"range": {"date": {
                                                                           "gte": f"{start_date}", "lte": f"{end_date}"}}}
                                         ]

                                     }
                                 }
                             ]
                         }
                     }
                     }
                doc_count = es.count(index=index_name,body=count_quer)

            else:
            
                # Curl
                # curl -H 'Content-Type: application/json' -XPOST 127.0.0.1:9200/telegram/_search?pretty -d '{"size":5,"query": { "bool":{"should":[{"regexp": {"conv_name": {"value": "Python","flags": "ALL","case_insensitive": "true","max_determinized_states": 10000,"rewrite": "constant_score"}}},   {"range":{"date":{"gte":"2020-01-01","lte":"now"}}}, {"fuzzy":{"message":{"value": "Python","fuzziness":"5"}}}]}}}'

                quer = {"size": max_results, "query": {"bool": {logical_opertaor: [default_search_query, default_search_filter,{"range": {"date": {"gte": f"{start_date}", "lte": f"{end_date}"}}}]}}, "sort": [{"date": {"order": f"{sort_order}"}}]}
                count_quer = { "query": {"bool": {logical_opertaor: [default_search_query, default_search_filter,{"range": {"date": {"gte": f"{start_date}", "lte": f"{end_date}"}}}]}}}
                print(quer)
                if decode_key != 'None':
                    try:
                        print('activated')
                        quer['search_after'] = [decode_key]
                    except:
                        print('search after could not ')
        
                res = es.search(index= index_name ,body= quer)
                doc_count = es.count(index=index_name,body=count_quer)
                #return str(res['hits']['hits'])
            encoded_key = 'None'
            try:
                if len(res['hits']['hits']) > 1:
                    encoded_key = cryptocode.encrypt(
                        str(res['hits']['hits'][-1]['sort'][0]), '#random_pass1&*$@')
            except:
                print('could not encrypr/add search after key')
            scroll_auth = scroll_auth_extractor(current_user)
            return_list = [] 
            total_doc_count = 0
            try:
                total_doc_count = doc_count['count']
            except:
                pass
            print(return_list)
            for hit in res['hits']['hits']:
                #print("inloop")
                #category mapping for route and api
                category = reverse_category_mapper(hit['_index'])
                hit['_source']['category'] = category
                return_list.append(hit["_source"])
                #print(return_list)

            redis_file_saver = 'None'
            if len(return_list) > 1:
                redis_file_saver = redis_data_saver({'data': return_list}, 1, qtext)
            if return_list == []:
                return_list = ['No results. Please try again after some time. API v2.0.3 Mode 2 ']
              
            
                
            return json.dumps({'data': return_list, 'total_db_data': total_doc_count,'search_id': encoded_key,'scroll_auth':scroll_auth,"ratelimit":funcall,'file_id': redis_file_saver},ensure_ascii=False, indent=0, sort_keys=False).encode('utf-8'), 200, {'Content-Type': 'application/json'}

        except Exception as e:
            with open('errorAPIlogs.txt','a',encoding='UTF-8') as securitylogs:
                securitylogs.write(f"""Error detected at v2/posts. APIv.2.2 MODE2 Accessed by user {current_user} on {datetime.datetime.utcnow().isoformat()+'+00:00'} from IP: {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}. Error Message: {e} \n""")
            return jsonify({"errormsg": "Please check if you are requesting the correct indices or inserting correct input parameters/data, or contact your service provider. ERROR_CODE: APIv2.2 Mode 2."}), 403


        """
        =============
        API MODE 3          NOTE : PLEASE CHECK THE API DOCUMENTATION FOR A DETAILED DESCRIPTION.
        =============

        1. Queries posts and grouptitles in LOGICAL mode , either AND or OR
        
        Example:

        API Client code:
            
            Dev mode:
            curl -H 'Content-Type: application/json' -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MzEyODA1NDksIm5iZiI6MTYzMTI4MDU0OSwianRpIjoiN2VkOGVmNmItNmMxNy00NjY4LWIxZjgtMTRjYjA5YWUwYjMwIiwiZXhwIjoxNjMxMzAyMTQ5LCJpZGVudGl0eSI6InRlc3RhcGkiLCJmcmVzaCI6ZmFsc2UsInR5cGUiOiJhY2Nlc3MifQ.l4Rz-qOaLrEYIcxVL6dTnulaHMqjNbxHKZKqEUwh1cE' -d '{"max":30,"qtext":["apple","hack"], "logic":["OR"],"sort_order":"desc","start_date":"None","end_date":"None","api_mode":"3"}' -XPOST 127.0.0.1:5000/v2/posts

            example 2:
            curl -H 'Content-Type: application/json' -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MzEyODA1NDksIm5iZiI6MTYzMTI4MDU0OSwianRpIjoiN2VkOGVmNmItNmMxNy00NjY4LWIxZjgtMTRjYjA5YWUwYjMwIiwiZXhwIjoxNjMxMzAyMTQ5LCJpZGVudGl0eSI6InRlc3RhcGkiLCJmcmVzaCI6ZmFsc2UsInR5cGUiOiJhY2Nlc3MifQ.l4Rz-qOaLrEYIcxVL6dTnulaHMqjNbxHKZKqEUwh1cE' -d '{"max":30,"qtext":[["apple","hack"],["tools","computer"]], "logic":["AND","AND","OR"],"sort_order":"desc","start_date":"None","end_date":"None","api_mode":"3"}' -XPOST 127.0.0.1:5000/v2/posts

            from internet,
            curl -H 'Content-Type: application/json' -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MzEyODA1NDksIm5iZiI6MTYzMTI4MDU0OSwianRpIjoiN2VkOGVmNmItNmMxNy00NjY4LWIxZjgtMTRjYjA5YWUwYjMwIiwiZXhwIjoxNjMxMzAyMTQ5LCJpZGVudGl0eSI6InRlc3RhcGkiLCJmcmVzaCI6ZmFsc2UsInR5cGUiOiJhY2Nlc3MifQ.l4Rz-qOaLrEYIcxVL6dTnulaHMqjNbxHKZKqEUwh1cE' -d '{"max":30,"qtext":["apple","hack"], "logic":["OR"],"sort_order":"desc","start_date":"None","end_date":"None","api_mode":"3"}' -XPOST https://api.recordedtelegram.com/v2/posts
            
            Elasticsearch search code:
            
            curl -H 'Content-Type: application/json' -d '{
                    "query": { "bool": { "must": [{
                        "query_string": {
                        "query": "(hack) OR (apple)",
                        "default_field": "message"
                        }
                    }
                    , {"range":{"date":{"gte":"2020-09-08","lte":"now"}}}]}}, "sort" : [{"date": {"order":"asc"}}]}' -XPOST 192.168.1.64:9200/telegram/_search?pretty

        """

    elif api_mode == 3:

        qtext = request.json.get('qtext', None)
        max_results = request.json.get('max', None)
        start_date = request.json.get('start_date', None)
        end_date = request.json.get('end_date', None)
        sort_order = request.json.get('sort_order', None)
        logic = request.json.get('logic', None)
        search_after_id = request.json.get('search_after_id', None)
        search_type = request.json.get('search_type', None)
        select_group = request.json.get('select_field', None)
        

        print(f"{colors.green}API mode:\t{api_mode}{colors.default}\nQuery:\t{qtext}\nMax results requested:\t{max_results}\n")

        if qtext == None or max_results == None or start_date == None or end_date == None or sort_order  == None :
            return jsonify({"errormsg":"Uh oh, careful with the fields in your request. It has to be exact. Refer the API documentation provided to you for API v2.0.3  Mode 3"}),403

        if select_group != 'conv_name' and select_group != 'message'  and select_group != None and select_group != 'None':
             return jsonify({"errormsg":"Uh oh, careful with the fields in your request. It has to be exact. Refer the API documentation provided to you for API v2.0.3  Mode 3"}),403

        if isinstance(qtext, str) == False:
            return jsonify({"errormsg":"qtext parameter must be a string type. Please refer the API documentation provided to you for API v2.0.3 Mode 3"}),403
        
        
        qtext = qtext.strip()
        #-------------------------------------------------------------------------------------------------------------------------------#

        
        """
        Sanitizes all input parameters
        """
        if start_date == "None":
            start_date = "1989-11-10T12:34:00"
        
        if end_date == "None" or end_date == "now":
            end_date = "now"

        if max_results < 1:
            return jsonify({"errormsg":"Results can't be less than 1. API v2.0.3 Mode 3 "}),403

        if sort_order != 'desc' and sort_order != 'asc':
            return jsonify({"errormsg":"sort_order can only be either asc or desc. API v2.0.3 Mode 3 "}),403
        


        try:
            es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True) # include hostnames if different Elasticserver, e.g Elasticsearch(['192.168.1.20'])

            if qtext == 'None':
                max_results = 20

            ################################## LOGICAL AND/OR QUERY BUILDING BLOCK , DO NOT EDIT ######################
            
            logical_query_string=qtext
            if logic == None:
                conv_data = logical_alert(qtext,True)
                print(conv_data)
                if conv_data != None:
                    all_keys = conv_data.keys()
                    if 'query' in all_keys:
                        logical_query_string =  conv_data['query']
                    elif 'message' in all_keys:
                        return jsonify({'errormsg':conv_data['message']}),403
                    else:
                        return jsonify({'errormsg':'Please check if you are requesting the correct indices or inserting correct input parameters/data for api_mode 3, or contact your service provider. ERROR_CODE: APIv2.2 Mode 3.'}),403

            print(f"{colors.green}Logical Query is:{colors.orange}\t {logical_query_string}\t{colors.default}")

            ################################## LOGICAL AND/OR QUERY BUILDING BLOCK ENDS HERE #########################

            #Adding decoded search after key to query if it passed on the api 
            decode_key = "None"
            try:
                if search_after_id != None and search_after_id != 'None':
                    search_after_validator = pagination_checker_limiter(current_user)
                    if search_after_validator is False:
                        return jsonify({'errormsg':f'Your Pagination limit is reached. Please contact at {COMPANY_EMAIL} for more information.'}), 403
                        
                    decode_key = cryptocode.decrypt(
                        str(search_after_id), '#random_pass1&*$@')
            except:
                print('could not decrypt the provided search after key')            
            default_search_filter = {'terms': {"is_group.keyword":  ["True", "False"]}}  
            if search_type != None:
                if search_type.lower() == 'group':
                    default_search_filter = {
                        'term': {"is_group.keyword": {"value": "True"}}}
                
                elif search_type.lower() == 'channel':
                    default_search_filter = {
                        'term': {"is_group.keyword": {"value": "False"}}} 
            
            default_field = ["message"]
                  
            if select_group == 'conv_name':
                default_field = ["conv_name"]
            
            try:
                checks_msg = re.compile('[`=<>?/\|@#,-_]')
        
                checkkey_msg = len(re.findall(checks_msg, qtext))
                if  checkkey_msg  > 0 and select_group != 'conv_name':
                    default_field = ["message.raw"]
            except Exception as e:
                pass

            print(logical_query_string)
            quer = {"size": max_results,
                    "query": { 
                        "bool": 
                        {"must": [ {
                                "query_string": {
                                        "query": f"{logical_query_string}",
                                        "fields":default_field
                                        }
                            },default_search_filter,    
                            {"range":{"date":{"gte":f"{start_date}","lte":f"{end_date}"}}},]}}, "sort" : [{"date": {"order":f"{sort_order}"}}]}
                
            count_quer = {
                    "query": { 
                        "bool": 
                        {"must": [ {
                                "query_string": {
                                        "query": f"{logical_query_string}",
                                        "fields":default_field
                                        }
                            },default_search_filter,    
                            {"range":{"date":{"gte":f"{start_date}","lte":f"{end_date}"}}}]}}}
            if decode_key != 'None':
                try:
                    quer['search_after'] = [decode_key]
                except:
                    print('search after could not ')

            res = es.search(index= index_name,body= quer)
            doc_count = es.count(index=index_name, body=count_quer)

            encoded_key = 'None'
            try:
                if len(res['hits']['hits']) > 1:
                    encoded_key = cryptocode.encrypt(
                        str(res['hits']['hits'][-1]['sort'][0]), '#random_pass1&*$@')
            except:
                print('could not encrypr/add search after key')
            #return str(res['hits']['hits'])
            scroll_auth = scroll_auth_extractor(current_user)
            return_list = [] 
            total_doc_count = 0
            try:
                total_doc_count = doc_count['count']
            except:
                pass
            print(return_list)
            for hit in res['hits']['hits']:
                #category mapping for route and api
                category = reverse_category_mapper(hit['_index'])
                hit['_source']['category'] = category
                return_list.append(hit["_source"])
                
            redis_file_saver = 'None'
            if len(return_list) > 1:
                redis_file_saver = redis_data_saver({'data': return_list}, 1, qtext)
            
            if return_list == []:
                return_list = ['No results. Please try again after some time. API v2.0.3 Mode 2 ']
            

            return json.dumps({'data': return_list, 'total_db_data': total_doc_count,'search_id': encoded_key,'scroll_auth':scroll_auth,"ratelimit":funcall,'file_id': redis_file_saver},ensure_ascii=False, indent=0, sort_keys=False).encode('utf-8'), 200, {'Content-Type': 'application/json'}
        
        except Exception as e:

            with open('errorAPIlogs.txt','a',encoding='UTF-8') as securitylogs:
                securitylogs.write(f"""Error detected at v2/posts. APIv.2.2 MODE 3 Accessed by user {current_user} on {datetime.datetime.utcnow().isoformat()+'+00:00'} from IP: {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}. Error Message: {e} \n""")
            return jsonify({"errormsg": "Please check if you are requesting the correct indices or inserting correct input parameters/data, or contact your service provider. ERROR_CODE: APIv2.2 Mode 3."}), 403
            
    else:
        return f"Error: Please select the correct API_MODE. ERROR_CODE: API v2.0.3 Mode 3"

#######################################################

"""
API v2.0.4

Search API for searching Users in Telegram
    
        Usage:
            
            =============
            API MODE 1
            =============

                
            1. Queries Usernames and Fullnames

                API Client code:
                curl -H "Content-Type: application/json" -d '{"api_mode":"1","name":"any_keyword_here","max":200, "fuzzing":3}' -X POST http://localhost:5000/v2/users

                from Internet,
                curl -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MzExODkxNTksIm5iZiI6MTYzMTE4OTE1OSwianRpIjoiMGI4MjA0YWUtNjFjNS00NzEzLWFiOWItZThhNTI5M2M4ZGMxIiwiZXhwIjoxNjMxMjEwNzU5LCJpZGVudGl0eSI6InRlc3RhcGkiLCJmcmVzaCI6ZmFsc2UsInR5cGUiOiJhY2Nlc3MifQ.eIL36RyMnnfbRHnb4l2LUE-bFeNvoKSSQWuXNwkNWYI' -H "Content-Type: application/json" -d '{"api_mode":"1","name":"hack","max":2, "fuzzing":3}' -X POST https://api.recordedtelegram.com/v2/users


            =============
            API MODE 2
            =============

            2. REGEX on Fullname of users, and Grouptitles
            
                API Client code:
                curl -H 'Content-Type: application/json' -d '{"api_mode":2,"max":2,"name":"[a-z]*"}' -XGET "127.0.0.1:5000/v2/users"

                from Internet,
                curl -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MzExODkxNTksIm5iZiI6MTYzMTE4OTE1OSwianRpIjoiMGI4MjA0YWUtNjFjNS00NzEzLWFiOWItZThhNTI5M2M4ZGMxIiwiZXhwIjoxNjMxMjEwNzU5LCJpZGVudGl0eSI6InRlc3RhcGkiLCJmcmVzaCI6ZmFsc2UsInR5cGUiOiJhY2Nlc3MifQ.eIL36RyMnnfbRHnb4l2LUE-bFeNvoKSSQWuXNwkNWYI' -H "Content-Type: application/json" -d '{"api_mode":2,"max":2,"name":"Lo.ely"}' -XPOST https://api.recordedtelegram.com/v2/users

                Elasticsearch search code:
                curl -H 'Content-Type: application/json' -d '{"size":200,"query": {"regexp": {"userfullname": {"value": "[a-z]*","flags": "ALL","case_insensitive": true,"max_determinized_states": 10000,"rewrite": "constant_score"}}}}' -XGET "127.0.0.1:9200/onlineusers/_search?pretty"
                
"""

@app.route('/v2/users', methods=['POST','GET'])
@jwt_required
@maxResults_decorator
def v2_usersearch():

    # Access the identity of the current user with get_jwt_identity
    jwt_all = get_jwt_identity()
    current_user = jwt_all[0]

    # Function to block usage of old tokens after change of password.
    if check_tokens(jwt_all) != 'successful':
        return check_tokens(jwt_all)[0]

    print(f"""{colors.green} User {current_user} has successfully logged. Accessing /v2/users API from IP: {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} {colors.default}""")
    
    # Logging for /v2/users
    f = open("apilogs.txt", "a", encoding='UTF-8')
    #data_to_log = f'''DATETIME:{datetime.datetime.utcnow()}\nIPADDRESS:{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}\nUsername:{username}\n\n'''
    data_to_log = {"DATETIME":f"{datetime.datetime.utcnow().isoformat()+'+00:00'}","IPADDRESS":f"""{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}""","ENDPOINT":"/v2/users","User": f"{current_user}"}
    f.write(str(data_to_log))
    f.write('\n')
    f.close()


    if 'jndi' in str(request.headers):
        data_to_log = str({"DATETIME":f"{datetime.datetime.utcnow().isoformat()+'+00:00'}","IPADDRESS":f"""{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}"""})
        header = '\n'+ str(request.headers)

        with open('LOG4Jattack.txt','a') as writer:
            writer.write(data_to_log +  header)
            writer.write('\n')
        
        return jsonify({"errormsg":"Unauthorized"}), 403


    """
    ____________________________________________________________________________________
    RATE_LIMITING CODE
    ____________________________________________________________________________________
    """
    funcall = rate_limiter(current_user)

    try:
        if int(funcall) >= 0:
            #print(type(funcall))
            print(f"{colors.green}No restrictions so far. {funcall} {colors.default}")
    except Exception as e:
        #print(type(funcall))
        print(f"{colors.red}Restrictions in effect. {funcall[0]} {colors.default}")
        return funcall        

    ####################################################################################
    print(f"{colors.yellow} Request received at /v2/users from {current_user} {colors.default}")

    # check if a json request was made 
    if not request.is_json:
        return jsonify({"errormsg": "Missing JSON in request"}), 400
    
    api_mode = int(request.json.get('api_mode',None))

    """
    =============
    API MODE 1
    =============

    1. Queries Usernames and Fullnames
    
    Example:

    API Client code:
    curl -H "Content-Type: application/json" -d '{"api_mode":"1","username":"any_keyword_here","max":200, fuzzing=3}' -X POST http://localhost:5000/v2/users

    From internet,
    curl -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MzExODkxNTksIm5iZiI6MTYzMTE4OTE1OSwianRpIjoiMGI4MjA0YWUtNjFjNS00NzEzLWFiOWItZThhNTI5M2M4ZGMxIiwiZXhwIjoxNjMxMjEwNzU5LCJpZGVudGl0eSI6InRlc3RhcGkiLCJmcmVzaCI6ZmFsc2UsInR5cGUiOiJhY2Nlc3MifQ.eIL36RyMnnfbRHnb4l2LUE-bFeNvoKSSQWuXNwkNWYI' -H "Content-Type: application/json" -d '{"api_mode":"1","name":"hack","max":2, "fuzzing":3}' -X POST https://api.recordedtelegram.com/v2/users
    """

    if api_mode == 1:
        username = request.json.get('name', None)
        max_results = request.json.get('max', None)
        #fuzzie = request.json.get('fuzzing', None)
        phone_filter = request.json.get('phone_filter', None)
        search_filter = request.json.get('search_filter', None)
        search_type = request.json.get('search_type', None)
        search_after_id = request.json.get('search_after_id', None)
        group_search_type = request.json.get('group_search_type', None)
        search_query = 'username'

        print(f"{colors.green}API mode:\t{api_mode}{colors.default}\nUsername searched:\t{username}\nMax results requested:\t{max_results}\n")

        if username == None or max_results == None:
            return jsonify({"errormsg": "Uh oh, careful with the fields in your request. It has to be exact. Refer the API documentation provided to you for API v2.0.4 Mode 1"}), 403

        #-------------------------------------------------------------------------------------------------------------------------------#
        """
            Sanitizes all input parameters
        """

        if ('"' in username or "'" in username):
            return jsonify({"errormsg": "You can not enter special characters inside the username field. API v2.0.4 MODE 1"}), 403

        checks = re.compile('[@!#$%^&()<>?/\|}{~:.]')

        if search_type != 'group':
            if(checks.search(username) == None):
                print("Valid format of username.")
            else:
                return jsonify({"errormsg": "You can not enter special characters inside the field. API v2.0.4 MODE 1"}), 403

        if search_type == 'username' and '*' in username :
            return jsonify({"errormsg": "You can not enter special characters inside the field. API v2.0.4 MODE 1"}), 403

        # if max_results < 1:
        #     return jsonify({"errormsg": "Results can't be less than 1. API v2.0.4 MODE 1"}), 403

        # if str(fuzzie).isnumeric():
        #     if fuzzie > 5 or fuzzie < 0:
        #         return jsonify({"errormsg": "Fuzzing only allowed up to 1-5 characters or it should be set to AUTO. API v2.0.4 MODE 1"}), 403
        # else:
        #     if str(fuzzie) == 'AUTO':
        #         pass
        #     else:
        #         return jsonify({"errormsg": "Only AUTO keyword is possible if you are not entering a number between 1-5. API v2.0.4 MODE 1"}), 403

        default_slop = 0
        if ' ' in username and search_filter == 'contains':
            default_slop = 100

        if search_type == 'phone':
            search_query = 'phone'
        elif search_type == 'user_id':
            search_query = 'userid'
        
        es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
        
        username = username.lower()
        default_search_query = {
            'match_phrase': {
                search_query: username
            }
        }
        if search_filter == 'contains' and ' ' not in username:
            default_query = 'prefix'
            if '*' in username:
                default_query = 'wildcard'

            default_search_query = {
                default_query: {
                    search_query: username

                }
            }

            if phone_filter == 'True':
                default_search_query = {"bool": {
                    "must": [
                        {
                            default_query: {
                                search_query: username

                            }
                        }
                    ],
                    'must_not': [
                        {'match': {'phone': 'None'}}
                    ]
                }}
            try:
                contains_count_quer = {"query": default_search_query}
                contains_doc_count = es.count(index='onlineusers',
                                            body=contains_count_quer)

                if contains_doc_count['count'] <= 0:
                    default_search_query = {
                        "query_string": {
                            "query": f"*{username}*",
                            "fields": [search_type]
                        }
                    }

            except Exception as e:
                print('query string not activated')

        else:
            
            if search_type == 'group':
                default_search_query = {
                    'term': {
                        'groupid': username
                    }
                }

                if group_search_type == 'group_username' or group_search_type == 'group_channel_name':
                    default_user = username
                    if group_search_type == 'group_channel_name':
                        channel_name = 'None'
                        res = es.search(index=all_index_name, size=1, body={
                        "query": {
                            'bool': {
                                'must': [{
                                    "match_phrase": {
                                        "conv_name": username
                                    }
                                },
                                    {
                                    "match": {
                                        "is_group": 'True'
                                    }
                                }]
                            }

                        },
                        "sort": [{"date": {"order": f"desc"}}]
                    })
                        if len(res['hits']['hits']) < 1:
                            return jsonify({"errormsg": "No data to display.Please try other search queries..."}), 403

                        try:
                            channel_name = res['hits']['hits'][0]['_source']['link']
                        except:
                            pass

                        if channel_name != 'None':
                            default_user = channel_name
                    
                    default_qtext = default_user
                    if 't.me' in default_user:
                        default_qtext = default_user.rsplit('/')[-1]
                        default_qtext = default_qtext.lower()
                    default_search_query = {
                        'term': {
                            'grouptitle': default_qtext
                        }
                    }

                if phone_filter == 'True':
                    default_search_query = {"bool": {
                        "must": [
                            default_search_query
                        ],
                        'must_not': [
                            {'match': {'phone': 'None'}}
                        ]
                    }}
            # include hostnames if different Elasticserver, e.g Elasticsearch(['192.168.1.20'])

            # wildcard for phone and userid
            if '*' in username and search_query != 'username':
                default_search_query = {
                    'wildcard': {
                        search_query: username
                    }
                }

            # search filter for username along with phone number
            if phone_filter == 'True' and search_query == 'username':
                default_search_query = {"bool": {
                    "must": [
                        {
                            'wildcard': {
                                search_query: username

                            }
                        }
                    ],
                    'must_not': [
                        {'match': {'phone': 'None'}}
                    ]
                }}

        print(default_search_query)
        quer = {"query": default_search_query, "sort": [ {"username.keyword": {"order": f"asc"}}]}
        decode_key = "None"
        try:
            if search_after_id != None and search_after_id != 'None':
                search_after_validator = pagination_checker_limiter(current_user)
                if search_after_validator is False:
                        return jsonify({'errormsg':f'Your Pagination limit is reached. Please contact at {COMPANY_EMAIL} for more information.'}), 403
                        
                decode_key = cryptocode.decrypt(
                    str(search_after_id), '#random_pass1&*$@')
        except:
            print('could not decrypt the provided search after key')

        if decode_key != 'None':
            try:
                print('activated')
                quer['search_after'] = [decode_key]
            except:
                print('search after could not be added')
        #-------------------------------------------------------------------------------------------------------------------------------#

        try:
            
            res = es.search(index="onlineusers", size=max_results,
                        body=quer)
            doc_count = es.count(index="onlineusers",
                        body={"query": default_search_query})
            #return str(res['hits']['hits'])
            
            return_list = [] 
            print(return_list)
            
            for hit in res['hits']['hits']:
                #print("inloop")
                return_list.append(hit["_source"])
                #print(return_list)

            # needs to be updated later incase of empty result

            # if return_list == [] and search_query == 'username':
            #     print("Nothing was found inside usernames, trying in fullnames.")
            #     quer =  {"from":0,"size":max_results,"query":{"match":{"userfullname":{"query": username,"fuzziness":f"{fuzzie}"}}}}
            #     count_quer = {"query":{"match":{"userfullname":{"query": username,"fuzziness":f"{fuzzie}"}}}}
                
            #     if phone_filter == 'True':
            #         quer = {"from": 0, "size": max_results, "query": {
            #             "bool": {
            #                 "must": [
            #                     {"match": {"userfullname": {
            #                         "query": username, "fuzziness": f"{fuzzie}"}}}

            #                 ],
            #                 'must_not': [
            #                     {'match': {'phone': 'None'}}
            #                 ]
            #             },

            #         }}
            #         count_quer = { "query": {
            #             "bool": {
            #                 "must": [
            #                     {"match": {"userfullname": {
            #                         "query": username, "fuzziness": f"{fuzzie}"}}}

            #                 ],
            #                 'must_not': [
            #                     {'match': {'phone': 'None'}}
            #                 ]
            #             },

            #         }}

            #     if username == 'None':
            #         quer = {"from":0,"size":200,"query":{"fuzzy":{"userfullname":{"value": username,"fuzziness":f"{fuzzie}"}}}}
            #         count_quer = {"query":{"fuzzy":{"userfullname":{"value": username,"fuzziness":f"{fuzzie}"}}}}
               
            #     res = es.search(index="onlineusers",body= quer)
            #     doc_count = es.count(index="onlineusers",body= count_quer)
            # #return str(res['hits']['hits'])
            
            #     return_list = [] 
            #     print(return_list)
            #     for hit in res['hits']['hits']:
            #         #print("inloop")
            #         return_list.append(hit["_source"])
            #         #print(return_list)
            encoded_key = 'None'
            try:
                if len(res['hits']['hits']) > 1:
                    encoded_key = cryptocode.encrypt(
                        str(res['hits']['hits'][-1]['sort'][0]), '#random_pass1&*$@')
            except:
                print('could not encrypr/add search after key')    
            if return_list == []:
                return_list = ['No results. Please try again after some time.']
            # scroll_auth = scroll_auth_extractor(current_user)  
            
            # return_list.append({"ratelimit":funcall})
            total_doc_count = 0
            try:
                    total_doc_count = doc_count['count']
            except:
                    pass
            print("rate limit -----> ", funcall)
            
            return json.dumps({'data': return_list, 'total_db_data': total_doc_count,'search_id': encoded_key,"ratelimit":funcall},ensure_ascii=False, indent=0, sort_keys=False).encode('utf-8'), 200, {'Content-Type': 'application/json'}

        except Exception as e:
            return jsonify({"errormsg":"Please check if you are requesting the correct indices, or contact your service provider. ERROR_CODE: API v2.0.4 Mode 1."}), 403

        """
        API MODE 2

        2. REGEX on Full name of users, with parameters of max. return values
        
        Example:

        API Client code:
        curl -H 'Content-Type: application/json' -d '{"api_mode":2,"max":2,"name":"[a-z]*"}' -XGET "127.0.0.1:5000/v2/users"

        from Internet, 
        curl -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MzExODkxNTksIm5iZiI6MTYzMTE4OTE1OSwianRpIjoiMGI4MjA0YWUtNjFjNS00NzEzLWFiOWItZThhNTI5M2M4ZGMxIiwiZXhwIjoxNjMxMjEwNzU5LCJpZGVudGl0eSI6InRlc3RhcGkiLCJmcmVzaCI6ZmFsc2UsInR5cGUiOiJhY2Nlc3MifQ.eIL36RyMnnfbRHnb4l2LUE-bFeNvoKSSQWuXNwkNWYI' -H "Content-Type: application/json" -d '{"api_mode":"1","name":"hack","max":2, "fuzzing":3}' -X POST https://api.recordedtelegram.com/v2/users
   
        Elasticsearch search code:
        curl -H 'Content-Type: application/json' -d '{"size":200,"query": {"regexp": {"userfullname": {"value": "[a-z]*","flags": "ALL","case_insensitive": true,"max_determinized_states": 10000,"rewrite": "constant_score"}}}}' -XGET "127.0.0.1:9200/onlineusers/_search?pretty"
        """

    elif api_mode == 2:
        max_results = request.json.get('max', None)
        regex_string = request.json.get('name', None)
        search_after_id = request.json.get('search_after_id', None)
        phone_filter = request.json.get('phone_filter', None)
        search_type = request.json.get('search_type', None)
        search_query = 'username'

        print(f"""{colors.green}API mode:\t{api_mode}{colors.default}\nUserfullname searched:\t{regex_string}\nMax results requested:\t{max_results}\n""")

        if max_results == None:
            return jsonify({"errormsg":"Uh oh, careful with the fields in your request. It has to be exact. Refer the API documentation provided to you for for API v2.0.4 Mode 2."}),403
        
        if regex_string == None:
            return jsonify({"errormsg":"Uh oh, careful with the fields in your request. It has to be exact. Refer the API documentation provided to you for for API v2.0.4 Mode 2."}),403
        #-------------------------------------------------------------------------------------------------------------------------------#
        """
        Sanitizes all input parameters
        """
        
        # if not str(max_results).isnumeric() or max_results > 1000:
        #     return jsonify({"errormsg":"You can not enter special characters inside the field that needs a number, or you want more than 1000 results, which is forbidden."}),403
        
        # if max_results < 1 or max_results > 500 :
        #     return jsonify({"errormsg":"Results can't be less than 1 or more than 500. API v2.0.4 MODE 1"}),403

        print(regex_string)

        if search_type == 'phone':
            search_query = 'phone'
        elif search_type == 'user_id':
            search_query = 'userid'

        # end of input sanitization
        #-------------------------------------------------------------------------------------------------------------------------------#

        try:

            # if search_logging == True:
            #     with open('searchlogs.txt','a', encoding='UTF-8') as searchlog:
            #         searchlog.write(regex_string)
            #         searchlog.write('\n')

            es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True) # include hostnames if different Elasticserver, e.g Elasticsearch(['192.168.1.20'])
            quer ={"size":max_results,"query": {"regexp": {f'{search_query}.keyword': {"value": f"{regex_string}","flags": "ALL","case_insensitive": "true","max_determinized_states": 10000,"rewrite": "constant_score"}}}}
            count_quer ={"query": {"regexp": {"userfullname.keyword": {"value": f"{regex_string}","flags": "ALL","case_insensitive": "true","max_determinized_states": 10000,"rewrite": "constant_score"}}}}
            
            if phone_filter == 'True':
                quer = {"size":max_results,"query":{
                    "bool":{"must":[
                        {"regexp": {"userfullname.keyword": {"value": f"{regex_string}","flags": "ALL","case_insensitive": "true","max_determinized_states": 10000,"rewrite": "constant_score"}}},
                    ],
                    'must_not': [
                                {'match': {'phone': 'None'}}
                            ]
                      }
                     },
                      "sort": [ {"username.keyword": {"order": f"asc"}}]
                    }
            
                count_quer ={"query":{
                    "bool":{"must":[
                        {"regexp": {"userfullname": {"value": f"{regex_string}","flags": "ALL","case_insensitive": "true","max_determinized_states": 10000,"rewrite": "constant_score"}}},
                    ],
                    'must_not': [
                                {'match': {'phone': 'None'}}
                            ]
                      }
                     },
               
                    }
            
                
            doc_count = es.count(index='onlineusers',body=count_quer)
            print(quer)
            decode_key = "None"
            try:
                if search_after_id != None and search_after_id != 'None':
                    search_after_validator = pagination_checker_limiter(current_user)
                    if search_after_validator is False:
                        return jsonify({'errormsg':f'Your Pagination limit is reached. Please contact at {COMPANY_EMAIL} for more information.'}), 403
                        
                    decode_key = cryptocode.decrypt(
                        str(search_after_id), '#random_pass1&*$@')
            except:
                print('could not decrypt the provided search after key')
            
            if decode_key != 'None':
                try:
                    print('activated')
                    quer['search_after'] = [decode_key]
                except:
                    print('search after could not ')
            
            res = es.search(index="onlineusers",body= quer)
            encoded_key = 'None'
            try:
                if len(res['hits']['hits']) > 1:
                    encoded_key = cryptocode.encrypt(
                        str(res['hits']['hits'][-1]['sort'][0]), '#random_pass1&*$@')
            except:
                print('could not encrypr/add search after key')
            #return str(res['hits']['hits'])
            
            return_list = [] 
            print(return_list)
            
            for hit in res['hits']['hits']:
                #print("inloop")
                return_list.append(hit["_source"])
                #print(return_list)

            if return_list == [] :
                print("Nothing was found inside fullnames, trying in grouptitle.")
                es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True) # include hostnames if different Elasticserver, e.g Elasticsearch(['192.168.1.20'])
                quer ={"size":max_results,"query": {"regexp": {"grouptitle": {"value": f"{regex_string}","flags": "ALL","case_insensitive": "true","max_determinized_states": 10000,"rewrite": "constant_score"}}}}
                count_quer ={"query": {"regexp": {"grouptitle": {"value": f"{regex_string}","flags": "ALL","case_insensitive": "true","max_determinized_states": 10000,"rewrite": "constant_score"}}}}
                print("Looking into groups with query: ",quer)
                
                res = es.search(index="onlineusers",body= quer)
                doc_count = es.count(index='onlineusers',body=count_quer)
                #return str(res['hits']['hits'])
                
                return_list = [] 
                print(return_list)
                for hit in res['hits']['hits']:
                    #print("inloop")
                    return_list.append(hit["_source"])
                    #print(return_list)

                return_list = 'No results. Please try again after some time.'
            total_doc_count = 0
            try:
                total_doc_count = doc_count['count']
            except:
                pass
       
            print("rate limit -----> ", funcall)
            scroll_auth = scroll_auth_extractor(current_user)

            return json.dumps({'data': return_list, 'total_db_data': total_doc_count,'search_id': encoded_key,'scroll_auth':scroll_auth,"ratelimit":funcall},ensure_ascii=False, indent=0, sort_keys=False).encode('utf-8'), 200, {'Content-Type': 'application/json'}

        except Exception as e:
            return jsonify({"errormsg": "Please check if you are requesting the correct indices, or contact your service provider. ERROR_CODE: API v2.0.4 Mode 2"}), 403

    else:
         return "Error: API_MODE ERROR. Enter correct API_MODE. ERROR_CODE: API v2.0.4 Mode 2"




######################################################################################
"""
TOTAL NUMBER OF DOCS INDEXED
"""

@app.route('/v2/totaldocuments', methods=['GET'])
def getalldocumentscount():
    try:
        es = Elasticsearch(elastichost, timeout=60, max_retries=10, retry_on_timeout=True) # include hostnames if different Elasticserver, e.g Elasticsearch(['192.168.1.20'])
        
        e1 = "telegram2_alias"
        first = json.loads(subprocess.run(f"curl -XGET 127.0.0.1:9200/{e1}/_count", shell=True , capture_output=True).stdout.decode())['count']

        e2 = "extremepolitical2_alias"
        second = json.loads(subprocess.run(f"curl -XGET 127.0.0.1:9200/{e2}/_count", shell=True , capture_output=True).stdout.decode())['count']

        e3 = "financials"
        third = json.loads(subprocess.run(f"curl -XGET 127.0.0.1:9200/{e3}/_count", shell=True , capture_output=True).stdout.decode())['count']

        e4 = "religion_spirituality_alias"
        fourth = json.loads(subprocess.run(f"curl -XGET 127.0.0.1:9200/{e4}/_count", shell=True , capture_output=True).stdout.decode())['count']

        e5 = "pharma_drugs_alias"
        fifth = json.loads(subprocess.run(f"curl -XGET 127.0.0.1:9200/{e5}/_count", shell=True , capture_output=True).stdout.decode())['count']

        e6 = "criminal_activities_alias"
        sixth = json.loads(subprocess.run(f"curl -XGET 127.0.0.1:9200/{e6}/_count", shell=True , capture_output=True).stdout.decode())['count']

        e7 = "cyber_security_alias"
        seventh = json.loads(subprocess.run(f"curl -XGET 127.0.0.1:9200/{e7}/_count", shell=True , capture_output=True).stdout.decode())['count']

        e8 = "information_technology"
        eighth = json.loads(subprocess.run(f"curl -XGET 127.0.0.1:9200/{e8}/_count", shell=True , capture_output=True).stdout.decode())['count']

        e9 = "betting_gambling_alias"
        ninth = json.loads(subprocess.run(f"curl -XGET 127.0.0.1:9200/{e9}/_count", shell=True , capture_output=True).stdout.decode())['count']
        
        e10 = "onlineusers"
        tenth = json.loads(subprocess.run(f"curl -XGET 127.0.0.1:9200/{e10}/_count", shell=True , capture_output=True).stdout.decode())['count']  
        
        e11 = "adult_content_alias"
        eleven = json.loads(subprocess.run(f"curl -XGET 127.0.0.1:9200/{e11}/_count", shell=True , capture_output=True).stdout.decode())['count']     

        e12 = "blogs_vlogs_alias"
        twelve = json.loads(subprocess.run(f"curl -XGET 127.0.0.1:9200/{e12}/_count", shell=True , capture_output=True).stdout.decode())['count']
        
        e13 = "science_index_alias"
        thirteen = json.loads(subprocess.run(f"curl -XGET 127.0.0.1:9200/{e13}/_count", shell=True , capture_output=True).stdout.decode())['count']

        e14 = "education_alias"
        fourteen = json.loads(subprocess.run(f"curl -XGET 127.0.0.1:9200/{e14}/_count", shell=True , capture_output=True).stdout.decode())['count'] 

        e15 = "movies_alias"
        fifteen = json.loads(subprocess.run(f"curl -XGET 127.0.0.1:9200/{e15}/_count", shell=True , capture_output=True).stdout.decode())['count']

        e16 = "travelling_alias"
        sixteen = json.loads(subprocess.run(f"curl -XGET 127.0.0.1:9200/{e16}/_count", shell=True , capture_output=True).stdout.decode())['count']

        e17 = "gaming_alias"
        seventeen = json.loads(subprocess.run(f"curl -XGET 127.0.0.1:9200/{e17}/_count", shell=True , capture_output=True).stdout.decode())['count']

        e18 = "lifestyle_alias"
        eighteen = json.loads(subprocess.run(f"curl -XGET 127.0.0.1:9200/{e18}/_count", shell=True , capture_output=True).stdout.decode())['count']

        e19 = "music_alias"
        nineteen = json.loads(subprocess.run(f"curl -XGET 127.0.0.1:9200/{e19}/_count", shell=True , capture_output=True).stdout.decode())['count']

        e20 = "books_comics_alias"
        twenty = json.loads(subprocess.run(f"curl -XGET 127.0.0.1:9200/{e20}/_count", shell=True , capture_output=True).stdout.decode())['count']

        e21 = "fashion_beauty_alias"
        tw1 = json.loads(subprocess.run(f"curl -XGET 127.0.0.1:9200/{e21}/_count", shell=True , capture_output=True).stdout.decode())['count']

        e22 = "design_arch_alias"
        tw2 = json.loads(subprocess.run(f"curl -XGET 127.0.0.1:9200/{e22}/_count", shell=True , capture_output=True).stdout.decode())['count']

        e23 = "humor_entertainment_alias"
        tw3 = json.loads(subprocess.run(f"curl -XGET 127.0.0.1:9200/{e23}/_count", shell=True , capture_output=True).stdout.decode())['count']

        e24 = "culture_events_alias"
        tw4 = json.loads(subprocess.run(f"curl -XGET 127.0.0.1:9200/{e24}/_count", shell=True , capture_output=True).stdout.decode())['count']

        
        e25 = "uncategorized"
        tw5 = json.loads(subprocess.run(f"curl -XGET 127.0.0.1:9200/{e25}/_count", shell=True , capture_output=True).stdout.decode())['count']
    

        total_C = int(tw1)+ int(tw2) + int(tw3) + int(tw4) + int(first) + int(second) + int(third) + int(fourth) + int(fifth) + int(sixth) + int(seventh) + int(eighth) + int(ninth) + int(eleven) + int(twelve) + int(thirteen)+ int(fourteen) + int(fifteen) + int(sixteen) + int(seventeen) + int(eighteen) + int(nineteen) + int(twenty)+int(tw5)
        total_all = total_C + int(tenth)
        
        documents = {"total_posts_indexed_hacking_category":f"""{first}""", 
        "total_posts_indexed_political_category":f"""{second}""",
        "total_posts_indexed_financials_category":f"""{third}""", 
        "total_posts_indexed_spiritual_and_religious_category":f"""{fourth}""",
        "total_posts_indexed_pharma_and_category":f"""{fifth}""",
        "total_posts_indexed_criminal_activites":f"""{sixth}""",
        "total_posts_indexed_cyber_security":f"""{seventh}""",
        "total_posts_indexed_information_technology":f"""{eighth}""",
        "total_posts_indexed_betting_gambling":f"""{ninth}""",
        "total_posts_indexed_adult_content":f"""{eleven}""",
        "total_posts_indexed_blogs_vlogs":f"""{twelve}""",
        "total_posts_indexed_education":f"""{fourteen}""", 
        "total_posts_indexed_science_category":f"""{thirteen}""",
        "total_posts_indexed_movies":f"{fifteen}" ,
        "total_posts_indexed_travelling":f"{sixteen}",
        "total_posts_indexed_gaming":f"{seventeen}",
        "total_posts_indexed_lifestyle":f"{eighteen}" , 
        "total_posts_indexed_music":f"{nineteen}",
        "total_posts_indexed_books_comics":f"{twenty}" ,
        "total_posts_indexed_fashion_beauty":f"{tw1}" ,
        "total_posts_indexed_design_arch":f"{tw2}" ,
        "total_posts_indexed_humor_entertainment":f"{tw3}" ,
        "total_posts_indexed_culture_events":f"{tw4}" ,
        "total_posts_indexed_uncategorized":f"{tw5}",
        "total_users_indexed":f"""{tenth}""",
        "total_posts_all_index":f"""{total_C}""",
        "total_searchable_documents_all_index":f"""{total_all}"""}
        
        return json.dumps(documents,ensure_ascii=False, indent=0, sort_keys=False).encode('utf-8'), 200, {'Content-Type': 'application/json'}

    except Exception as e:
        with open('errorAPIlogs.txt','a',encoding='UTF-8') as securitylogs:
            securitylogs.write(f"""Error detected at v2/totaldocuments. APIv.2 Accessed on {datetime.datetime.utcnow().isoformat()+'+00:00'} from IP: {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}. Error Message: {e} \n""")
        return f"Error: Something happened while fetching the count at /v2/totaldocuments."


####################
"""
THIS API IS NOT FOR CUSTOMERS. DO NOT DOCUMENT IT IN THE API DOCUMENTATION.
Indexing Route for Scraper Data.

How to use this API?
    Calculate MD5 hash from str() from the dictionary data
    and pass the hash to the API as id.

    pass the passcode as '@lazlxEtIcS3A9rchIydzXiqg2u21fr0m' 
    and data as the dictionary data.


    Example:

    curl -H 'Content-Type: application/json' -d '{"data": { 
    "id": "PeerUser(user_id=1482008667)",
    "toid": "1288833614",
    "conv_name": "Qanon France",
    "convimagehash": "35f35792078ac841001ae78b28d7d9bf",
    "mext": "jpg",
    "date": "2021-09-04T17:14:47+00:00",
    "msgid": "360924",
    "message": "**Les dômes solaires pourraient dessaler l’eau de mer à l’échelle commerciale\n\nLa première usine de dômes solaires est en cours de construction en Arabie saoudite.\n\n71 % de la Terre est recouverte d’eau, mais seulement 3 % de cette eau est douce. Le dessalement efficace de l’eau de mer à grande échelle serait clairement une réalisation qui changerait le monde et qui serait célébrée dans le monde entier.\n\n**C’est dans cette optique que la société londonienne Solar Water PLC a récemment signé un accord avec le gouvernement saoudien dans le cadre du projet __« NEOM »,__ un projet d’avenir propre de 500 milliards de dollars. L’entreprise construit la __« première usine de dessalement utilisant la technologie des dômes solaires »__, explique un reportage de CNN Arabia (traduit sur le site web de Solar Water PLC).\n                                                                                                                                                      **Un avenir de dessalement de l’eau de mer neutre en carbone\n\n**L’accord, conclu le 29 janvier 2020, verra l’entreprise londonienne construire sa technologie dans le nord-ouest de l’Arabie saoudite, l’usine à dôme solaire devant être terminée à la mi-2021.\n\nL’usine est essentiellement __« un pot en acier enterré sous terre, recouvert d’un dôme »,__ ce qui lui donne l’apparence d’une boule, a déclaré David Reavley, PDG de Solar Water, à __CNN Arabia__. Le dôme en verre, une forme de technologie d’énergie solaire concentrée (CSP), est entouré de réflecteurs __« héliostatiques »__ qui concentrent le rayonnement solaire vers l’intérieur. La chaleur est transférée à l’eau de mer à l’intérieur du dôme, qui s’évapore puis se condense pour former de l’eau douce. La centrale à dôme solaire n’utilise pas les fibres polluantes généralement employées dans les technologies de dessalement par osmose inverse, et M. Reavley affirme qu’elle est peu coûteuse et rapide à construire, tout en étant neutre en carbone.\n                                                                                                                                                         **Des questions subsistent sur l’énergie solaire concentrée\n\n**Des questions subsistent en effet sur l’efficacité de la technologie CSP. Une étude réalisée en 2019, par exemple, a souligné qu’il y a peu de preuves soutenant le fait que la technologie pourrait être efficacement déployée à une échelle de masse. Les enjeux sont donc élevés pour l’expérience de 2021 de Solar Water PLC. S’ils atteignent leur objectif, ils prouveront la faisabilité d’une nouvelle technique de dessalement neutre en carbone qui ne nécessite pas de grandes quantités d’électricité ni de produits chimiques polluants.\n\nSolar Water PLC n’est pas la seule entreprise à vouloir fournir des services de dessalement de l’eau de mer à grande échelle. Climate Fund Manager et Solar Water Solutions, par exemple, installent environ 200 unités de dessalement neutres en carbone dans le comté de Kitui, au Kenya, avec l’objectif à long terme de fournir de l’eau propre à 400 000 personnes d’ici 2023.\n\nDes solutions telles que le dôme solaire de Solar Water PLC sont particulièrement importantes au Moyen-Orient, car de grandes régions de la zone reçoivent peu de précipitations et les sources d’eau douce font défaut. Une autre expérience récente a vu le déploiement de __« drones de pluie »__ aux Émirats arabes unis. Ces drones controversés déchargent de l’électricité près des nuages pour encourager la transpiration. La lumière du soleil, en revanche, est abondante, ce qui signifie qu’elle peut être exploitée pour produire de l’électricité et, dans ce cas, pour transformer l’eau de mer en eau douce potable.\n\n[🔗 Article\n](https://www.anguillesousroche.com/environnement/les-domes-solaires-pourraient-dessaler-leau-de-mer-a-lechelle-commerciale/)                                                                                                                                                             👇👇👇 Découvrez\nhttps://t.me/linfoautrement 🌍🌎🌏",
    "forwarderid": "None",
    "forwardedfromchanid": "1319181144",
    "mentioned": "False",
    "fromscheduled": "False",
    "viabotid": "None",
    "editdate": "None",
    "replytomsgid": "None",
    "media": "True",
    "filename": "NA",
    "fileext": ".jpg",
    "filehash": "NA",
    "filesize": "18470",
    "views": "1140"
    }, "id":"0db39adc5a6e0b0c5fa8edc3a7f5d203", "passcode":"@lazlxEtIcS3A9rchIydzXiqg2u21fr0m"}'  -XPOST https://api.recordedtelegram.com/v2/indexer

"""

@app.route('/v2/indexer', methods=['POST'])
def v2_indexer():

    index_name = 'telegram2_alias'
    # check if a json request was made
    if not request.is_json:
        return jsonify({"errormsg": "Missing JSON in request"}), 403

    # Logging for /v2/indexer
    f = open("indexerlogs.txt", "a", encoding='UTF-8')
    #data_to_log = f'''DATETIME:{datetime.datetime.utcnow()}\nIPADDRESS:{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}\nUsername:{username}\n\n'''
    data_to_log = {"DATETIME":f"{datetime.datetime.utcnow().isoformat()+'+00:00'}","IPADDRESS":f"""{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}""","ENDPOINT":"/v2/indexer"}
    f.write(str(data_to_log))
    f.write('\n')
    f.close()

    secret_code = request.json.get('passcode', None)
    idx = request.json.get('id', None)
    data = request.json.get('data', None)

    if secret_code == None:
        return jsonify({"errormsg":"Uh oh, careful with the fields in your request. It has to be exactly 'secret_code'."}),403

    if idx == None:
        return jsonify({"errormsg":"Uh oh, careful with the fields in your request. It has to be exactly 'id'."}),403

    if data == None:
        return jsonify({"errormsg":"Uh oh, careful with the fields in your request. It has to be exactly 'data'."}),403

    if idx.isalnum() and len(idx) == 32:  # For MD5 hashes
        pass
    else:
        return jsonify({"errormsg":"Hashes should be alphanumberic and length should be 32, i.e MD5."}),403

    if secret_code == '@lazlxEtIcS3A9rchIydzXiqg2u21fr0m':
        pass
    else:
        return jsonify({"errormsg":"Please enter the correct secret_code"}),403

    # Elasticsearch Object
    es = Elasticsearch(elastichost, timeout = 120 )
    
    try:                        
        es.get(index= index_name, id=idx)
        #print(res1)
        print(f"""{colors.grey} Document with id {idx} {colors.yellow}already exists{colors.grey}, skipping. request from IP {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} {colors.default}""")
        return jsonify({"info":"Data already indexed before. Try something else."}),200
    except Exception as e:
        # print(type(e), e)
        if '"found":false' in str(e):
            index_unpresence = index_hex_id_checker(idx)
            if index_unpresence == True:
                res = es.index(index= index_name, body=data, id = idx)
                print(f"""{colors.blue} Result -> {res['result']} with id {idx} from IP {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}{colors.default}""")
                return jsonify({"info":f"""Successfully indexed with id {idx}"""}),201
            else:
                print(f"""{colors.grey} Document with id {idx} {colors.yellow}already exists{colors.grey}, skipping. request from IP {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} {colors.default}""")
                return jsonify({"info":"Data already indexed before. Try something else."}),200
        else:
            return jsonify({"info":f"""Request not valid."""}),400

# indexer category 2 : extrempol
@app.route('/v2/indexer/extremepolitical2', methods=['POST'])
def v2_indexer_extremepolitical2():

    index_name = 'extremepolitical2_alias'
    # check if a json request was made
    if not request.is_json:
        return jsonify({"errormsg": "Missing JSON in request"}), 403

    # Logging for /v2/indexer
    f = open("indexerlogs.txt", "a", encoding='UTF-8')
    #data_to_log = f'''DATETIME:{datetime.datetime.utcnow()}\nIPADDRESS:{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}\nUsername:{username}\n\n'''
    data_to_log = {"DATETIME":f"{datetime.datetime.utcnow().isoformat()+'+00:00'}","IPADDRESS":f"""{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}""","ENDPOINT":"/v2/indexer/extremepolitical2_alias"}
    f.write(str(data_to_log))
    f.write('\n')
    f.close()

    secret_code = request.json.get('passcode', None)
    idx = request.json.get('id', None)
    data = request.json.get('data', None)

    if secret_code == None:
        return jsonify({"errormsg":"Uh oh, careful with the fields in your request. It has to be exactly 'secret_code'."}),403

    if idx == None:
        return jsonify({"errormsg":"Uh oh, careful with the fields in your request. It has to be exactly 'id'."}),403

    if data == None:
        return jsonify({"errormsg":"Uh oh, careful with the fields in your request. It has to be exactly 'data'."}),403

    if idx.isalnum() and len(idx) == 32:  # For MD5 hashes
        pass
    else:
        return jsonify({"errormsg":"Hashes should be alphanumberic and length should be 32, i.e MD5."}),403

    if secret_code == '@lazlxEtIcS3A9rchIydzXiqg2u21fr0m':
        pass
    else:
        return jsonify({"errormsg":"Please enter the correct secret_code"}),403

    # Elasticsearch Object
    es = Elasticsearch(elastichost, timeout = 120 )
    
    try:                        
        es.get(index= index_name, id=idx)
        #print(res1)
        print(f"""{colors.grey} Document with id {idx} {colors.yellow}already exists{colors.grey}, skipping. request from IP {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} {colors.default}""")
        return jsonify({"info":"Data already indexed before. Try something else."}),200
    except Exception as e:
        # print(type(e), e)
        if '"found":false' in str(e):
            index_unpresence = index_hex_id_checker(idx)
            if index_unpresence == True:
                res = es.index(index= index_name, body=data, id = idx)
                print(f"""{colors.blue} Result -> {res['result']} with id {idx} from IP {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}{colors.default}""")
                return jsonify({"info":f"""Successfully indexed with id {idx}"""}),201
            else:
                print(f"""{colors.grey} Document with id {idx} {colors.yellow}already exists{colors.grey}, skipping. request from IP {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} {colors.default}""")
                return jsonify({"info":"Data already indexed before. Try something else."}),200
        else:
            return jsonify({"info":f"""Request not valid."""}),400
##############################################################################

# indexer category 3 : Financials
@app.route('/v2/indexer/financials', methods=['POST'])
def v2_indexer_financials():

    index_name = 'financials_alias'
    # check if a json request was made
    if not request.is_json:
        return jsonify({"errormsg": "Missing JSON in request"}), 403

    # Logging for /v2/indexer
    f = open("indexerlogs.txt", "a", encoding='UTF-8')
    #data_to_log = f'''DATETIME:{datetime.datetime.utcnow()}\nIPADDRESS:{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}\nUsername:{username}\n\n'''
    data_to_log = {"DATETIME":f"{datetime.datetime.utcnow().isoformat()+'+00:00'}","IPADDRESS":f"""{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}""","ENDPOINT":"/v2/indexer/financials"}
    f.write(str(data_to_log))
    f.write('\n')
    f.close()

    secret_code = request.json.get('passcode', None)
    idx = request.json.get('id', None)
    data = request.json.get('data', None)

    if secret_code == None:
        return jsonify({"errormsg":"Uh oh, careful with the fields in your request. It has to be exactly 'secret_code'."}),403

    if idx == None:
        return jsonify({"errormsg":"Uh oh, careful with the fields in your request. It has to be exactly 'id'."}),403

    if data == None:
        return jsonify({"errormsg":"Uh oh, careful with the fields in your request. It has to be exactly 'data'."}),403

    if idx.isalnum() and len(idx) == 32:  # For MD5 hashes
        pass
    else:
        return jsonify({"errormsg":"Hashes should be alphanumberic and length should be 32, i.e MD5."}),403

    if secret_code == '@lazlxEtIcS3A9rchIydzXiqg2u21fr0m':
        pass
    else:
        return jsonify({"errormsg":"Please enter the correct secret_code"}),403

    # Elasticsearch Object
    es = Elasticsearch(elastichost, timeout = 120 )
    
    try:                        
        es.get(index= index_name, id=idx)
        #print(res1)
        print(f"""{colors.grey} Document with id {idx} {colors.yellow}already exists{colors.grey}, skipping. request from IP {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} {colors.default}""")
        return jsonify({"info":"Data already indexed before. Try something else."}),200
    except Exception as e:
        # print(type(e), e)
        if '"found":false' in str(e):
            index_unpresence = index_hex_id_checker(idx)
            if index_unpresence == True:
                res = es.index(index= index_name, body=data, id = idx)
                print(f"""{colors.blue} Result -> {res['result']} with id {idx} from IP {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}{colors.default}""")
                return jsonify({"info":f"""Successfully indexed with id {idx}"""}),201
            else:
                print(f"""{colors.grey} Document with id {idx} {colors.yellow}already exists{colors.grey}, skipping. request from IP {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} {colors.default}""")
                return jsonify({"info":"Data already indexed before. Try something else."}),200
        else:
            return jsonify({"info":f"""Request not valid."""}),400
##############################################################################


# indexer category 4 : religion_spirituality
@app.route('/v2/indexer/religion_spirituality', methods=['POST'])
def v2_indexer_religion_spirituality():

    index_name = 'religion_spirituality_alias'
    # check if a json request was made
    if not request.is_json:
        return jsonify({"errormsg": "Missing JSON in request"}), 403

    # Logging for /v2/indexer
    f = open("indexerlogs.txt", "a", encoding='UTF-8')
    #data_to_log = f'''DATETIME:{datetime.datetime.utcnow()}\nIPADDRESS:{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}\nUsername:{username}\n\n'''
    data_to_log = {"DATETIME":f"{datetime.datetime.utcnow().isoformat()+'+00:00'}","IPADDRESS":f"""{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}""","ENDPOINT":"/v2/indexer/religion_spirituality_alias"}
    f.write(str(data_to_log))
    f.write('\n')
    f.close()

    secret_code = request.json.get('passcode', None)
    idx = request.json.get('id', None)
    data = request.json.get('data', None)

    if secret_code == None:
        return jsonify({"errormsg":"Uh oh, careful with the fields in your request. It has to be exactly 'secret_code'."}),403

    if idx == None:
        return jsonify({"errormsg":"Uh oh, careful with the fields in your request. It has to be exactly 'id'."}),403

    if data == None:
        return jsonify({"errormsg":"Uh oh, careful with the fields in your request. It has to be exactly 'data'."}),403

    if idx.isalnum() and len(idx) == 32:  # For MD5 hashes
        pass
    else:
        return jsonify({"errormsg":"Hashes should be alphanumberic and length should be 32, i.e MD5."}),403

    if secret_code == '@lazlxEtIcS3A9rchIydzXiqg2u21fr0m':
        pass
    else:
        return jsonify({"errormsg":"Please enter the correct secret_code"}),403

    # Elasticsearch Object
    es = Elasticsearch(elastichost, timeout = 120 )
    
    try:                        
        es.get(index= index_name, id=idx)
        #print(res1)
        print(f"""{colors.grey} Document with id {idx} {colors.yellow}already exists{colors.grey}, skipping. request from IP {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} {colors.default}""")
        return jsonify({"info":"Data already indexed before. Try something else."}),200
    except Exception as e:
        # print(type(e), e)
        if '"found":false' in str(e):
            index_unpresence = index_hex_id_checker(idx)
            if index_unpresence == True:
                res = es.index(index= index_name, body=data, id = idx)
                print(f"""{colors.blue} Result -> {res['result']} with id {idx} from IP {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}{colors.default}""")
                return jsonify({"info":f"""Successfully indexed with id {idx}"""}),201
            else:
                print(f"""{colors.grey} Document with id {idx} {colors.yellow}already exists{colors.grey}, skipping. request from IP {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} {colors.default}""")
                return jsonify({"info":"Data already indexed before. Try something else."}),200
        else:
            return jsonify({"info":f"""Request not valid."""}),400

##############################################################################

# indexer category 5 : pharma_drugs
@app.route('/v2/indexer/pharmad', methods=['POST'])
def v2_indexer_pharmad():

    index_name = 'pharma_drugs_alias'
    # check if a json request was made
    if not request.is_json:
        return jsonify({"errormsg": "Missing JSON in request"}), 403

    # Logging for /v2/indexer
    f = open("indexerlogs.txt", "a", encoding='UTF-8')
    #data_to_log = f'''DATETIME:{datetime.datetime.utcnow()}\nIPADDRESS:{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}\nUsername:{username}\n\n'''
    data_to_log = {"DATETIME":f"{datetime.datetime.utcnow().isoformat()+'+00:00'}","IPADDRESS":f"""{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}""","ENDPOINT":"/v2/indexer/pharma_drugs_alias"}
    f.write(str(data_to_log))
    f.write('\n')
    f.close()

    secret_code = request.json.get('passcode', None)
    idx = request.json.get('id', None)
    data = request.json.get('data', None)

    if secret_code == None:
        return jsonify({"errormsg":"Uh oh, careful with the fields in your request. It has to be exactly 'secret_code'."}),403

    if idx == None:
        return jsonify({"errormsg":"Uh oh, careful with the fields in your request. It has to be exactly 'id'."}),403

    if data == None:
        return jsonify({"errormsg":"Uh oh, careful with the fields in your request. It has to be exactly 'data'."}),403

    if idx.isalnum() and len(idx) == 32:  # For MD5 hashes
        pass
    else:
        return jsonify({"errormsg":"Hashes should be alphanumberic and length should be 32, i.e MD5."}),403

    if secret_code == '@lazlxEtIcS3A9rchIydzXiqg2u21fr0m':
        pass
    else:
        return jsonify({"errormsg":"Please enter the correct secret_code"}),403

    # Elasticsearch Object
    es = Elasticsearch(elastichost, timeout = 120 )
    
    try:                        
        es.get(index= index_name, id=idx)
        #print(res1)
        print(f"""{colors.grey} Document with id {idx} {colors.yellow}already exists{colors.grey}, skipping. request from IP {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} {colors.default}""")
        return jsonify({"info":"Data already indexed before. Try something else."}),200
    except Exception as e:
        # print(type(e), e)
        if '"found":false' in str(e):
            index_unpresence = index_hex_id_checker(idx)
            if index_unpresence == True:
                res = es.index(index= index_name, body=data, id = idx)
                print(f"""{colors.blue} Result -> {res['result']} with id {idx} from IP {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}{colors.default}""")
                return jsonify({"info":f"""Successfully indexed with id {idx}"""}),201
            else:
                print(f"""{colors.grey} Document with id {idx} {colors.yellow}already exists{colors.grey}, skipping. request from IP {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} {colors.default}""")
                return jsonify({"info":"Data already indexed before. Try something else."}),200
        else:
            return jsonify({"info":f"""Request not valid."""}),400

# indexer category 5 : criminal_activities
@app.route('/v2/indexer/criminal_activities', methods=['POST'])
def v2_indexer_criminal_activities():

    index_name = 'criminal_activities_alias'
    # check if a json request was made
    if not request.is_json:
        return jsonify({"errormsg": "Missing JSON in request"}), 403

    # Logging for /v2/indexer
    f = open("indexerlogs.txt", "a", encoding='UTF-8')
    #data_to_log = f'''DATETIME:{datetime.datetime.utcnow()}\nIPADDRESS:{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}\nUsername:{username}\n\n'''
    data_to_log = {"DATETIME":f"{datetime.datetime.utcnow().isoformat()+'+00:00'}","IPADDRESS":f"""{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}""","ENDPOINT":"/v2/indexer/criminal_activities_alias"}
    f.write(str(data_to_log))
    f.write('\n')
    f.close()

    secret_code = request.json.get('passcode', None)
    idx = request.json.get('id', None)
    data = request.json.get('data', None)

    if secret_code == None:
        return jsonify({"errormsg":"Uh oh, careful with the fields in your request. It has to be exactly 'secret_code'."}),403

    if idx == None:
        return jsonify({"errormsg":"Uh oh, careful with the fields in your request. It has to be exactly 'id'."}),403

    if data == None:
        return jsonify({"errormsg":"Uh oh, careful with the fields in your request. It has to be exactly 'data'."}),403

    if idx.isalnum() and len(idx) == 32:  # For MD5 hashes
        pass
    else:
        return jsonify({"errormsg":"Hashes should be alphanumberic and length should be 32, i.e MD5."}),403

    if secret_code == '@lazlxEtIcS3A9rchIydzXiqg2u21fr0m':
        pass
    else:
        return jsonify({"errormsg":"Please enter the correct secret_code"}),403

    # Elasticsearch Object
    es = Elasticsearch(elastichost, timeout = 120 )
    
    try:                        
        es.get(index= index_name, id=idx)
        #print(res1)
        print(f"""{colors.grey} Document with id {idx} {colors.yellow}already exists{colors.grey}, skipping. request from IP {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} {colors.default}""")
        return jsonify({"info":"Data already indexed before. Try something else."}),200
    except Exception as e:
        # print(type(e), e)
        if '"found":false' in str(e):
            index_unpresence = index_hex_id_checker(idx)
            if index_unpresence == True:
                res = es.index(index= index_name, body=data, id = idx)
                print(f"""{colors.blue} Result -> {res['result']} with id {idx} from IP {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}{colors.default}""")
                return jsonify({"info":f"""Successfully indexed with id {idx}"""}),201
            else:
                print(f"""{colors.grey} Document with id {idx} {colors.yellow}already exists{colors.grey}, skipping. request from IP {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} {colors.default}""")
                return jsonify({"info":"Data already indexed before. Try something else."}),200
        else:
            return jsonify({"info":f"""Request not valid."""}),400

# indexer category 6 : cyber_security
@app.route('/v2/indexer/cyber_security', methods=['POST'])
def v2_indexer_cyber_security():

    index_name = 'cyber_security_alias'
    # check if a json request was made
    if not request.is_json:
        return jsonify({"errormsg": "Missing JSON in request"}), 403

    # Logging for /v2/indexer
    f = open("indexerlogs.txt", "a", encoding='UTF-8')
    #data_to_log = f'''DATETIME:{datetime.datetime.utcnow()}\nIPADDRESS:{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}\nUsername:{username}\n\n'''
    data_to_log = {"DATETIME":f"{datetime.datetime.utcnow().isoformat()+'+00:00'}","IPADDRESS":f"""{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}""","ENDPOINT":"/v2/indexer/cyber_security_alias"}
    f.write(str(data_to_log))
    f.write('\n')
    f.close()

    secret_code = request.json.get('passcode', None)
    idx = request.json.get('id', None)
    data = request.json.get('data', None)

    if secret_code == None:
        return jsonify({"errormsg":"Uh oh, careful with the fields in your request. It has to be exactly 'secret_code'."}),403

    if idx == None:
        return jsonify({"errormsg":"Uh oh, careful with the fields in your request. It has to be exactly 'id'."}),403

    if data == None:
        return jsonify({"errormsg":"Uh oh, careful with the fields in your request. It has to be exactly 'data'."}),403

    if idx.isalnum() and len(idx) == 32:  # For MD5 hashes
        pass
    else:
        return jsonify({"errormsg":"Hashes should be alphanumberic and length should be 32, i.e MD5."}),403

    if secret_code == '@lazlxEtIcS3A9rchIydzXiqg2u21fr0m':
        pass
    else:
        return jsonify({"errormsg":"Please enter the correct secret_code"}),403

    # Elasticsearch Object
    es = Elasticsearch(elastichost, timeout = 120 )
    
    try:                        
        es.get(index= index_name, id=idx)
        #print(res1)
        print(f"""{colors.grey} Document with id {idx} {colors.yellow}already exists{colors.grey}, skipping. request from IP {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} {colors.default}""")
        return jsonify({"info":"Data already indexed before. Try something else."}),200
    except Exception as e:
        # print(type(e), e)
        if '"found":false' in str(e):
            index_unpresence = index_hex_id_checker(idx)
            if index_unpresence == True:
                res = es.index(index= index_name, body=data, id = idx)
                print(f"""{colors.blue} Result -> {res['result']} with id {idx} from IP {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}{colors.default}""")
                return jsonify({"info":f"""Successfully indexed with id {idx}"""}),201
            else:
                print(f"""{colors.grey} Document with id {idx} {colors.yellow}already exists{colors.grey}, skipping. request from IP {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} {colors.default}""")
                return jsonify({"info":"Data already indexed before. Try something else."}),200
        else:
            return jsonify({"info":f"""Request not valid."""}),400

# indexer category 7 : cyber_security
@app.route('/v2/indexer/information_technology', methods=['POST'])
def v2_indexer_information_technology():

    index_name = 'information_technology_alias'
    # check if a json request was made
    if not request.is_json:
        return jsonify({"errormsg": "Missing JSON in request"}), 403

    # Logging for /v2/indexer
    f = open("indexerlogs.txt", "a", encoding='UTF-8')
    #data_to_log = f'''DATETIME:{datetime.datetime.utcnow()}\nIPADDRESS:{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}\nUsername:{username}\n\n'''
    data_to_log = {"DATETIME":f"{datetime.datetime.utcnow().isoformat()+'+00:00'}","IPADDRESS":f"""{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}""","ENDPOINT":"/v2/indexer/information_technology"}
    f.write(str(data_to_log))
    f.write('\n')
    f.close()

    secret_code = request.json.get('passcode', None)
    idx = request.json.get('id', None)
    data = request.json.get('data', None)

    if secret_code == None:
        return jsonify({"errormsg":"Uh oh, careful with the fields in your request. It has to be exactly 'secret_code'."}),403

    if idx == None:
        return jsonify({"errormsg":"Uh oh, careful with the fields in your request. It has to be exactly 'id'."}),403

    if data == None:
        return jsonify({"errormsg":"Uh oh, careful with the fields in your request. It has to be exactly 'data'."}),403

    if idx.isalnum() and len(idx) == 32:  # For MD5 hashes
        pass
    else:
        return jsonify({"errormsg":"Hashes should be alphanumberic and length should be 32, i.e MD5."}),403

    if secret_code == '@lazlxEtIcS3A9rchIydzXiqg2u21fr0m':
        pass
    else:
        return jsonify({"errormsg":"Please enter the correct secret_code"}),403

    # Elasticsearch Object
    es = Elasticsearch(elastichost, timeout = 120 )
    
    try:                        
        es.get(index= index_name, id=idx)
        #print(res1)
        print(f"""{colors.grey} Document with id {idx} {colors.yellow}already exists{colors.grey}, skipping. request from IP {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} {colors.default}""")
        return jsonify({"info":"Data already indexed before. Try something else."}),200
    except Exception as e:
        # print(type(e), e)
        if '"found":false' in str(e):
            index_unpresence = index_hex_id_checker(idx)
            if index_unpresence == True:
                res = es.index(index= index_name, body=data, id = idx)
                print(f"""{colors.blue} Result -> {res['result']} with id {idx} from IP {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}{colors.default}""")
                return jsonify({"info":f"""Successfully indexed with id {idx}"""}),201
            else:
                print(f"""{colors.grey} Document with id {idx} {colors.yellow}already exists{colors.grey}, skipping. request from IP {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} {colors.default}""")
                return jsonify({"info":"Data already indexed before. Try something else."}),200
        else:
            return jsonify({"info":f"""Request not valid."""}),400


@app.route('/v2/indexer/betting_gambling', methods=['POST'])
def v2_indexer_betting_gambling():

    index_name = 'betting_gambling_alias'
    # check if a json request was made
    if not request.is_json:
        return jsonify({"errormsg": "Missing JSON in request"}), 403

    # Logging for /v2/indexer
    f = open("indexerlogs.txt", "a", encoding='UTF-8')
    #data_to_log = f'''DATETIME:{datetime.datetime.utcnow()}\nIPADDRESS:{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}\nUsername:{username}\n\n'''
    data_to_log = {"DATETIME":f"{datetime.datetime.utcnow().isoformat()+'+00:00'}","IPADDRESS":f"""{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}""","ENDPOINT":"/v2/indexer/information_technology"}
    f.write(str(data_to_log))
    f.write('\n')
    f.close()

    secret_code = request.json.get('passcode', None)
    idx = request.json.get('id', None)
    data = request.json.get('data', None)

    if secret_code == None:
        return jsonify({"errormsg":"Uh oh, careful with the fields in your request. It has to be exactly 'secret_code'."}),403

    if idx == None:
        return jsonify({"errormsg":"Uh oh, careful with the fields in your request. It has to be exactly 'id'."}),403

    if data == None:
        return jsonify({"errormsg":"Uh oh, careful with the fields in your request. It has to be exactly 'data'."}),403

    if idx.isalnum() and len(idx) == 32:  # For MD5 hashes
        pass
    else:
        return jsonify({"errormsg":"Hashes should be alphanumberic and length should be 32, i.e MD5."}),403

    if secret_code == '@lazlxEtIcS3A9rchIydzXiqg2u21fr0m':
        pass
    else:
        return jsonify({"errormsg":"Please enter the correct secret_code"}),403

    # Elasticsearch Object
    es = Elasticsearch(elastichost, timeout = 120 )
    
    try:                        
        es.get(index= index_name, id=idx)
        #print(res1)
        print(f"""{colors.grey} Document with id {idx} {colors.yellow}already exists{colors.grey}, skipping. request from IP {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} {colors.default}""")
        return jsonify({"info":"Data already indexed before. Try something else."}),200
    except Exception as e:
        # print(type(e), e)
        if '"found":false' in str(e):
            index_unpresence = index_hex_id_checker(idx)
            if index_unpresence == True:
                res = es.index(index= index_name, body=data, id = idx)
                print(f"""{colors.blue} Result -> {res['result']} with id {idx} from IP {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}{colors.default}""")
                return jsonify({"info":f"""Successfully indexed with id {idx}"""}),201
            else:
                print(f"""{colors.grey} Document with id {idx} {colors.yellow}already exists{colors.grey}, skipping. request from IP {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} {colors.default}""")
                return jsonify({"info":"Data already indexed before. Try something else."}),200
        else:
            return jsonify({"info":f"""Request not valid."""}),400

@app.route('/v2/indexer/adult_content', methods=['POST'])
def v2_indexer_adult_content():

    index_name = 'adult_content_alias'
    # check if a json request was made
    if not request.is_json:
        return jsonify({"errormsg": "Missing JSON in request"}), 403

    # Logging for /v2/indexer
    f = open("indexerlogs.txt", "a", encoding='UTF-8')
    #data_to_log = f'''DATETIME:{datetime.datetime.utcnow()}\nIPADDRESS:{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}\nUsername:{username}\n\n'''
    data_to_log = {"DATETIME":f"{datetime.datetime.utcnow().isoformat()+'+00:00'}","IPADDRESS":f"""{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}""","ENDPOINT":"/v2/indexer/information_technology"}
    f.write(str(data_to_log))
    f.write('\n')
    f.close()

    secret_code = request.json.get('passcode', None)
    idx = request.json.get('id', None)
    data = request.json.get('data', None)

    if secret_code == None:
        return jsonify({"errormsg":"Uh oh, careful with the fields in your request. It has to be exactly 'secret_code'."}),403

    if idx == None:
        return jsonify({"errormsg":"Uh oh, careful with the fields in your request. It has to be exactly 'id'."}),403

    if data == None:
        return jsonify({"errormsg":"Uh oh, careful with the fields in your request. It has to be exactly 'data'."}),403

    if idx.isalnum() and len(idx) == 32:  # For MD5 hashes
        pass
    else:
        return jsonify({"errormsg":"Hashes should be alphanumberic and length should be 32, i.e MD5."}),403

    if secret_code == '@lazlxEtIcS3A9rchIydzXiqg2u21fr0m':
        pass
    else:
        return jsonify({"errormsg":"Please enter the correct secret_code"}),403

    # Elasticsearch Object
    es = Elasticsearch(elastichost, timeout = 120 )
    
    try:                        
        es.get(index= index_name, id=idx)
        #print(res1)
        print(f"""{colors.grey} Document with id {idx} {colors.yellow}already exists{colors.grey}, skipping. request from IP {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} {colors.default}""")
        return jsonify({"info":"Data already indexed before. Try something else."}),200
    except Exception as e:
        # print(type(e), e)
        if '"found":false' in str(e):
            index_unpresence = index_hex_id_checker(idx)
            if index_unpresence == True:
                res = es.index(index= index_name, body=data, id = idx)
                print(f"""{colors.blue} Result -> {res['result']} with id {idx} from IP {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}{colors.default}""")
                return jsonify({"info":f"""Successfully indexed with id {idx}"""}),201
            else:
                print(f"""{colors.grey} Document with id {idx} {colors.yellow}already exists{colors.grey}, skipping. request from IP {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} {colors.default}""")
                return jsonify({"info":"Data already indexed before. Try something else."}),200
        else:
            return jsonify({"info":f"""Request not valid."""}),400

@app.route('/v2/indexer/blogs_vlogs', methods=['POST'])
def v2_indexer_blogs_vlogs():

    index_name = 'blogs_vlogs_alias'
    # check if a json request was made
    if not request.is_json:
        return jsonify({"errormsg": "Missing JSON in request"}), 403

    # Logging for /v2/indexer
    f = open("indexerlogs.txt", "a", encoding='UTF-8')
    #data_to_log = f'''DATETIME:{datetime.datetime.utcnow()}\nIPADDRESS:{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}\nUsername:{username}\n\n'''
    data_to_log = {"DATETIME":f"{datetime.datetime.utcnow().isoformat()+'+00:00'}","IPADDRESS":f"""{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}""","ENDPOINT":"/v2/indexer/information_technology"}
    f.write(str(data_to_log))
    f.write('\n')
    f.close()

    secret_code = request.json.get('passcode', None)
    idx = request.json.get('id', None)
    data = request.json.get('data', None)

    if secret_code == None:
        return jsonify({"errormsg":"Uh oh, careful with the fields in your request. It has to be exactly 'secret_code'."}),403

    if idx == None:
        return jsonify({"errormsg":"Uh oh, careful with the fields in your request. It has to be exactly 'id'."}),403

    if data == None:
        return jsonify({"errormsg":"Uh oh, careful with the fields in your request. It has to be exactly 'data'."}),403

    if idx.isalnum() and len(idx) == 32:  # For MD5 hashes
        pass
    else:
        return jsonify({"errormsg":"Hashes should be alphanumberic and length should be 32, i.e MD5."}),403

    if secret_code == '@lazlxEtIcS3A9rchIydzXiqg2u21fr0m':
        pass
    else:
        return jsonify({"errormsg":"Please enter the correct secret_code"}),403

    # Elasticsearch Object
    es = Elasticsearch(elastichost, timeout = 120 )
    
    try:                        
        es.get(index= index_name, id=idx)
        #print(res1)
        print(f"""{colors.grey} Document with id {idx} {colors.yellow}already exists{colors.grey}, skipping. request from IP {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} {colors.default}""")
        return jsonify({"info":"Data already indexed before. Try something else."}),200
    except Exception as e:
        # print(type(e), e)
        if '"found":false' in str(e):
            index_unpresence = index_hex_id_checker(idx)
            if index_unpresence == True:
                res = es.index(index= index_name, body=data, id = idx)
                print(f"""{colors.blue} Result -> {res['result']} with id {idx} from IP {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}{colors.default}""")
                return jsonify({"info":f"""Successfully indexed with id {idx}"""}),201
            else:
                print(f"""{colors.grey} Document with id {idx} {colors.yellow}already exists{colors.grey}, skipping. request from IP {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} {colors.default}""")
                return jsonify({"info":"Data already indexed before. Try something else."}),200
        else:
            return jsonify({"info":f"""Request not valid."""}),400

@app.route('/v2/indexer/science_index', methods=['POST'])
def v2_indexer_science_index():

    index_name = 'science_index_alias'
    # check if a json request was made
    if not request.is_json:
        return jsonify({"errormsg": "Missing JSON in request"}), 403

    # Logging for /v2/indexer
    f = open("indexerlogs.txt", "a", encoding='UTF-8')
    #data_to_log = f'''DATETIME:{datetime.datetime.utcnow()}\nIPADDRESS:{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}\nUsername:{username}\n\n'''
    data_to_log = {"DATETIME":f"{datetime.datetime.utcnow().isoformat()+'+00:00'}","IPADDRESS":f"""{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}""","ENDPOINT":"/v2/indexer/science_index "}
    f.write(str(data_to_log))
    f.write('\n')
    f.close()

    secret_code = request.json.get('passcode', None)
    idx = request.json.get('id', None)
    data = request.json.get('data', None)

    if secret_code == None:
        return jsonify({"errormsg":"Uh oh, careful with the fields in your request. It has to be exactly 'secret_code'."}),403

    if idx == None:
        return jsonify({"errormsg":"Uh oh, careful with the fields in your request. It has to be exactly 'id'."}),403

    if data == None:
        return jsonify({"errormsg":"Uh oh, careful with the fields in your request. It has to be exactly 'data'."}),403

    if idx.isalnum() and len(idx) == 32:  # For MD5 hashes
        pass
    else:
        return jsonify({"errormsg":"Hashes should be alphanumberic and length should be 32, i.e MD5."}),403

    if secret_code == '@lazlxEtIcS3A9rchIydzXiqg2u21fr0m':
        pass
    else:
        return jsonify({"errormsg":"Please enter the correct secret_code"}),403

    # Elasticsearch Object
    es = Elasticsearch(elastichost, timeout = 120 )
    
    try:                        
        es.get(index= index_name, id=idx)
        #print(res1)
        print(f"""{colors.grey} Document with id {idx} {colors.yellow}already exists{colors.grey}, skipping. request from IP {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} {colors.default}""")
        return jsonify({"info":"Data already indexed before. Try something else."}),200
    except Exception as e:
        # print(type(e), e)
        if '"found":false' in str(e):
            index_unpresence = index_hex_id_checker(idx)
            if index_unpresence == True:
                res = es.index(index= index_name, body=data, id = idx)
                print(f"""{colors.blue} Result -> {res['result']} with id {idx} from IP {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}{colors.default}""")
                return jsonify({"info":f"""Successfully indexed with id {idx}"""}),201
            else:
                print(f"""{colors.grey} Document with id {idx} {colors.yellow}already exists{colors.grey}, skipping. request from IP {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} {colors.default}""")
                return jsonify({"info":"Data already indexed before. Try something else."}),200
        else:
            return jsonify({"info":f"""Request not valid."""}),400

@app.route('/v2/indexer/education_index', methods=['POST'])
@index_decorator
def v2_indexer_education_index(idx, data):

    index_name = 'education_alias'
    # check if a json request was made
    try:
        index_unpresence = index_hex_id_checker(idx)
        if index_unpresence == True:
            
            es = Elasticsearch(elastichost, timeout = 120 )
            res = es.index(index=index_name, body=data, id=idx)
            print(
                f"""{colors.blue} Result -> {res['result']} with id {idx} from IP {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}{colors.default}""")
            return jsonify({"info": f"""Successfully indexed with id {idx}"""}), 201
        else:
            print(f"""{colors.grey} Document with id {idx} {colors.yellow}already exists{colors.grey}, skipping. request from IP {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} {colors.default}""")
            return jsonify({"info": "Data already indexed before. Try something else."}), 200
    except:
            return jsonify({"info": f"""Request not valid."""}), 400

@app.route('/v2/indexer/notification_scraper', methods=['POST'])
def v2_indexer_notification_scraper():

    index_name = 'notification_scraper'
    # check if a json request was made
    if not request.is_json:
        return jsonify({"errormsg": "Missing JSON in request"}), 403

    # Logging for /v2/indexer
    f = open("indexerlogs.txt", "a", encoding='UTF-8')
    #data_to_log = f'''DATETIME:{datetime.datetime.utcnow()}\nIPADDRESS:{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}\nUsername:{username}\n\n'''
    data_to_log = {"DATETIME":f"{datetime.datetime.utcnow().isoformat()+'+00:00'}","IPADDRESS":f"""{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}""","ENDPOINT":"/v2/indexer/information_technology"}
    f.write(str(data_to_log))
    f.write('\n')
    f.close()

    secret_code = request.json.get('passcode', None)
    idx = request.json.get('id', None)
    data = request.json.get('data', None)

    if secret_code == None:
        return jsonify({"errormsg":"Uh oh, careful with the fields in your request. It has to be exactly 'secret_code'."}),403

    if idx == None:
        return jsonify({"errormsg":"Uh oh, careful with the fields in your request. It has to be exactly 'id'."}),403

    if data == None:
        return jsonify({"errormsg":"Uh oh, careful with the fields in your request. It has to be exactly 'data'."}),403

    if idx.isalnum() and len(idx) == 32:  # For MD5 hashes
        pass
    else:
        return jsonify({"errormsg":"Hashes should be alphanumberic and length should be 32, i.e MD5."}),403

    if secret_code == '@lazlxEtIcS3A9rchIydzXiqg2u21fr0m':
        pass
    else:
        return jsonify({"errormsg":"Please enter the correct secret_code"}),403

    # Elasticsearch Object
    es = Elasticsearch(elastichost, timeout = 120 )
    
    try:                        
        es.get(index= index_name, id=idx)
        #print(res1)
        print(f"""{colors.grey} Document with id {idx} {colors.yellow}already exists{colors.grey}, skipping. request from IP {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} {colors.default}""")
        return jsonify({"info":"Data already indexed before. Try something else."}),200
    except Exception as e:
        # print(type(e), e)
        if '"found":false' in str(e):
                res = es.index(index= index_name, body=data, id = idx)
                print(f"""{colors.blue} Result -> {res['result']} with id {idx} from IP {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}{colors.default}""")
                return jsonify({"info":f"""Successfully indexed with id {idx}"""}),201
        else:
            return jsonify({"info":f"""Request not valid."""}),400

@app.route('/v2/indexer/notification_posts', methods=['POST'])
@index_decorator
def notification_posts(idx, data):

    index_name = request.json.get('index_name', None)
    if index_name == None:
        return jsonify({"info": f"""please provide valid parameters"""}),400
    # check if a json request was made
    try:
        index_unpresence = index_hex_id_checker(idx)
        if index_unpresence == True:
            
            es = Elasticsearch(elastichost, timeout = 120 )
            res = es.index(index=index_name, body=data, id=idx)
            print(
                f"""{colors.blue} Result -> {res['result']} with id {idx} from IP {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}{colors.default}""")
            return jsonify({"info": f"""Successfully indexed with id {idx}"""}), 201
        else:
            print(f"""{colors.grey} Document with id {idx} {colors.yellow}already exists{colors.grey}, skipping. request from IP {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} {colors.default}""")
            return jsonify({"info": "Data already indexed before. Try something else."}), 200
    except:
            return jsonify({"info": f"""Request not valid."""}), 400
##############################################################################

@app.route('/v2/data_count', methods=["GET"])
@jwt_required
def get_scrapper_data():

    index_name = "telegram2_alias"

    # Access the identity of the current user with get_jwt_identity
    jwt_all = get_jwt_identity()
    current_user = jwt_all[0]

    # Function to block usage of old tokens after change of password.
    if check_tokens(jwt_all) != 'successful':
        return check_tokens(jwt_all)[0]

    print(f"""{colors.green} User {current_user} has successfully logged. Accessing /v2/posts API from IP: {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} {colors.default}""")

    if current_user == 'administrator':
        
        # check if the cache exists? if exists, return the value else proceed further
        r = redis.Redis(host='localhost', port= 6379, db=0)

        try:           
            if r.get("scraper_statistics").decode() != "None" :
                data_return = ast.literal_eval(r.get("scraper_statistics").decode())
                if data_return == None:
                    raise Exception
                return jsonify({"new_data": data_return}), 200 
                print(f"{colors.green} -------------------------------------------------------------  Returned cache results.{colors.default}")
        except Exception as e:
            pass
        
        # es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
        es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
        total_group_res = es.count(index= all_index_name,
                    body={
                        "query": {
                            "match": {
                                "is_group": 'True'
                            }
                        }
                    })
        
        total_channel_res = es.count(index=all_index_name,
                    body={
                        "query": {
                            "match": {
                                "is_group": 'False'
                            }
                        }
                    })

        total_group_file_count = file_count_func(["telegram2_alias","financials","extremepolitical2_alias","religion_spirituality_alias","pharma_drugs_alias","criminal_activities_alias","information_technology","cyber_security_alias","adult_content_alias","blogs_vlogs_alias"], 'True')
        total_group_forwarded_count = forwarded_data_count(["telegram2_alias","financials","extremepolitical2_alias","religion_spirituality_alias","pharma_drugs_alias","criminal_activities_alias","information_technology","cyber_security_alias","adult_content_alias","blogs_vlogs_alias"], 'True')
        total_group_unique_channel = unique_channel_count(all_index_name, 'True')

        total_file_count = file_count_func(["telegram2_alias","financials","extremepolitical2_alias","religion_spirituality_alias","pharma_drugs_alias","criminal_activities_alias","information_technology","cyber_security_alias","adult_content_alias","blogs_vlogs_alias"])
        total_forwarded_count = forwarded_data_count(["telegram2_alias","financials","extremepolitical2_alias","religion_spirituality_alias","pharma_drugs_alias","criminal_activities_alias","information_technology","cyber_security_alias","adult_content_alias","blogs_vlogs_alias"])
        total_unique_channel = unique_channel_count(all_index_name)

        hacking_group_res = es.count(index= index_name,
                    body={
                        "query": {
                            "match": {
                                "is_group": 'True'
                            }
                        }
                    })
        
        hacking_channel_res = es.count(index= index_name,
                    body={
                        "query": {
                            "match": {
                                "is_group": 'False'
                            }
                        }
                    })
        hacking_group_file_count = file_count_func("telegram2_alias", 'True')
        hacking_group_forwarded_count = forwarded_data_count("telegram2_alias", 'True')
        hacking_group_unique_channel = unique_channel_count("telegram2_alias", 'True')

        hacking_file_count = file_count_func("telegram2_alias")
        hacking_forwarded_count = forwarded_data_count("telegram2_alias")
        hacking_unique_channel = unique_channel_count("telegram2_alias")

        poltical_group_res = es.count(index= "extremepolitical2_alias",
                    body={
                        "query": {
                            "match": {
                                "is_group": 'True'
                            }
                        }
                    })
        
        political_channel_res = es.count(index= "extremepolitical2_alias",
                    body={
                        "query": {
                            "match": {
                                "is_group": 'False'
                            }
                        }
                    })
        political_group_file_count = file_count_func("extremepolitical2_alias", 'True')
        political_group_forwarded_count = forwarded_data_count("extremepolitical2_alias", 'True')
        political_group_unique_channel = unique_channel_count("extremepolitical2_alias", 'True')

        political_file_count = file_count_func("extremepolitical2_alias")
        political_forwarded_count = forwarded_data_count("extremepolitical2_alias")
        political_unique_channel = unique_channel_count("extremepolitical2_alias")

        finacial_group_res = es.count(index= "financials",
                    body={
                        "query": {
                            "match": {
                                "is_group": 'True'
                            }
                        }
                    })
        
        financial_channel_res = es.count(index= "financials",
                    body={
                        "query": {
                            "match": {
                                "is_group": 'False'
                            }
                        }
                    })
        financial_group_file_count = file_count_func("financials_alias", 'True')
        financial_group_forwarded_count = forwarded_data_count("financials_alias", 'True')
        financial_group_unique_channel = unique_channel_count("financials_alias", 'True')

        financial_file_count = file_count_func("financials_alias")
        financial_forwarded_count = forwarded_data_count("financials_alias")
        financial_unique_channel = unique_channel_count("financials_alias")

        spiritual_group_res = es.count(index= "religion_spirituality_alias",
                    body={
                        "query": {
                            "match": {
                                "is_group": 'True'
                            }
                        }
                    })
        
        spiritual_channel_res = es.count(index= "religion_spirituality_alias",
                    body={
                        "query": {
                            "match": {
                                "is_group": 'False'
                            }
                        }
                    })
        spiritual_channel_group_file_count = file_count_func("religion_spirituality_alias", 'True')
        spiritual_channel_group_forwarded_count = forwarded_data_count("religion_spirituality_alias", 'True')
        spiritual_channel_group_unique_channel = unique_channel_count("religion_spirituality_alias", 'True')

        spiritual_channel_file_count = file_count_func("religion_spirituality_alias")
        spiritual_channel_forwarded_count = forwarded_data_count("religion_spirituality_alias")
        spiritual_channel_unique_channel = unique_channel_count("religion_spirituality_alias")

        pharma_group_res = es.count(index= "pharma_drugs_alias",
                    body={
                        "query": {
                            "match": {
                                "is_group": 'True'
                            }
                        }
                    })
        
        pharma_channel_res = es.count(index= "pharma_drugs_alias",
                    body={
                        "query": {
                            "match": {
                                "is_group": 'False'
                            }
                        }
                    })

        pharma_channel_group_file_count = file_count_func("pharma_drugs_alias", 'True')
        pharma_channel_group_forwarded_count = forwarded_data_count("pharma_drugs_alias", 'True')
        pharma_channel_group_unique_channel = unique_channel_count("pharma_drugs_alias", 'True')

        pharma_channel_file_count = file_count_func("pharma_drugs_alias")
        pharma_channel_forwarded_count = forwarded_data_count("pharma_drugs_alias")
        pharma_channel_unique_channel = unique_channel_count("pharma_drugs_alias")

        criminal_group_res = es.count(index= "criminal_activities_alias",
            body={
                "query": {
                    "match": {
                        "is_group": 'True'
                    }
                }
            })

        criminal_channel_res = es.count(index= "criminal_activities_alias",
                    body={
                        "query": {
                            "match": {
                                "is_group": 'False'
                            }
                        }
                    })
        criminal_channel_group_file_count = file_count_func("criminal_activities_alias", 'True')
        criminal_channel_group_forwarded_count = forwarded_data_count("criminal_activities_alias", 'True')
        criminal_channel_group_unique_channel = unique_channel_count("criminal_activities_alias", 'True')

        criminal_channel_file_count = file_count_func("criminal_activities_alias" )
        criminal_channel_forwarded_count = forwarded_data_count("criminal_activities_alias" )
        criminal_channel_unique_channel = unique_channel_count("criminal_activities_alias")

        information_technology_group_res = es.count(index= "information_technology",
                    body={
                        "query": {
                            "match": {
                                "is_group": 'True'
                            }
                        }
                    })
        
        
        information_technology_channel_res = es.count(index= "information_technology",
                    body={
                        "query": {
                            "match": {
                                "is_group": 'False'
                            }
                        }
                    })
        information_technology_group_file_count = file_count_func("information_technology", 'True')
        information_technology_group_forwarded_count = forwarded_data_count("information_technology", 'True')
        information_technology_group_unique_channel = unique_channel_count("information_technology", 'True')

        information_technology_file_count = file_count_func("information_technology")
        information_technology_forwarded_count = forwarded_data_count("information_technology")
        information_technology_unique_channel = unique_channel_count("information_technology")


        cyber_security_group_res = es.count(index= "cyber_security_alias",
                    body={
                        "query": {
                            "match": {
                                "is_group": 'True'
                            }
                        }
                    })
        
        
        cyber_security_channel_res = es.count(index= "cyber_security_alias",
                    body={
                        "query": {
                            "match": {
                                "is_group": 'False'
                            }
                        }
                    })
        cyber_security_group_file_count = file_count_func("cyber_security_alias", 'True')
        cyber_security_group_forwarded_count = forwarded_data_count("cyber_security_alias", 'True')
        cyber_security_group_unique_channel = unique_channel_count("cyber_security_alias", 'True')

        cyber_security_file_count = file_count_func("cyber_security_alias")
        cyber_security_forwarded_count = forwarded_data_count("cyber_security_alias")
        cyber_security_unique_channel = unique_channel_count("cyber_security_alias")

        adult_content_group_res = es.count(index= "adult_content_alias",
                    body={
                        "query": {
                            "match": {
                                "is_group": 'True'
                            }
                        }
                    })
        
        
        adult_content_channel_res = es.count(index= "adult_content_alias",
                    body={
                        "query": {
                            "match": {
                                "is_group": 'False'
                            }
                        }
                    })
        adult_content_group_file_count = file_count_func("adult_content_alias", 'True')
        adult_content_group_forwarded_count = forwarded_data_count("adult_content_alias", 'True')
        adult_content_group_unique_channel = unique_channel_count("adult_content_alias", 'True')

        adult_content_file_count = file_count_func("adult_content_alias")
        adult_content_forwarded_count = forwarded_data_count("adult_content_alias")
        adult_content_unique_channel = unique_channel_count("adult_content_alias")


        new_send_res = {
        "Hacking":{
            "No.of total channel posts avaialable": hacking_channel_res['count'],
            "No.of total channel file posts avaialable": hacking_file_count,
            "No.of total channel forwarded posts avaialable":hacking_forwarded_count,
            "No.of total unique channel ": hacking_unique_channel,
            "No.of total group posts avaialable": hacking_group_res['count'],
            "No.of total group file posts avaialable": hacking_group_file_count,
            "No.of total group forwarded posts avaialable": hacking_group_forwarded_count,
            "No.of total unique group ": hacking_group_unique_channel,
        },
        "Political":{
            "No.of total channel posts avaialable": political_channel_res['count'],
            "No.of total channel file posts avaialable": political_file_count,
            "No.of total channel forwarded posts avaialable":political_forwarded_count,
            "No.of total unique channel ": political_unique_channel,
            "No.of total group posts avaialable": poltical_group_res['count'],
            "No.of total group file posts avaialable": political_group_file_count,
            "No.of total group forwarded posts avaialable": political_group_forwarded_count,
            "No.of total unique group ": political_group_unique_channel,
        },
        "Financials":{
            "No.of total channel posts avaialable": financial_channel_res['count'],
            "No.of total channel file posts avaialable": financial_file_count,
            "No.of total channel forwarded posts avaialable":financial_forwarded_count,
            "No.of total unique channel ": financial_unique_channel,
            "No.of total group posts avaialable": finacial_group_res['count'],
            "No.of total group file posts avaialable": financial_group_file_count,
            "No.of total group forwarded posts avaialable": financial_group_forwarded_count,
            "No.of total unique group ": financial_group_unique_channel,
        },
        "Spiritual and Religious":{
            "No.of total channel posts avaialable": spiritual_channel_res['count'],
            "No.of total channel file posts avaialable": spiritual_channel_file_count,
            "No.of total channel forwarded posts avaialable":spiritual_channel_forwarded_count,
            "No.of total unique channel ": spiritual_channel_unique_channel,
            "No.of total group posts avaialable": spiritual_group_res['count'],
            "No.of total group file posts avaialable": spiritual_channel_group_file_count,
            "No.of total group forwarded posts avaialable": spiritual_channel_group_forwarded_count,
            "No.of total unique group ": spiritual_channel_group_unique_channel,
        },
        "Criminal Activities":{
            "No.of total channel posts avaialable": criminal_channel_res['count'],
            "No.of total channel file posts avaialable": criminal_channel_file_count,
            "No.of total channel forwarded posts avaialable":criminal_channel_forwarded_count,
            "No.of total unique channel ": criminal_channel_unique_channel,
            "No.of total group posts avaialable": criminal_group_res['count'],
            "No.of total group file posts avaialable": criminal_channel_group_file_count,
            "No.of total group forwarded posts avaialable": criminal_channel_group_forwarded_count,
            "No.of total unique group ": criminal_channel_group_unique_channel,
        },
        "Pharma and Drugs":{
            "No.of total channel posts avaialable": pharma_channel_res['count'],
            "No.of total channel file posts avaialable": pharma_channel_file_count,
            "No.of total channel forwarded posts avaialable":pharma_channel_forwarded_count,
            "No.of total unique channel ": pharma_channel_unique_channel,
            "No.of total group posts avaialable": pharma_group_res['count'],
            "No.of total group file posts avaialable": pharma_channel_group_file_count,
            "No.of total group forwarded posts avaialable": pharma_channel_group_forwarded_count,
            "No.of total unique group ": pharma_channel_group_unique_channel,
        },
        "Information Technology":{
            "No.of total channel posts avaialable": information_technology_channel_res['count'],
            "No.of total channel file posts avaialable": information_technology_file_count,
            "No.of total channel forwarded posts avaialable":information_technology_forwarded_count,
            "No.of total unique channel ": information_technology_unique_channel,
            "No.of total group posts avaialable": information_technology_group_res['count'],
            "No.of total group file posts avaialable": information_technology_group_file_count,
            "No.of total group forwarded posts avaialable": information_technology_group_forwarded_count,
            "No.of total unique group ": information_technology_group_unique_channel,
        },
        "Cyber Security":{
            "No.of total channel posts avaialable": cyber_security_channel_res['count'],
            "No.of total channel file posts avaialable": cyber_security_file_count,
            "No.of total channel forwarded posts avaialable":cyber_security_forwarded_count,
            "No.of total unique channel ": cyber_security_unique_channel,
            "No.of total group posts avaialable": cyber_security_group_res['count'],
            "No.of total group file posts avaialable": cyber_security_group_file_count,
            "No.of total group forwarded posts avaialable": cyber_security_group_forwarded_count,
            "No.of total unique group ": cyber_security_group_unique_channel,
        },"Adult Content":{
            "No.of total channel posts avaialable": adult_content_channel_res['count'],
            "No.of total channel file posts avaialable": adult_content_file_count,
            "No.of total channel forwarded posts avaialable":adult_content_forwarded_count,
            "No.of total unique channel ": adult_content_unique_channel,
            "No.of total group posts avaialable": adult_content_group_res['count'],
            "No.of total group file posts avaialable": adult_content_group_file_count,
            "No.of total group forwarded posts avaialable": adult_content_group_forwarded_count,
            "No.of total unique group ": adult_content_group_unique_channel,
        },
        "Total Data":{
            
            "No.of total channel posts avaialable": total_channel_res['count'],
            "No.of total channel file posts avaialable": total_file_count,
            "No.of total channel forwarded posts avaialable":total_forwarded_count,
            "No.of total unique channel ": total_unique_channel,
            "No.of total group posts avaialable": total_group_res['count'],
            "No.of total group file posts avaialable": total_group_file_count,
            "No.of total group forwarded posts avaialable": total_group_forwarded_count,
            "No.of total unique group ": total_group_unique_channel,
        
        }
    }
        
        send_res = {"total_channels": total_channel_res['count'], 'groups': total_group_res['count'],'hacking_channel':hacking_channel_res['count'],'hacking_group':hacking_group_res['count'],'political_channel':political_channel_res['count'],'political_group':poltical_group_res['count'],'finacial_channel':financial_channel_res['count'],'financial_group':finacial_group_res['count'],'spiritual_channel':spiritual_channel_res['count'],'spiritual_group':spiritual_group_res['count'],'pharma_channel':pharma_channel_res['count'],'pharma_group':pharma_group_res['count']}
        # response = res['hits']['hits']

        try: 
            r.set("scraper_statistics",str(new_send_res).encode(), ex = 3600 )
            print(f"{colors.green} ------------------------------------------------------------- Cache set for scraper_statistics. {colors.default}")
        except Exception as e:
            pass
        
        return jsonify({'data': send_res,"new_data":new_send_res})
    else:
        return jsonify({"errormsg": "Authorized users only."}), 403


'''
Insert info of scrapper
'''

@app.route('/insert_scrapper_info', methods=["POST"])
def scraper_inf_data():
    try:
        scrapper_id = request.json['scrapper_id']
        total_channel = request.json['total_channel']
        total_scrapped = request.json['total_scrapped']
        current_channel = request.json['current_channel']
        cpu_usage = request.json['cpu_usage']
        ram_usage = request.json['ram_usage']
        finished_scrapper_time = request.json['finished_scrapper_time']
        last_updated_time = request.json['last_updated_time']

        new_arr = {'scrapper_id': scrapper_id, 'total_channel': total_channel, 'total_scrapped': total_scrapped, 'current_channel': current_channel,
                   'cpu_usage': cpu_usage, 'ram_usage': ram_usage, 'finished_scrapper_time': finished_scrapper_time, 'last_updated_time': last_updated_time}
        es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
        res = es.index(index='scrapper_index',
                       id=scrapper_id, body=new_arr)
        return jsonify({'data': res})
    except Exception as e:
        return jsonify({'error': e, 'msg': 'error in updating the infos'})

#--------------------------------------------------------------------------------------------------------------------------------------------#
'''
Get the details of all the channel scrappers 
'''
@app.route('/scrapper_data', methods=["GET"])
@jwt_required
def scrapper_data():
    # Access the identity of the current user with get_jwt_identity
    jwt_all = get_jwt_identity()
    current_user = jwt_all[0]
    print(f"""{colors.green} User {current_user} has successfully logged. Accessing /v2/posts API from IP: {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} {colors.default}""")

    # Function to block usage of old tokens after change of password.
    if check_tokens(jwt_all) != 'successful':
        return check_tokens(jwt_all)[0]

    if current_user == 'administrator':
        es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
        res = es.search(index='scrapper_index',
                        body={
                            "query": {
                                "match_all": {}
                            }
                        })
        return jsonify({'data': res['hits']['hits']})
    else:
        return jsonify({"errormsg": "Authorized users only."}), 403

# route for frontend rendering
@app.route("/admin/scraper", methods=['GET','POST'])
def scraper_display():
    return flask.render_template('index.html')


#--------------------------------------------------------------------------------------------------------------------------------------------#
# todo: remove it later
# route to extract channel data.
@app.route('/extract_channel_data', methods=["POST"])
def extract_channel_data():
  
    try:
        index_name = ["telegram2_alias","financials_alias","extremepolitical2_alias","religion_spirituality_alias","pharma_drugs_alias","criminal_activities_alias","information_technology","cyber_security_alias"]
        search_data = request.json['search']
        es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
        print(search_data)
        res = es.search(index= index_name, size=10000,
                        body={
                            "query": {
                                "match_phrase": {
                                    "conv_name": search_data,
                                },

                            }
                        })
        response = res['hits']['hits']

        return jsonify({'data': response})
    except:
        return jsonify({'data': 'Proper fields are not provided'})



#--------------------------------------------------------------------------------------------------------------------------------------------#
'''
Get the details of all the channel scrappers
'''

@app.route('/channel_check', methods=["POST"])
def channel_check():
    
    qtext = request.json.get('search', None)
    type = request.json.get('search_type', None)
    

    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
    
    search_type = 'link.keyword'
    try:
        if type == 'id':
            search_type = "to_id.keyword"
        
        res = es.search(index=["telegram2_alias","financials_alias","extremepolitical2_alias","religion_spirituality_alias","pharma_drugs_alias","criminal_activities_alias","information_technology","cyber_security_alias"], size=1,
            body={
            "query": {
            "term": {
            search_type: {
            "value": qtext,
            "boost": 1.0
            }
            }
            }
            })

        return jsonify({'data': res['hits']['hits']})
    except Exception as e:
        return jsonify({'error':'contact dev.'})


#--------------------------------------------------------------------------------------------------------------------------------------------#
"""
Fetch forwareded channels from a index
"""
@app.route('/random_forwaded_scrapper_data', methods=['GET'])
def random_forwaded_scrapper_data():
    index_name = "telegram2_alias"
    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
    viewed = es.search(index= index_name, size=100, body={
        'query': {
            'bool': {
                'must_not': [
                    {'match': {'forwardedfromchanid': 'None'}}
                ]

            }
        },
        "sort": {
            "_script": {
                "script": "Math.random()",
                "type": "number",

                "order": "asc"
            }
        }
    })
  
    response = viewed['hits']['hits']
    return jsonify(response)


#--------------------------------------------------------------------------------------------------------------------------------------------#
'''
stats for views per post of a channel
'''
@app.route('/stats', methods=['POST'])
@jwt_required
@stats_decorator
def stats(default_query):
    try:
        #checking token validation
        jwt_all = get_jwt_identity()

        if check_tokens(jwt_all) != 'successful':
            return check_tokens(jwt_all)[0]

        qtext = request.json.get('qtext', None)
        es = Elasticsearch(elastichost, timeout=300, sniff_on_connection_fail=True,retry_on_timeout=True, max_retries=2,maxsize=5)
        total_post = es.count(index=all_index_name, body={
             'query': default_query
        })

        main_stats = es.search(index=all_index_name, size=1, body={
             'query': default_query
        })
        
        print('Stat requested..')

        tot_post_view = 0
        try:
            tot_post_view = es.search(index=all_index_name, size=0, body={
                "query": default_query,

                "aggs": {
                    "total_views": {
                        "sum": {

                            "script": {
                                "lang": "painless",
                                "source": """
                            if (params._source.views !== null ) {
                            if (params._source.views !== 'None' ){
                                try {
                                
                                    int new_num = 1;
                                    if(params._source.views instanceof String){
                                    
                                        String str = params._source.views.replace('.','').replace('K','000');
                                        new_num = Integer.parseInt(str);
                                        return new_num
                                    }
                                    else{
                                    return params._source.views
                                    }
                                }
                                catch (NumberFormatException e) { return 0}
                                
                                }
                                else{
                                    return 0
                                }
                                    
                                    
                                    
                                    
                                    } 
                                else {return 0 }
                            """

                            }


                        }
                    }
                }
            })
        except:
            pass
        

        total_views = (tot_post_view['aggregations']['total_views']['value'])

        main_response = main_stats['hits']['hits'][0]['_source']
        basic_aud_info = channel_basic_stats(main_response)
        channel_average_view = average_view(total_views, total_post['count'])

        cust_eng = 0
        # print(main_response)
        # response = forarded['count']
        new_obj = {'audience_info': basic_aud_info,
                   'average_view': channel_average_view, 'total_views': total_views, 'customer_engagement': cust_eng, 'total_post': total_post}
        return jsonify(new_obj)
    except Exception as e:
        return jsonify({'errormsg':f'sorry could not retrieve the data'}),403


#--------------------------------------------------------------------------------------------------------------------------------------------#
'''
data forforwaded post of a channel
'''

@app.route('/forwaded_post', methods=['POST'])
@jwt_required
@stats_decorator
def forwaded_post(default_query):
    
    #checking token validation
    jwt_all = get_jwt_identity()

    if check_tokens(jwt_all) != 'successful':
        return check_tokens(jwt_all)[0]

    qtext = request.json.get('qtext', None)
    qtext_filter = channel_name_converter(qtext)
    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
    print(default_query)
    try:
        
        forwarded = es.search(index=all_index_name, size=10, body={

            'query': {
                'bool': {
                    'must': [
                        default_query,

                    ],
                    'must_not':[
                        {
                                "query_string": {
                                        "query":'None',
                                        "fields":['forwardedfromchanid','forwardedromchanid']
                                        }
                            }
                    ]

                }
            },
            'sort': [{'views.keyword': {"order": "desc"}}]

        })
        total_forwaded = es.count(index=all_index_name, body={

            'query': {
                'bool': {
                    'must': [
                        default_query,

                    ],
                    'must_not': [
                        {
                                "query_string": {
                                        "query":'None',
                                        "fields":['forwardedfromchanid','forwardedromchanid']
                                        }
                            }
                    ]

                }
            },


        })
        total_post = es.count(index=all_index_name, body={

            'query': {
                'bool': {
                    'must': [
                        default_query,

                    ],


                }
            },


        })
        new_obj = {'tot_forwarded_post': 0,
                    'tot_forwarded_post_percent': 0, 'forwaded_post': []}
  
        if len(forwarded['hits']['hits']) > 0:
            tot_forwarded_post = total_forwaded['count']
            tot_forwarded_post_percent=0
            if tot_forwarded_post != 0:
                tot_forwarded_post_percent = round((total_forwaded['count']/total_post['count'])*100, 2)
            response = forwarded['hits']['hits']
            return_list = []

            for hit in forwarded['hits']['hits']:
                default_key = 'forwardedfromchanid'
                obj_keys = hit['_source'].keys()
                if 'forwardedromchanid' in obj_keys:
                    default_key = 'forwardedromchanid'

                forwarded_channel = channel_name_extractor_from_id(hit["_source"][default_key])
                hit["_source"][default_key] = forwarded_channel
                return_list.append(hit["_source"])

            new_obj = {'tot_forwarded_post': tot_forwarded_post,
                    'tot_forwarded_post_percent': tot_forwarded_post_percent, 'forwaded_post': return_list}
        return jsonify(new_obj)
    except Exception as e:
        print(e)
        new_obj = {'tot_forwarded_post': 0,
                    'tot_forwarded_post_percent': 0, 'forwaded_post': []}
        return jsonify(new_obj)

#--------------------------------------------------------------------------------------------------------------------------------------------#
'''
stats forforwaded post of a channel
'''
@app.route('/forwaded_post_channel', methods=['POST'])
@jwt_required
@stats_decorator
def forwaded_post_channel(default_query):
    try:
        #checking token validation
        jwt_all = get_jwt_identity()

        if check_tokens(jwt_all) != 'successful':
            return check_tokens(jwt_all)[0]

        es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
        print('activated')
        print(default_query)
        forwarded = es.search(index=all_index_name, size=1000, body={

            'query': {
                'bool': {
                    'must': [
                        default_query,

                    ],
                    'must_not': [
                        {
                                "query_string": {
                                        "query":'None',
                                        "fields":['forwardedfromchanid','forwardedromchanid']
                                        }
                            }
                    ]

                }
            },
            'sort': [{'views.keyword': {"order": "desc"}}]

        })
        channels = forwaded_channel_count(forwarded['hits']['hits'])
        print(channels)

        return jsonify(channels)
    except Exception as e:
        print(e)
        return jsonify({'errormsg':'sorry could not rerieve the data'}),403

#--------------------------------------------------------------------------------------------------------------------------------------------#
'''
data for most viwed posts
'''
@app.route('/most_viewed', methods=['POST'])
def most_viewed():
    qtext = request.json.get('qtext', None)
    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
    viewed = es.search(index=all_index_name, size=10, body={

        'query': {
            'bool': {
                'must': [
                    {'match_phrase': {
                        'conv_name': qtext
                    },
                    },

                ],
            }
        },
        'sort': [{'views.keyword': {"order": "desc"}}]

    })
    response = viewed['hits']['hits']
    return jsonify(response)


#--------------------------------------------------------------------------------------------------------------------------------------------#

'''
data for date on calendar basis
'''

@app.route('/group_date', methods=['POST'])
@jwt_required
@stats_decorator
def group_date(default_queryz):
    try:
        #checking token validation
        jwt_all = get_jwt_identity()

        if check_tokens(jwt_all) != 'successful':
            return check_tokens(jwt_all)[0]

        qtext = request.json.get('qtext', None)
        
        extra_filter = request.json.get('extra_filter', None)
        sort_filter = request.json.get('sort_filter', None)
        default_sort = '_count'
        if sort_filter == 'date':
            default_sort = '_key'
        default_query = {'match_phrase': {
                            'conv_name': qtext
                        }
        }
        if extra_filter != 'user_filter':
            default_query =default_queryz
        
        else:
            default_query = {'match_phrase': {
                            'id': qtext
                        }
            }

        dt_filter = request.json.get('dt_filter', None)
        apply_filter = '1d'
        if dt_filter == 'week':
            apply_filter = '1w'
        elif dt_filter == 'month':
            apply_filter = '1M'
        elif dt_filter == 'year':
            apply_filter = '1y'
        else:
            apply_filter = '1d'
        es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
        viewed = es.search(index=["telegram2_alias","financials_alias","extremepolitical2_alias","religion_spirituality_alias","pharma_drugs_alias","criminal_activities_alias","information_technology","cyber_security_alias"], size=0, body={

            'query': {
                'bool': {
                    'must': [
                        default_query

                    ],
                }
            },
            "aggs": {
                "group_by_month": {
                    "date_histogram": {
                        "field": 'date',
                        "calendar_interval": apply_filter,
                        "format": "yyyy-MM-dd",
                        "order": {
                            default_sort: "desc"
                        }
                    }
                }

            }

        })
        # print(viewed['aggregations']['group_by_month']['buckets'])
        response = viewed['aggregations']['group_by_month']['buckets']
        return jsonify(response)
    except Exception as e:
        return jsonify({'errormsg':f'sorry could not rerieve the data'}),403


#--------------------------------------------------------------------------------------------------------------------------------------------#
'''
stats for date on calendar basis
'''
@app.route('/group_date_stats', methods=['POST'])
@jwt_required
@stats_decorator
def group_date_stats(default_queryz):
    try:
        #checking token validation
        jwt_all = get_jwt_identity()

        if check_tokens(jwt_all) != 'successful':
            return check_tokens(jwt_all)[0]

        qtext = request.json.get('qtext', None)
        es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
        extra_filter = request.json.get('extra_filter', None)
        default_query = {'match_phrase': {
                                'conv_name': qtext
                            }
            }
        if extra_filter != 'user_filter':
        
                default_query = default_queryz
        else:
                default_query = {'match_phrase': {
                                'id': qtext
                            }
                }

        day = es.search(index=all_index_name, size=0, body={

            'query': {
                'bool': {
                    'must': [
                        default_query
                    ],
                }
            },
            "aggs": {
                "group_by_month": {
                    "date_histogram": {
                        "field": 'date',
                        "calendar_interval": '1d',
                        "format": "yyyy-MM-dd",
                        "order": {
                            "_count": "desc"
                        }
                    }
                }

            },
            # 'sort': [{'views.keyword': {"order": "desc"}}]

        })
        week = es.search(index=all_index_name, size=0, body={

            'query': {
                'bool': {
                    'must': [
                        default_query

                    ],
                }
            },
            "aggs": {
                "group_by_month": {
                    "date_histogram": {
                        "field": 'date',
                        "calendar_interval": '1w',
                        "format": "yyyy-MM-dd",
                        "order": {
                            "_count": "desc"
                        }
                    }
                }

            },
            # 'sort': [{'views.keyword': {"order": "desc"}}]

        })
        year = es.search(index=all_index_name, size=0, body={

            'query': {
                'bool': {
                    'must': [
                        default_query
                    ],
                }
            },
            "aggs": {
                "group_by_month": {
                    "date_histogram": {
                        "field": 'date',
                        "calendar_interval": '1y',
                        "format": "yyyy-MM-dd",
                        "order": {
                            "_count": "desc"
                        }
                    }
                }

            },
            # 'sort': [{'views.keyword': {"order": "desc"}}]

        })
        month = es.search(index=all_index_name, size=0, body={

            'query': {
                'bool': {
                    'must': [
                        default_query
                    ],
                }
            },
            "aggs": {
                "group_by_month": {
                    "date_histogram": {
                        "field": 'date',
                        "calendar_interval": '1M',
                        "format": "yyyy-MM-dd",
                        "order": {
                            "_count": "desc"
                        }
                    }
                }

            },
            # 'sort': [{'views.keyword': {"order": "desc"}}]

        })
        # print(viewed['aggregations']['group_by_month']['buckets'])
        new_day = date_stats_filter(day)
        new_week = date_stats_filter(week)
        new_month = date_stats_filter(month)
        new_yesr = date_stats_filter(year)
        new_obj = {'new_day': new_day, 'new_month': new_month,
                'new_week': new_week, 'new_year': new_yesr}
        return jsonify(new_obj)
    except Exception as e:
        return jsonify({'errormsg':f'Sorry could not process your request at the moment. Pleasy try again later.'})

# # size of index index in gb 
# @app.route('/v2/sizeof', methods=['GET'])
# def sizeofindex():
#     try:
#         p = re.findall('[0-9.]+gb',str(subprocess.run("curl -XGET 127.0.0.1:9200/_cat/indices?pretty", shell= True, capture_output= True)).split('\\n')[1])[0]
#         return jsonify(p)
#     except Exception as e:
#         return jsonify({"error":"something happened."})


#--------------------------------------------------------------------------------------------------------------------------------------------#
"""
FILE SEARCH API
API 2.0.3.1
"""

@app.route('/file_search', methods=["POST"])
@jwt_required
@maxResults_decorator
@category_access_decorator
def file_search(index_name):
        
    print(index_name) 

    # Access the identity of the current user with get_jwt_identity
    jwt_all = get_jwt_identity()
    current_user = jwt_all[0]

    # Function to block usage of old tokens after change of password.
    if check_tokens(jwt_all) != 'successful':
        return check_tokens(jwt_all)[0]

    print(f"""{colors.green} User {current_user} has successfully logged. Accessing /file_search API from IP: {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} {colors.default}""")
    #logging for user acessing routes
    f = open("apilogs.txt", "a", encoding='UTF-8')
    #data_to_log = f'''DATETIME:{datetime.datetime.utcnow()}\nIPADDRESS:{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}\nUsername:{username}\n\n'''
    data_to_log = {"DATETIME":f"{datetime.datetime.utcnow().isoformat()+'+00:00'}","IPADDRESS":f"""{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}""","ENDPOINT":"/file_search","User": f"{current_user}"}
    f.write(str(data_to_log))
    f.write('\n')
    f.close()

    # check if a json request was made
    if not request.is_json:
        return jsonify({"errormsg": "Missing JSON in request"}), 400

    """
    ____________________________________________________________________________________
    RATE_LIMITING CODE
    ____________________________________________________________________________________
    """
    funcall = rate_limiter(current_user)

    try:
        if int(funcall) >= 0:
            #print(type(funcall))
            print(f"{colors.green}No restrictions so far. {funcall} {colors.default}")
    except Exception as e:
        #print(type(funcall))
        print(f"{colors.red}Restrictions in effect. {funcall[0]} {colors.default}")
        return funcall

    qtext = request.json.get('qtext', None)
    max_results = request.json.get('max', None)
    fuzzie = request.json.get('fuzzing', None)
    start_date = request.json.get('start_date', None)
    end_date = request.json.get('end_date', None)
    sort_order = request.json.get('sort_order', None)
    select_group = request.json.get('select_field', None)
    search_type = request.json.get('search_type', None)
    search_after_id = request.json.get('search_after_id', None)
    search_filter = request.json.get('search_filter', None)
    api_mode = request.json.get('api_mode', None)

    # if not str(max_results).isnumeric() or max_results > 1000:
    #         return jsonify({"errormsg":"You can not enter special characters inside the field that needs a number, or you want more than 1000 results, which is forbidden. API v2.0.3 Mode 1"}),403
   
    # es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)

    default_slop = 0
    if ' ' in qtext and search_filter == 'contains':
        default_slop = 100
    if search_filter == 'contains':
        print(qtext)
        url_regex = re.compile(r"https?://(www\.)?")
        qtext = url_regex.sub('', qtext).strip().strip('/')
        print(qtext, 'regex filter')
    
    try:
        qtext = qtext.lower()
    except:
        pass

    if start_date == "None":
        start_date = "1989-11-10T12:34:00"

    if end_date == "None" or end_date == "now":
        end_date = "now"

    fields_selected = "filename"
    fuzzy_selected = "message"
    ''' fields filter based on post/title filter'''

    if ' ' in qtext:
        fuzzie = 'AUTO'

    default_search_query = {"match_phrase": {
        "filename": {
            'query': qtext, 'slop': default_slop
        }
    }}

    default_search_filter = {'terms': {"is_group.keyword":  ["True", "False"]}}
    if search_type == 'group':
        default_search_filter = {
            'term': {"is_group.keyword": {"value": "True"}}}
    elif search_type == 'channel':
        default_search_filter = {
            'term': {"is_group.keyword": {"value": "False"}}}

    if sort_order != 'desc' and sort_order != 'asc':
        return jsonify({"errormsg": "sort_order can only be either asc or desc. API v2.0.3 MODE 1"}), 403

    if search_filter == 'contains' and ' ' not in qtext:
        default_query = 'wildcard'
        if '*' in qtext:
            default_query = 'wildcard'

        default_search_query = {
            default_query: {
                'filename.keyword': qtext

            }
        }
        new_contains_count_quer = {"query": {"bool": {"must": [default_search_query,default_search_filter, {"range": {"date": {"gte": f"{start_date}", "lte": f"{end_date}"}}}]}}} 
        new_contains_doc_count = es.count(index=index_name,
                body=new_contains_count_quer)
        if new_contains_doc_count['count'] <= 0:
            if select_group == 'None':
                default_search_query = {"multi_match": { "query": qtext, "type": "phrase", "fields": ["filename"], "slop": default_slop}}
            else:
                    default_search_query = {"match_phrase": {
                                fields_selected: {
                                    'query': qtext, 'slop': default_slop
                                        }
                                    }}
    decode_key = "None"
    try:
        if search_after_id != None and search_after_id != 'None':
            search_after_validator = pagination_checker_limiter(current_user)
            if search_after_validator is False:
                        return jsonify({'errormsg':f'Your Pagination limit is reached. Please contact at {COMPANY_EMAIL} for more information.'}), 403
                        
            decode_key = cryptocode.decrypt(
            str(search_after_id), '#random_pass1&*$@')
    except:
            print('could not decrypt the provided search after key')
    quer = {"size": max_results, "query": {"bool": {"must": [default_search_query, default_search_filter, {"range": {"date": {
            "gte": f"{start_date}", "lte": f"{end_date}"}}}]}}, "sort": [{"date": {"order": f"{sort_order}"}}]}
    count_quer = {"query": {"bool": {"must": [default_search_query, default_search_filter, {"range": {"date": {
            "gte": f"{start_date}", "lte": f"{end_date}"}}}]}}}
    #file search for userid/username
    if select_group == 'username' or select_group =='user_id':
        user_list = []
        user_filter ={"match_phrase": {
            "id": qtext}}
        if select_group == 'username':
            #extract userame match from db 
            user_res = es.search(index='onlineusers', body={
            "query": {
                "match": {
                    "username": {
                        "query": qtext,
                        "fuzziness": 1
                    }
                }
            }
        })

            for hit in user_res['hits']['hits']:

                user_list.append(hit["_source"]['userid'])
            user_filter={"terms": { "id": user_list}}
            
        quer = {"size": max_results, "query": {"bool": {"must": [user_filter, default_search_filter, {"range": {"date": {
            "gte": f"{start_date}", "lte": f"{end_date}"}}}],'must_not': [{'match': {'filename': 'None'}}]}}, "sort": [{"date": {"order": f"{sort_order}"}}]}
        count_quer = {"query": {"bool": {"must": [user_filter, default_search_filter, {"range": {"date": {
            "gte": f"{start_date}", "lte": f"{end_date}"}}}],'must_not': [{'match': {'filename': 'None'}}]}}}
            
    if decode_key != 'None':
        try:
            print('activated')
            quer['search_after'] = [decode_key]
        except:
            print('search after could not ')
    
    res = es.search(index= index_name ,
                    body=quer)
    doc_count = es.count(index=index_name,
                         body=count_quer)
    encoded_key = 'None'
    try:
        if len(res['hits']['hits']) > 1:
            encoded_key = cryptocode.encrypt(
            str(res['hits']['hits'][-1]['sort'][0]), '#random_pass1&*$@')
    except:
        print('could not encrypt/add search after key')
    scroll_auth = scroll_auth_extractor(current_user)
    return_list = [] 
    print(return_list)
    for hit in res['hits']['hits']:
                #print("inloop")
                #category mapping for route and api
                category = reverse_category_mapper(hit['_index'])
                hit['_source']['category'] = category
                return_list.append(hit["_source"])
                #print(return_list)
                
    redis_file_saver = 'None'
    if len(return_list) > 1:
        redis_file_saver = redis_data_saver({'data': return_list}, 1, qtext)
    
    if return_list == []:
        return_list = ['No results. Please try again after some time. API v2.0.3 Mode 2 ']
    total_doc_count = 0
    try:
        total_doc_count = doc_count['count']
    except:
        pass
                
    return json.dumps({'data': return_list, 'total_db_data': total_doc_count,'search_id': encoded_key,'scroll_auth':scroll_auth,"ratelimit":funcall,'file_id': redis_file_saver},ensure_ascii=False, indent=0, sort_keys=False).encode('utf-8'), 200, {'Content-Type': 'application/json'}

#--------------------------------------------------------------------------------------------------------------------------------------------#
"""
Search-as-a-type Feature
""" 
@app.route('/search_fields', methods=['POST'])
@jwt_required
def search_fields():
    index_name = all_index_name

    # Access the identity of the current user with get_jwt_identity
    jwt_all = get_jwt_identity()
    current_user = jwt_all[0]
    
    #logging for user acessing routes
    f = open("apilogs.txt", "a", encoding='UTF-8')
    #data_to_log = f'''DATETIME:{datetime.datetime.utcnow()}\nIPADDRESS:{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}\nUsername:{username}\n\n'''
    data_to_log = {"DATETIME":f"{datetime.datetime.utcnow().isoformat()+'+00:00'}","IPADDRESS":f"""{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}""","ENDPOINT":"/v2/search_fields","User": f"{current_user}"}
    f.write(str(data_to_log))
    f.write('\n')
    f.close()
    
    # Function to block usage of old tokens after change of password.
    if check_tokens(jwt_all) != 'successful':
        return check_tokens(jwt_all)[0]

    print(f"""{colors.green} User {current_user} has successfully logged. Accessing /search_fields API from IP: {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} {colors.default}""")

    # check if a json request was made
    if not request.is_json:
        return jsonify({"errormsg": "Missing JSON in request"}), 400
    
    """
    ____________________________________________________________________________________
    RATE_LIMITING CODE
    ____________________________________________________________________________________
    """
    funcall = rate_limiter(current_user)

    try:
        if int(funcall) >= 0:
            #print(type(funcall))
            print(f"{colors.green}No restrictions so far. {funcall} {colors.default}")
    except Exception as e:
        #print(type(funcall))
        print(f"{colors.red}Restrictions in effect. {funcall[0]} {colors.default}")
        return funcall
    
    #record for user channel search in the format of --> (userid,channel_search,last_searched_date) 
    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
    try:
    
        if es.indices.exists(index="user_channel_search"):
                print("Index user_channel_search exists.")
        else:
            print("Creating index user_channel_search")
            es.indices.create(index='user_channel_search', ignore=400)
        user_id=user_id_returner(current_user)
        if user_id == False:
            return jsonify({"errormsg": "You don't have privileges to perform this action. Please contact your service provider "}), 400
        dateandtime = datetime.datetime.now(timezone.utc).isoformat()
            
        new_obj = {'user_id':user_id} 
        hashasid = hashlib.md5(str(new_obj).encode('UTF-8')).hexdigest()
        if es.exists(index='user_channel_search', id=hashasid):
            res = es.update(index='user_channel_search',id=hashasid,body={
                "script" : {"inline":"""ctx._source.channel_search += params.state.count;
                ctx._source.last_searched_date =params.state.date ;""",
                "params": {
                "state": {"date": dateandtime,"count": 1}
        }}
                    })
        else:
            res=es.index(index='user_channel_search',id=hashasid,body={'user_id':user_id,'channel_search':1,'last_searched_date':dateandtime})
    except:
        pass

    qtext = request.json.get('qtext', None)

    viewed = es.search(index= all_index_name, size=5, body={
        'query': {
            "match_phrase_prefix": {
                "conv_name": {
                    "query": qtext,
                    "slop": 5

                }

            }
        },
        "collapse": {
            "field": "conv_name.keyword",
            "inner_hits": {
                "name": "latest",
                "size": 0
            }
        }
    })
    # print(viewed['aggregations']['group_by_month']['buckets'])
    return_list = []

    for hit in viewed['hits']['hits']:
        # print("inloop")
        new_obj = {'channel_name': hit["_source"]
                   ['conv_name'], 'channel_id': hit["_source"]['id'],'link': hit["_source"]['link']}
        return_list.append(new_obj)

    return jsonify(return_list)
#--------------------------------------------------------------------------------------------------------------------------------------------#

"""
Checks if a channel is in index or not
"""
@app.route('/channel_checker', methods=['POST'])
def channel_checker():
    index_name = all_index_name
    qtext = request.json.get('qtext', None)
    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
    res = es.search(index= index_name , size=5, body={
        "query": {
            "match_phrase": {
                "conv_name": qtext
            }
        }
    })
    response = res['hits']['hits']
    if len(response) > 1:
        return jsonify(res)
    else:
        return jsonify(res), 204

#--------------------------------------------------------------------------------------------------------------------------------------------#
"""
API to search files by extension
"""
@app.route('/file_extension_search', methods=["POST"])
@jwt_required
@stats_decorator
def file_extension_search(default_query):
    try:
        #checking token validation
        jwt_all = get_jwt_identity()

        if check_tokens(jwt_all) != 'successful':
            return check_tokens(jwt_all)[0]
        
        es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
        file_cnt = es.search(index=all_index_name, size=1000, body={
            "query": {
                "bool": {
                    "must": [
                        default_query

                    ],
                    'must_not': [
                        {'match': {'filename': 'None'}}
                    ]
                }
            }
        })

        if len(file_cnt['hits']['hits']) < 1:
            return jsonify({'data': [], 'total': []})

        files = file_cnt['hits']['hits']
        file_data = file_counter(files)
        current_app.config['JSON_SORT_KEYS'] = False
        return jsonify(file_data)
    except Exception as e:
        return jsonify(f'errormsg : Sorry could not process your request at the moment.')

#--------------------------------------------------------------------------------------------------------------------------------------------#
"""
API to filter filenames
"""
@app.route('/file_post_filter', methods=["POST"])
@jwt_required
@stats_decorator
def file_post_filter(default_query):
    try:
        #checking token validation
        jwt_all = get_jwt_identity()

        if check_tokens(jwt_all) != 'successful':
            return check_tokens(jwt_all)[0]

        es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
        file_cnt = es.search(index=all_index_name, size=20, body={
            "query": {
                "bool": {
                    "must": [
                       default_query,

                    ],
                    'must_not': [
                        {'match': {'filename': 'None'}}
                    ]
                }
            },
            "sort": [
                {
                    "date": {
                        "order": "desc"
                    }
                }
            ]
        })

        return_list = []
        if len(file_cnt['hits']['hits']) < 1:
            return jsonify([])

        for hit in file_cnt['hits']['hits']:
            # print("inloop")

            return_list.append(hit["_source"])

        return jsonify(return_list)
    except Exception as e:
        return jsonify(f'errormsg : Sorry could not process your request at the moment. Pleasy try again later.')
#--------------------------------------------------------------------------------------------------------------------------------------------#
"""
Mentions feature for channels and groups
"""
@app.route('/mentions', methods=["POST"])
@jwt_required
@stats_decorator
def mentions(default_query):
    try:
        #checking token validation
        jwt_all = get_jwt_identity()

        if check_tokens(jwt_all) != 'successful':
            return check_tokens(jwt_all)[0]

        es = Elasticsearch(elastichost, timeout=300, sniff_on_connection_fail=True,retry_on_timeout=True, max_retries=2,maxsize=5)
        print(1)
        res = es.search(index=all_index_name, size=1000,
                        body={
                        "query": {
                            "bool": {
                                "must": [
                                    default_query,
                                    {
                                        "wildcard": {
                                            "message.raw": {
                                                "wildcard": "*@*",
                                                "boost": 100.0

                                            }
                                        }
                                    },
                                ],
                                "adjust_pure_negative": "true",
                                "boost": 10.0
                            }


                        }
                    })
        total_post = es.count(index=all_index_name,
                            body={
                                "query":default_query
                            }) 
        new_res = mentionscalc(res['hits']['hits'], total_post['count'])

        current_app.config['JSON_SORT_KEYS'] = False

        return jsonify(new_res)
    except Exception as e:
        print(e)
        return jsonify(f'error :Sorry could not process your request at the moment')
#--------------------------------------------------------------------------------------------------------------------------------------------#
"""
Hashtag feature API
"""
@app.route('/hash', methods=["POST"])
@jwt_required
@stats_decorator
def hash(default_query):
    try:
        #checking token validation
        jwt_all = get_jwt_identity()

        if check_tokens(jwt_all) != 'successful':
            return check_tokens(jwt_all)[0]

        # es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
        es = Elasticsearch(elastichost, timeout=300, sniff_on_connection_fail=True,retry_on_timeout=True, max_retries=2,maxsize=5)
        res = es.search(index=all_index_name, size=900,
                        body={
                            "query": {
                                "bool": {
                                    "must": [
                                        default_query,
                                        {
                                            "wildcard": {
                                                "message.raw": {
                                                    "wildcard": "#*",
                                                    "boost": 100.0

                                                }
                                            }
                                        }


                                    ],
                                    "adjust_pure_negative": "true",

                                    "boost": 10.0
                                }
                            }
                        })
        total_post = es.count(index=all_index_name,
                            body={
                                "query": default_query
                            })
        new_res = hashcalc(res['hits']['hits'], total_post['count'])

        current_app.config['JSON_SORT_KEYS'] = False

        return jsonify(new_res)
    except Exception as e:
        return jsonify ({'error' :'Sorry could not process your request at the moment. Please try again later'})

#--------------------------------------------------------------------------------------------------------------------------------------------#
'''
user custom data insertion for statistics
'''
@app.route('/add_custom_channels', methods=['POST'])
@jwt_required
def add_custom_channels():
    
    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)

    try:
        '''
        postgress code
        '''
        jwt_all = get_jwt_identity()
        current_user = jwt_all[0]

        # Function to block usage of old tokens after change of password.
        if check_tokens(jwt_all) != 'successful':
            return check_tokens(jwt_all)[0]

        conn = psycopg2.connect(database='client_database', user=database_username,
                                password=database_password, host=host_name, port=db_port)
        conn.autocommit = True
        cursor = conn.cursor()
        cursor.execute(
            f"SELECT userid from client_database where username='{current_user}';")
        conn.commit()
        uname = cursor.fetchall()
        useridadmin = uname[0][0]

        '''
        route code
        '''

        channel_name = request.json.get('channel_name', None)
        channel_id = request.json.get('channel_id', None)
        date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # print(date)
        new_obj = {'channel_name': channel_name, 'channel_id': channel_id, 'user_id': str(useridadmin), 'created_date': date}
        hash_str = str(new_obj)
        hash_obj = {'channel_name': channel_name,'user_id': str(useridadmin)}
        hashasid = hashlib.md5(str(hash_obj).encode('UTF-8')).hexdigest()
        
        if es.indices.exists(index="user_customisation"):
            print("Index user_customisation exists.")
        else:
            print("Creating index user_customisation")
            es.indices.create(index='user_customisation', ignore=400)

        try:
            es.index(index='user_customisation',id=hashasid, body=new_obj)
            return jsonify({'message': f'successfully added the data for userid {useridadmin}'})
        except:
            return jsonify({'error': 'sorry could not insert the data'})
    except Exception as e:
        print(e)
        return jsonify({"error":e})

#--------------------------------------------------------------------------------------------------------------------------------------------#
'''
get user custom data for channel statistics
'''
@app.route('/get_custom_channels', methods=['GET'])
@jwt_required
def get_custom_channels():
    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
    jwt_all = get_jwt_identity()
    current_user = jwt_all[0]

    # Function to block usage of old tokens after change of password.
    if check_tokens(jwt_all) != 'successful':
        return check_tokens(jwt_all)[0]
    
    conn = psycopg2.connect(database='client_database', user=database_username,password=database_password, host=host_name, port=db_port)
    conn.autocommit = True
    cursor = conn.cursor()
    cursor.execute(f"SELECT userid from client_database where username='{current_user}';")
    conn.commit()
    
    uname = cursor.fetchall()
    useridadmin = str(uname[0][0])
    
    res = es.search(index='user_customisation', size=50, body={
        'query': {
            'term': {
                'user_id': useridadmin
            }
        }
    })
    
    response = res['hits']['hits']
    return jsonify(response)

#--------------------------------------------------------------------------------------------------------------------------------------------#
"""
Deletes user added channels for statistics
"""
@app.route('/delete_channel_custom', methods=["POST"])
@jwt_required
def delet_channel_custom():
    try:
        es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
        hash_id = request.json.get('hash_id', None)
        res = es.delete(index='user_customisation', id=hash_id)

        return jsonify({'status': 'succesfully deleted the channels.'})
    except Exception as e:
        return jsonify({'data': 'delete was unsuccessfull'})

#--------------------------------------------------------------------------------------------------------------------------------------------#
@app.route('/all_user_data_update', methods=["GET"])
def all_user_data_update():

    try:
        es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
        res = es.search(index='user_customisation',
                        body={
                            "query": {
                                "match_all": {}
                            }
                        })
        for i in res['hits']['hits']:
            new_id = i['_id']
            new_val = i['_source']
            print(new_val)
            source_to_update = {
                "doc": {
                    "notification": 'False'
                }
            }
            response = es.update(index='user_customisation',
                                 id=new_id, body=source_to_update)

        return jsonify({'message': 'all user notification status updated'})
    except Exception as e:
        return jsonify({'message': 'not updated', 'error': e})



"""
Enable/Disable user notifications
"""
@app.route('/update_notification', methods=["POST"])
def update_notification():
    user_id = request.json.get('id', None)
    notification_value = request.json.get('notification_value', None)
    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
    try:
        new_id = user_id
        source_to_update = {
            "doc": {
                "notification": notification_value
            }
        }
        response = es.update(index='user_customisation',
                             id=new_id, body=source_to_update)

        return jsonify({'message': 'updated successfully'})
    except:
        return jsonify({'message': 'not updated'})



"""
v2.0.8
Get Notification keywords from customers, and log the creation date.
"""
@app.route("/v2/create_notifications", methods=["POST"])
@jwt_required
@category_access_decorator
def create_notifications(index_name):
    try:

        # always calculate time based on UTC, ISO Format
        # to parse this string just use datetime.datetime.fromisoformat(date_of_submission)
        date_of_submission = datetime.datetime.utcnow().isoformat()+"+00:00"

        keyword_entered = request.json.get('keyword_to_watch', None)
        interval_type = request.json.get('interval_type', None)
        interval_number = request.json.get('interval_number', None)
        regex_status = request.json.get('regex_status', 'False')
        notification_type = request.json.get('type',None)
        search_type = request.json.get('search_type','exact')
        print(search_type,'search_type')
        keyword_value = keyword_entered

        # Access the identity of the current user with get_jwt_identity
        jwt_all = get_jwt_identity()
        current_user = jwt_all[0]

        # Function to block usage of old tokens after change of password.
        if check_tokens(jwt_all) != 'successful':
            return check_tokens(jwt_all)[0]

        print(f"""{colors.green} User {current_user} has successfully logged. Accessing /v2/getselfid API from IP: {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} {colors.default}""")

        if notification_type == None:
            notification_type = 'keyword'

        if notification_type != 'channel' and notification_type != 'logical'  and notification_type != 'keyword' :
            return jsonify({"errormsg": "from /v2/create_notifications. Please refer to the documentation for type parameters."}), 403, {'Content-Type': 'application/json'}

        if notification_type == 'channel' or 't.me' in keyword_entered:
            if't.me' in keyword_entered:
                new_val = keyword_entered.rsplit('/')[-1]
                keyword_value = new_val
        if notification_type != 'logical':
            verfier_conv = re.sub(r'\s{2,}',' ',keyword_entered)
            verifier = re.findall(r'\s(\b(and|or|AND|OR)\b)\s',verfier_conv)
            if len(verifier)>0:
                return jsonify({"errormsg": "from /v2/create_notifications. AND/OR operator are only allowed on logical feature."}), 403, {'Content-Type': 'application/json'}
        if notification_type != 'channel' and notification_type != 'logical':
            if regex_status == 'False' or regex_status == None:
                if search_type != 'exact' and search_type != 'contains':
                    return jsonify({"errormsg": "from /v2/create_notifications. Please refer to the documentation for serch_type parameters."}), 403, {'Content-Type': 'application/json'}
        else:
            if regex_status == 'True':
                return jsonify({"errormsg": "from /v2/create_notifications. 'regex' values is not supported on channel  or logical filters."}), 403, {'Content-Type': 'application/json'}
            if search_type == 'contains':
                return jsonify({"errormsg": "from /v2/create_notifications. 'contains' paramaeter is not supported on channel or regex or logical filters."}), 403, {'Content-Type': 'application/json'}

        if notification_type == 'logical':
            conv_data = logical_alert(keyword_entered)
            if conv_data != None:
                all_keys = conv_data.keys()
                if 'query' in all_keys:
                    keyword_entered =  conv_data['query']
                elif 'message' in all_keys:
                    return jsonify({'errormsg':conv_data['message']}),403
                else:
                    return jsonify({'errormsg':'Invalid parameter.Please refer to the docs'}),403

        if search_type == None:
            search_type = 'exact'
        default_regex = 'False'
        
        if regex_status == 'True':
            default_regex ='True'
        
        notification_status = "True"
        updated_date = datetime.datetime.utcnow().isoformat()+"+00:00"
        es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)

        if interval_number == '' or interval_type == '' or interval_number == None or interval_type == None:
            return jsonify({"errormsg": "from /v2/create_notifications. Please do not send keywords that are NoneType or 'None'."}), 403, {'Content-Type': 'application/json'}

        if str(interval_number).isnumeric() == False:
            return jsonify({"errormsg": "from /v2/create_notifications. Please send interval numbers as numeric value."}), 403, {'Content-Type': 'application/json'}
        if int(interval_number) < 1:
            return jsonify({"errormsg": "from /v2/create_notifications. Please send interval numbers as numeric value should be 1 or greater ."}), 403, {'Content-Type': 'application/json'}

        
        if interval_type != 'day' and interval_type != 'week' and interval_type != 'minutes':
            return jsonify({"errormsg": "from /v2/create_notifications. Please send valid parameters for interval_type should be day or week or minutes."}), 403, {'Content-Type': 'application/json'}

        if interval_type == 'minutes':
            conn1 = psycopg2.connect(database='client_database', user=database_username,password=database_password, host=host_name, port=db_port)
            conn1.autocommit = True
            cursor1 = conn1.cursor()
            cursor1.execute(f"SELECT customer_type from client_database where username='{current_user}';")
            conn1.commit()
            
            utype = cursor1.fetchall()
            sub_utype = str(utype[0][0])

            if int(interval_number) > 1439:
                return jsonify({"errormsg": "from /v2/create_notifications. The alert interval should not exceed a day ."}), 403, {'Content-Type': 'application/json'}
            if sub_utype != 'PAID_CUSTOMER':
                return jsonify({"errormsg": f"from /v2/create_notifications. Please contact us at {COMPANY_EMAIL} to enable this feature."}), 403, {'Content-Type': 'application/json'}
        if interval_type == 'week':
            if int(interval_number) > 54:
                return jsonify({"errormsg": "from /v2/create_notifications. The alert interval for weeks should not exceed a year ."}), 403, {'Content-Type': 'application/json'}
        if interval_type == 'day':
            if int(interval_number) > 365:
                return jsonify({"errormsg": "from /v2/create_notifications. The alert interval for day should not exceed a year ."}), 403, {'Content-Type': 'application/json'}
        filterword = ['None', None, '']
        if keyword_entered in filterword or len(keyword_entered) < 2:
            return jsonify({"errormsg": "from /v2/create_notifications. Please do not send keywords that are NoneType or 'None'."}), 403, {'Content-Type': 'application/json'}

        # connecting to the database
        try:
            conn = psycopg2.connect(database= 'client_database' , user= database_username , password= database_password , host= host_name, port= db_port)
            conn.autocommit = True
            cursor = conn.cursor()
        except Exception as e:
            conn.close()
            print("Database connection failed.")

        try:
            print(current_user)
            cursor.execute(f"SELECT userid from client_database where username='{current_user}';")
            conn.commit()
            uname = cursor.fetchall()
            userid= uname[0][0]
            print(f"userid is {userid}")
            conn.close()
            #results = {"username":f"{current_user}", "id":f"{userid}"}
            if es.indices.exists(index="user_notification"):
                print("Index user_notification exists.")
            else:
                print("Creating index user_notification")
                es.indices.create(index='user_notification', ignore=400)
            
            try:
                new_res = es.search(index="user_notification",size=10, body={
                    "query": {
                                "bool":
                                {
                                    "must": [
                                        {
                                            "term": {
                                            "userid": userid,
                                            }
                                        },
                                        {
                                            "term": {
                                            "keyword_entered": keyword_value,
                                            }

                                        },

                                        {
                                            "term": {
                                            "notification_type": "channel",
                                            }

                                        }
                                        
                                    ]
                                }

                            }
                        })
            
                if len(new_res['hits']['hits']) > 0:
                    notification_type = "channel"
            except Exception as e:
                pass
            
            # print(userid)
            new_obj = {'keyword_entered': keyword_value, 'userid': userid}
            body_obj = {'keyword_entered': keyword_value, 'userid': userid, 'interval_type': interval_type,
                        'interval_number': interval_number, 'updated_date': updated_date, 'date_of_submission': date_of_submission, 'notification_status': notification_status,'regex_status':default_regex,'notification_type':notification_type,'category':index_name,'search_type':search_type}
            hash_str = str(new_obj)
            hashasid = hashlib.md5(hash_str.encode('UTF-8')).hexdigest()
            # try:
            #     res1 = es.get(index="user_notification", id=hashasid)
            #     return jsonify({'message': 'the keyword has already been added'})
            # except:
            #     pass
            if es.indices.exists(index="user_notification"):
                print('index found')
                pass
            else:
                es.indices.create(index='user_notification', ignore=400)
            try:
                try:
                    res = es.count(index='user_notification', body={
                    "query": {
                                "term": {
                                    "userid": userid,


                                },

                                }
                })
                    if int(res['count']) >= 100:
                        return jsonify({"errormsg": "You have reached you notification rate limit.Please contact service provider for further query"}), 403, {'Content-Type': 'application/json'}
                except:
                    pass
                es.index(index='user_notification',
                        id=hashasid, body=body_obj)
                return jsonify({'message': f'Successfully added the alert feature with keyword {keyword_entered}'})
            except:
                return jsonify({'errormsg': 'Sorry could not insert the data .Please contact service provider'})
        except Exception as e:
            # conn.close()
            print(e)
            return jsonify({"errormsg":"Something happened while fetching profile ID."}), 400, {'Content-Type': 'application/json'}
    except Exception as e:
        return jsonify({'errormsg': f'Sorry could not insert the data .Please contact service provider'})



"""
Gets all alert settings for a user
""" 
@app.route('/v2/get_notification_data', methods=['POST'])
@jwt_required
def get_notification_data():
    # Access the identity of the current user with get_jwt_identity
    jwt_all = get_jwt_identity()
    current_user = jwt_all[0]

    # Function to block usage of old tokens after change of password.
    if check_tokens(jwt_all) != 'successful':
        return check_tokens(jwt_all)[0]

    print(f"""{colors.green} User {current_user} has successfully logged. Accessing /v2/getselfid API from IP: {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} {colors.default}""")

    # connecting to the database
    try:
        conn = psycopg2.connect(database= 'client_database' , user= database_username , password= database_password , host= host_name, port= db_port)
        conn.autocommit = True
        cursor = conn.cursor()
    except Exception as e:
        conn.close()
        print("Database connection failed.")

    try:
     
        cursor.execute(f"SELECT userid from client_database where username='{current_user}';")
        conn.commit()
        uname = cursor.fetchall()
        userid= uname[0][0]
        print(f"userid is {userid}")
        conn.close()
        results = {"username":f"{current_user}", "id":f"{userid}"}
        print(userid)

        try:
            es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
            res = es.search(index='user_notification', size=100, body={
                "query": {
                            "term": {
                                "userid": userid,


                            },

                            }
            })
            print(res)
            return_list = [] 
            
            if len(res['hits']['hits']) >= 1:
                for hit in res['hits']['hits']:
                    id = hit["_id"]
                    hit["_source"]["_id"] = id
                    if hit["_source"]["category"] != None and hit["_source"]["category"] != 'all':
                        hit["_source"]["category"] = [reverse_category_mapper(x) for x in hit["_source"]["category"]]
            
                    return_list.append(hit["_source"])
            return jsonify(return_list)
        
        except Exception as e:
            print(e)
            return jsonify({'errormsg': 'sorry could not retrieve  the data'}), 403
    except Exception as e:
        # conn.close()
        print(e)
        return jsonify({"errormsg":"Something happened while fetching profile ID."}), 400, {'Content-Type': 'application/json'}
"""
Gets all alert keyword settings for a user
""" 
@app.route('/v2/keyword_post_notification_data', methods=['POST'])
@jwt_required
def keyword_post_notification_data():
    # Access the identity of the current user with get_jwt_identity
    search_type = request.json.get('search_type', None)
    jwt_all = get_jwt_identity()
    current_user = jwt_all[0]

    # Function to block usage of old tokens after change of password.
    if check_tokens(jwt_all) != 'successful':
        return check_tokens(jwt_all)[0]

    print(f"""{colors.green} User {current_user} has successfully logged. Accessing /v2/getselfid API from IP: {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} {colors.default}""")

    # connecting to the database
    try:
        conn = psycopg2.connect(database= 'client_database' , user= database_username , password= database_password , host= host_name, port= db_port)
        conn.autocommit = True
        cursor = conn.cursor()
    except Exception as e:
        conn.close()
        print("Database connection failed.")

    try:
     
        cursor.execute(f"SELECT userid from client_database where username='{current_user}';")
        conn.commit()
        uname = cursor.fetchall()
        userid= uname[0][0]
        print(f"userid is {userid}")
        conn.close()
        results = {"username":f"{current_user}", "id":f"{userid}"}
        print(userid)
        default_quer = {"must":[ {"term": {
                                "userid": userid,

                            }}],
                            'must_not': [
                        {'match': {'notification_type': 'channel'}}
                    ]
                    }
        if search_type == 'channel':
            default_quer = {"must":[ {"term": {
                                "userid": userid,
                            }},
                            {'match': {'notification_type': 'channel'}}],
                    }
        try:
            es = Elasticsearch(elastichost)
            res = es.search(index='user_notification', size=100, body={
                "query": {
                    "bool":default_quer
                }
            })
            print(res)
            
            return_list = [] 
            if len(res['hits']['hits']) >= 1:
                for hit in res['hits']['hits']:
                    id = hit["_id"]
                    hit["_source"]["_id"] = id
            
                    return_list.append(hit["_source"])
            
            return jsonify({'data':return_list})
        except Exception as e:
            print(e)
            return jsonify({'error': 'sorry could not retrieve  the data'})
    except Exception as e:
        # conn.close()
        print(e)
        return jsonify("Something happened while fetching profile ID."), 200, {'Content-Type': 'application/json'}

@app.route('/server_email_data_extractor', methods=['POST'])
def server_email_data_extractor():
    try:
        secret_code = request.json.get('passcode', None)
        search_type = request.json.get('search_type', None)
        userid = request.json.get('user_id', None)
        interval_type = request.json.get('interval_type', None)
        if secret_code == '@lazlxEtIcS3A9rchIydzXiqg2u21fr0m':
            pass
        else:
            return jsonify({"errormsg": "Please enter the correct secret_code"}), 403
        try:
            default_quer = {"must": [
                            {"term": {
                                "userid": userid,


                            }},
                            {"match": {
                                "interval_type": interval_type,


                            }},

                            ],
                            'must_not': [
                {'match': {'notification_type': 'channel'}}
            ]
            }
            if search_type == 'channel':
                default_quer = {"must": [{"term": {
                    "userid": userid,
                }},
                {"match": {
                                "interval_type": interval_type,


                            }},
                    {'match': {'notification_type': 'channel'}}],
                }
            # print(default_quer)
            es = Elasticsearch(elastichost)
            res = es.search(index='user_notification', size=100, body={
                "query": {
                    "bool": default_quer
                },
                "sort": [{"updated_date": {"order": f"desc"}}]
            })

            return jsonify(res['hits']['hits'])
        except Exception as e:
            print(e)
            return jsonify({'error': 'sorry could not retrieve  the data'})
    except Exception as e:
        # conn.close()
        print(e)
        return jsonify("Something happened while fetching profile ID."), 200, {'Content-Type': 'application/json'}

"""
Disable or Enable alert notifications
"""
@app.route('/v2/update_notification_status', methods=['POST'])
@jwt_required
def update_notification_status():
    es_id = request.json.get('id', None)

    new_notification = "True"

    notification_status = request.json.get('status', None)

    if notification_status == "False":
        new_notification = "False"

    source_to_update = {
        "doc": {
            "notification_status": new_notification
        }
    }

    try:
        try:
            es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
            res = es.update(index='user_notification',
                            id=es_id, body=source_to_update)
            print(res)
            return jsonify(res)
        except Exception as e:
            print(e)
            return jsonify({"error": "Could not update the data for /v2/update_notification_status"})
    except Exception as e:
        return jsonify("Could not update the data for /v2/update_notification_status"), 200, {'Content-Type': 'application/json'}

"""
Temporary Route for modifying regex feature on all alert notifications
"""
@app.route('/v2/update_regex_feature', methods=['POST'])
def update_regex_feature():
    es_id = request.json.get('id', None)

    source_to_update = {
        "doc": {
            "regex_status": 'False'
        }
    }

    try:
        try:
            es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
            res = es.update(index='user_notification',
                            id=es_id, body=source_to_update)
            print(res)
            return jsonify(res)
        except Exception as e:
            print(e)
            return jsonify({"error": "Could not update the data for /v2/update_regex_feature"})
    except Exception as e:
        return jsonify("Could not update the data for /v2/update_regex_feature"), 200, {'Content-Type': 'application/json'}

"""
Updates alert time tracker
""" 
@app.route('/v2/update_notification_data', methods=['POST'])
# @jwt_required
def update_notification_data():
    es_id = request.json.get('id', None)
    updt_date = request.json.get('updt_date', None)
    
    source_to_update = {
        "doc": {
            "updated_date": updt_date#"2021-12-12T12:12:12.0+00:00" 
        }
    }

    try:
        try:
            es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
            res = es.update(index='user_notification',
                            id=es_id, body=source_to_update)
            print(res)
            return jsonify(res)
        except Exception as e:
            print(e)
            return jsonify({"error": f"""sorry could not update  the data with the error"""}),403
    except Exception as e:
        print(e)
        return jsonify(f"""sorry could not update the data with the error."""), 200, {'Content-Type': 'application/json'}

"""
Update the search_type of every users on elasticsearch index
"""
@app.route('/v2/update_search_type', methods=['POST'])
def update_search_type():
    es_id = request.json.get('id', None)
    secret_code = request.json.get('passcode', None)

    if secret_code == None:
        return jsonify({"errormsg": "Uh oh, careful with the fields in your request. It has to be exactly 'secret_code'."}), 403
    if secret_code == '@lazlxEtIcS3A9rchIydzXiqg2u21fr0m':
        pass
    else:
        return jsonify({"errormsg": "Please enter the correct secret_code"}), 403
    source_to_update = {
        "doc": {
            "category": "all"
        }
    }

    try:
        try:
            es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
            res = es.update(index='user_notification',
                            id=es_id, body=source_to_update)
            print(res)
            return jsonify(res)
        except Exception as e:
            print(e)
            return jsonify({"error": "Could not update the data for /v2/update_search_type"})
    except Exception as e:
        print(e)
        return jsonify("Could not update the data for /v2/update_search_type"), 200, {'Content-Type': 'application/json'}

"""
2.0.8.d
Deletes user alert notifications
""" 
@app.route('/v2/delete_user_notification', methods=["POST"])
@jwt_required
def delet_user_notification():
    try:
        es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
        hash_id = request.json.get('hash_id', None)
        res = es.delete(index='user_notification', id=hash_id)

        return jsonify({'status': 'Succesfully deleted the E-mail alert notification keyword.'}), 200
    except Exception as e:
        return jsonify({'errormsg': 'delete was unsuccessful'}), 403


"""
fetch channel names for daily scraping
""" 
@app.route('/channel_name_loop_parition', methods=['GET'])
def channel_name_loop_parition():

    index_name = "telegram2_alias"

    all_data = []
    for i in range(20):
        es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
        channel_query = es.search(index= index_name, size=0, body={
            'query': {
                'match_all': {}
            },
            "aggs": {
                "unique_channels": {
                    "terms": {"field": "conv_name.keyword",
                              "include": {
                                  "partition": i,
                                  "num_partitions": 20
                              },
                              "size": 10000}
                }
            }
        })

        response = channel_query
        new_res = response['aggregations']["unique_channels"]['buckets']
        for i in new_res:
            all_data.append(i)

    # print(viewed['aggregations']['group_by_month']['buckets'])

    return jsonify({"length": len(all_data), "data": all_data})



"""
Searches all user-notifications keyword by server: JWT not required
"""
@app.route('/v2/get_user_data_server', methods=['GET'])
def get_user_data_server():
    
    try:
        ip_new = request.environ.get("HTTP_X_REAL_IP", request.remote_addr).split(',')[0]
        print(ip_new)

    except Exception as e:
        print(e)
    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
    
    if es.indices.exists(index="user_notification"):
                print('index found')
                pass
    else:
        es.indices.create(index='user_notification', ignore=400)

    # allowing Localhost only
    # if ip_new != '127.0.0.1':
    #     return jsonify({'message': 'sorry you dont have priviliges'})

    try:
        try:
            
            res = es.search(index='user_notification', size=0, body={
                "query": {
                            "match_all": {},
                            },
                "aggs": {
                    "all_users": {
                        "terms": {"field": "userid",  "size": 1000}
                    }
                }
            })
            print(res)
            return jsonify(res['aggregations']["all_users"]['buckets'])
        except Exception as e:
            print(e)
            return jsonify({'error': 'sorry could not retrieve  the data'})
    except Exception as e:
        # conn.close()
        print(e)
        return jsonify("Something happened while fetching data."), 200, {'Content-Type': 'application/json'}



"""
Search user-notification keyword by server for a particular user: JWT not required
"""
@app.route('/v2/get_notification_individual_data_server', methods=['POST'])
def get_notification_individual_data_server():
    
    try:
        ip_new = request.environ.get("HTTP_X_REAL_IP", request.remote_addr).split(',')[0]
        print(ip_new)

    except Exception as e:
        print(e)

    # Allowing localhost only
    if ip_new != '127.0.0.1':
        return jsonify({'message': 'sorry you dont have priviliges'})

    userid = request.json.get('userid', None)
    interval_type = request.json.get('interval_type', None)

    try:

        try:
            es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
            res = es.search(index='user_notification', size=100, body={
                "query": {
                    "bool": {
                        "must": [
                            {"term": {
                                "userid": userid,


                            }},
                            {"term": {
                                "interval_type": interval_type,


                            }},

                        ]
                    },

                }
            })
            print(res)
            return jsonify(res['hits']['hits'])
        except Exception as e:
            print(e)
            return jsonify({'error': 'sorry could not retrieve  the data'})
    except Exception as e:
        # conn.close()
        print(e)
        return jsonify("Something happened while fetching profile ID."), 200, {'Content-Type': 'application/json'}


"""
Search user-notification keywords by server: JWT not required
"""
@app.route('/v2/notification_data_search', methods=['POST'])
# @jwt_required
def notification_data_search():
    try:
        ip_new = request.environ.get("HTTP_X_REAL_IP", request.remote_addr).split(',')[0]
        print(ip_new)

    except Exception as e:
        print(e)
    
    # Allowing localhost only
    # if ip_new != '127.0.0.1' :
    #     return jsonify({'message': 'sorry you dont have priviliges'})

    keyword = request.json.get('keyword', None)
    updated_data = request.json.get('updated_data', None)
    regex_status = request.json.get('regex_status',None)
    notification_type = request.json.get('notification_type',None)
    category = request.json.get('category','all')
    search_type= request.json.get('search_type','exact')
    userid = request.json.get('user_id',None)
    new_category = category

    try:
        conn = psycopg2.connect(database='client_database', user=database_username,
                                password=database_password, host=host_name, port=db_port)
        conn.autocommit = True
        cursor = conn.cursor()
        cursor.execute(
            f"SELECT isauthorized from client_database where userid='{userid}'")
        conn.commit()
        uname = cursor.fetchall()
        isauthorized = uname[0][0]
        if isauthorized != 'True':

            #sending empty data to unsend email to unauth users
            return jsonify([])
        conn.close()
    except:
        conn.close()
        

    #old to new index converter logic 
    if category == 'all':
        all_category = account_category_returner(userid)
        conv_category = [old_to_new_category(x) for x in all_category]
        new_category = conv_category
    else:
        conv_category = [old_to_new_category(x) for x in category]
        new_category = conv_category
        
    if search_type == 'contains':
            url_regex = re.compile(r"https?://(www\.)?")
            keyword = url_regex.sub('', keyword).strip().strip('/')
    index_name = new_category
    default_query = {
                                "match_phrase": {
                                    "message": keyword,

                                }
                            }
    if search_type == 'contains':
        default_query = {
                        "query_string": {
                                "query": f"*{keyword}*",
                                "fields": [ "message" ]
                            }
                        }
    
    if regex_status == 'True':
        default_query={"regexp": {regex_validator(keyword, "message"): {"value": f"""{keyword}""", "flags": "ALL","case_insensitive": "true", "max_determinized_states": 10000, "rewrite": "constant_score"}}}
    if notification_type == 'channel':
        qtext = channel_name_converter(keyword)
        default_query = {
            "terms": {
                "link": qtext
            }
        }
        index_name =all_index_name
    print(notification_type)
    if notification_type == 'logical':
        default_query={
            "query_string": {
             "query":keyword,
            "default_field":"message"

            }
        }
    print(default_query)
    
    try:
        try:
            es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
            res = es.search(index=index_name, size=1000, body={
                "query": {
                    "bool": {
                        "must": [default_query
                            ,
                            {"range": {"date": {
                                "gte": updated_data}}}
                        ]
                    }

                }
            })
            print(len(res['hits']['hits']))
            return jsonify(res['hits']['hits'])
        except Exception as e:
            print(e)
            return jsonify({'errormsg': 'sorry, we could not retrieve requested data.'})
    
    except Exception as e:
        # conn.close()
        print(e)
        return jsonify({"errormsg":"Something happened while fetching profile ID, in the route /v2/notification_data_search"}), 200, {'Content-Type': 'application/json'}

"""
Sends Mail from API server locally. 
Only allows localhost to access this route.
"""

@app.route("/v2/bot_notifications", methods=["POST"])
def bot_notifications():
    try:
        try:
            ip_new = request.environ.get("HTTP_X_REAL_IP", request.remote_addr).split(',')[0]
            print(ip_new)

        except Exception as e:
            print(e)

        # allowing Localhost only
        if ip_new != '127.0.0.1' :
            return jsonify('404 Not Found. This page does not exist.'), 404, {'Content-Type': 'application/json'}
        
        program_path = os.getcwd()
        es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
        filename = request.json.get("filename", None)
        keyword = request.json.get("keyword", None)
        userid = request.json.get("userid", None)
        
        file_dir = '/root/notifications/'
        
        if filename == None or userid == None or keyword == None:
            return jsonify({'message': 'Please also send the file name'})

        if es.indices.exists(index="email_db"):
            print('index found')
            pass
        else:
            es.indices.create(index='email_db', ignore=400)
        
        file_hash_obj = {'filename': filename, 'keyword': keyword,'userid': userid}
        file_hash = hashlib.md5(str(file_hash_obj).encode('UTF-8')).hexdigest()
        
        try:
            res1 = es.get(index="email_db", id=file_hash)
            print('mail data found')
            return jsonify({'message': 'Email already sent.'})

        except:
            os.chdir(file_dir)
            
            email_checker = email_extractor(userid)

            if email_checker == False:
                return jsonify({'message': 'Sorry could not retrive. Email was already sent.'})

            print(email_checker)
            file_path = os.path.join(file_dir+filename)

            sender = 'tesseract@tesseractintelligence.com'

            recipients = [email_checker]
            print("----test", recipients)

            msg = Message('Keyword Report', sender=sender, body=f'The following are the reports based on the preference of {keyword} present on our platform.',recipients=recipients )
            
            with app.open_resource(file_path) as fp:
                msg.attach(filename, "text/csv", fp.read())
                mail.send(msg)
            
            new_obj = {'filename': filename, 'keyword': keyword,'email_sent_time': datetime.datetime.today()}
            
            es.index(index="email_db", body=new_obj, id=file_hash)

            mail.send(msg)
            print(mail)
            
            os.chdir(program_path)

            return jsonify({'message': 'Email sent'}), 200, {'Content-Type': 'application/json'}
    except Exception as e:
        os.chdir(program_path)
        return jsonify({'Error': f'Sorry could not process your request at the moment. Pleasy try again later.'}), 200, {'Content-Type': 'application/json'}
        
# get sent email through the bot script for admin only
@app.route('/get_bot_email', methods=['GET'])
@jwt_required
def get_bot_email():
    try:

        jwt_all = get_jwt_identity()
        current_user = jwt_all[0]
    
        # Function to block usage of old tokens after change of password.
        if check_tokens(jwt_all) != 'successful':
            return check_tokens(jwt_all)[0]

        print(f"""{colors.green} User {current_user} has successfully logged. Accessing /v2/posts API from IP: {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} {colors.default}""")
        if current_user == 'administrator':
            es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
            res = es.search(index='email_db', size=1000, body={
                "query": {
                    "match_all": {}
                }
            })
            response = res['hits']['hits']
            return_list = []

            for hit in res['hits']['hits']:
                # print("inloop")
                return_list.append(hit["_source"])
            return jsonify(return_list)
        else:
            return jsonify({'errormsg': 'You do not have priviliges to perfom this action. Error from API route /get_bot_email'})
    except Exception as e:
        return jsonify({'errormsg': 'Something happened in the API route /get_bot_email'})

#--------------------------------------------------------------------------------------------------------------------------------------------#
"""
Forums search API
This API searches inside a list of forums that are set by using
cse.google.com account.
Please import the gkey and seid from config file.
"""

@app.route("/v2/forums_search", methods=["POST"])
@jwt_required
def search_engine():

    try:

        rate_limit_forums = ''
        # Access the identity of the current user with get_jwt_identity
        jwt_all = get_jwt_identity()
        current_user = jwt_all[0]
        #logging for user acessing routes
        f = open("apilogs.txt", "a", encoding='UTF-8')
        #data_to_log = f'''DATETIME:{datetime.datetime.utcnow()}\nIPADDRESS:{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}\nUsername:{username}\n\n'''
        data_to_log = {"DATETIME":f"{datetime.datetime.utcnow().isoformat()+'+00:00'}","IPADDRESS":f"""{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}""","ENDPOINT":"/v2/forums_search","User": f"{current_user}"}
        f.write(str(data_to_log))
        f.write('\n')
        f.close()

        # Function to block usage of old tokens after change of password.
        if check_tokens(jwt_all) != 'successful':
            return check_tokens(jwt_all)[0]

        print(f"""{colors.green} User {current_user} has successfully logged. Accessing /v2/forums_search API from IP: {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} {colors.default}""")
        
        # connecting to the database
        try:
            conn_db = psycopg2.connect(database= 'client_database' , user= database_username , password= database_password , host= host_name, port= db_port)
            conn_db.autocommit = True
            cursor_db = conn_db.cursor()

            query_to_db = f"SELECT forums_ratelimit from client_database where username='{current_user}'"
            cursor_db.execute(query_to_db)
            rate_limit_forums = cursor_db.fetchall()[0][0]

        except Exception as e:
            conn_db.close()
            return jsonify({"errormsg": "Are you registered? Please contact us at tesseract@tesseractintelligence.com"}), 403, {'Content-Type': 'application/json'}
        
        if rate_limit_forums< 1:
            return jsonify({"errormsg":"You have reached a rate-limit for forums search. Please contact your service provider."}), 403 , {'Content-Type': 'application/json'}

        
        """
        ____________________________________________________________________________________
        RATE_LIMITING CODE
        ____________________________________________________________________________________
        """
        funcall = rate_limiter(current_user)

        try:
            if int(funcall) >= 0:
                #print(type(funcall))
                print(f"{colors.green}No restrictions so far.{colors.default}")
        except Exception as e:
            #print(type(funcall))
            print(f"{colors.red}Restrictions in effect. {funcall[0]} {colors.default}")
            return funcall 

        # query
        query = request.json.get('qtext', None)

        if len(query) < 1 or len(query) > 50 :
            return jsonify({"errormsg":"The query must not be empty or greater than 50 chars. From /v2/forums_search"}), 403 , {'Content-Type': 'application/json'}
        
        if '"' in query or "'" in query:
            return jsonify({"errormsg":"Quotes not allowed. From /v2/forums_search"}), 403 , {'Content-Type': 'application/json'}


        # Google-API URL
        url = "https://www.googleapis.com/customsearch/v1"

        all_data = [] 

        for i in range(3):
            try:
                qstr = {"key":gkey,"cx":seid ,"num":"10","q": query ,"start": i } # remove 'start' field if no indexing
            except Exception as e:
                return jsonify({"errormsg":"Contact service provider. There is a server error at /v2/forums_search"}), 500 , {'Content-Type': 'application/json'}

            print(f"search LOOP ----> {i}")
            response = requests.request("GET", url, params=qstr)
            json_data = json.loads(response.text)   
            
            # break the loop if the first query doesn't render any results to save API quota
            try:
                print(f"""""{colors.red} {json_data["items"]}{colors.default}""")
            except Exception as e:
                print(f"""""{colors.red} {e}{colors.default}""")
                break
            
            all_data.append(json_data)

        try:
            if """Quota exceeded for quota metric 'Queries' and limit 'Queries per day' of service 'customsearch.googleapis.com""" in json_data['error']['message']:
                print(json.dumps({"Error":"You have exceeded your daily limits."}))

                return jsonify({"errormsg":"Server issues. Please contact your service provider."}), 403 , {'Content-Type': 'application/json'}

        except Exception as e:
            pass

        a = all_data
        filtered_data = [] 

        for i in range(len(a)):
            print(type(a[i]))
            try:
                for m in a[i]["items"]:
                    print(m.keys())
                    post_title = m['title']
                    urllink = m['link']
                    snippet = m['snippet']

                    print(f'''{colors.green}"title":{m['title']}{colors.default}''')
                    print(f'''{colors.green}"urllink":{m['link']}{colors.default}''')
                    print(f'''{colors.green}"snippet":{m['snippet']}{colors.default}''')

                    image_link = "None"
                    try:
                        image_link = m['pagemap']['cse_image'][0]['src']
                    except Exception as e:
                        print("no link")
                    
                    new_object = {"post_title":post_title, "urllink": urllink, "snippet":snippet, "image_link": image_link}
                    filtered_data.append(new_object)

            except Exception as e:
                print(e)

        print(f"{colors.cyan}{filtered_data}{colors.default}")


        if current_user != 'administrator':
            # connecting to the database
            try:
                conn_db = psycopg2.connect(database= 'client_database' , user= database_username , password= database_password , host= host_name, port= db_port)
                conn_db.autocommit = True
                cursor_db = conn_db.cursor()

                rate_limit_forums -= 1 
                query_to_db = f"UPDATE client_database set forums_ratelimit={rate_limit_forums} where username='{current_user}'"
                cursor_db.execute(query_to_db)
            except Exception as e:
                conn_db.close()
                return jsonify({"errormsg": "ratelimit update failed for ratelimit at /v2/forums_search Please contact us at tesseract@tesseractintelligence.com"}), 403, {'Content-Type': 'application/json'}

        if filtered_data == []:
            filtered_data = 'No results. Please try again after some time.'
            return jsonify({"errormsg":filtered_data, "rate_limits":funcall, "forums_ratelimit": rate_limit_forums}), 404, {'Content-Type': 'application/json'}
        else:
            return jsonify({"data":filtered_data, "rate_limits":funcall, "forums_ratelimit": rate_limit_forums}), 200, {'Content-Type': 'application/json'}
    
    except Exception as e:
        return jsonify({"errormsg":f"Please refer to the documentation for /v2/forums_search. If the problem persists, please try again later or contact us at {COMPANY_EMAIL}"}), 400


#--------------------------------------------------------------------------------------------------------------------------------------------#

"""
Crawling Telegram channel images in real-time.
"""
@app.route('/image_crawler', methods=['POST'])
def image_crawler_route():
    img_url = request.json.get('url', None)

    try:
        url = requests.get(img_url).text

        soup = BeautifulSoup(url, 'lxml')
        main_parent = soup.find(
            'a', {'class': 'tgme_widget_message_photo_wrap'})['style']
        style = cssutils.parseStyle(main_parent)

        src = style['background-image']

        return jsonify({'src': src})

    except Exception as e:
        return jsonify({'src': f'error{e}'})


"""
Generates report for current user.
"""
@app.route('/report_generator', methods=["POST"])
@jwt_required
def report_generator():
    try:
        jwt_all = get_jwt_identity()
        current_user = jwt_all[0]

        # Function to block usage of old tokens after change of password.
        if check_tokens(jwt_all) != 'successful':
            return check_tokens(jwt_all)[0]
        
        # ratelimiter
        # connecting to the database
        try:
            conn_db = psycopg2.connect(database= 'client_database' , user= database_username , password= database_password , host= host_name, port= db_port)
            conn_db.autocommit = True
            cursor_db = conn_db.cursor()

            query_to_db = f"SELECT reportgenerator_ratelimit from client_database where username='{current_user}'"
            cursor_db.execute(query_to_db)

            ratelimit_fetched = cursor_db.fetchall()[0][0]

            if ratelimit_fetched < 1:
                return jsonify({"errormsg":"You have reached a rate-limit for report generator. Please contact your service provider."}), 403 , {'Content-Type': 'application/json'}

            if current_user != 'administrator':
                rate_limit_report = ratelimit_fetched - 1
                try:
                    cursor_db.execute(f"UPDATE client_database set reportgenerator_ratelimit ={rate_limit_report} where username='{current_user}';")
                except Exception as e:
                    return jsonify({"errormsg":"Could not verify your ratelimit. Please contact your service provider. Error from /report_generator"}), 403

        except Exception as e:
            conn_db.close()
            return jsonify({"errormsg": "Are you registered? Please contact us at tesseract@tesseractintelligence.com"}), 403, {'Content-Type': 'application/json'}
        

        f = open("apilogs.txt", "a", encoding='UTF-8')
        #data_to_log = f'''DATETIME:{datetime.datetime.utcnow()}\nIPADDRESS:{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}\nUsername:{username}\n\n'''
        data_to_log = {"DATETIME":f"{datetime.datetime.utcnow().isoformat()+'+00:00'}","IPADDRESS":f"""{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}""","ENDPOINT":"/report_generator","User": f"{current_user}"}
        f.write(str(data_to_log))
        f.write('\n')
        f.close()

        
        if 'jndi' in str(request.headers):
            data_to_log = str({"DATETIME":f"{datetime.datetime.utcnow().isoformat()+'+00:00'}","IPADDRESS":f"""{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}"""})
            header = '\n'+ str(request.headers)

            with open('LOG4Jattack.txt','a') as writer:
                writer.write(data_to_log +  header)
                writer.write('\n')
            
            return jsonify({"errormsg":"Unauthorized"}), 403
        try:
            conn = psycopg2.connect(database= 'client_database' , user= database_username , password= database_password , host= host_name, port= db_port)
            conn.autocommit = True
            cursor = conn.cursor()
        except Exception as e:
            conn.close()
            print("Database connection failed.")


        index_name_user = request.json.get('selectCategory', None)
        index_name = []

        try:
            if "hacking" in index_name_user:
                index_name.append("telegram2_alias")
            
            if "financials" in index_name_user:
                index_name.append("financials")

            if "extremepolitical" in index_name_user:
                index_name.append("extremepolitical2_alias")
            
            if "religion_spirituality" in index_name_user:
                index_name.append("religion_spirituality_alias")
            
            if "pharma_drugs" in index_name_user:
                index_name.append("pharma_drugs_alias")
            
            if "criminal_activities" in index_name_user:
                index_name.append("criminal_activities_alias")

            if "information_technology" in index_name_user:
                index_name.append("information_technology")
            if "cyber_security_alias"in index_name_user:
                index_name.append("cyber_security_alias")

            if index_name_user == None or index_name_user == "all": 
                index_name =  ["telegram2_alias","financials","extremepolitical2_alias","religion_spirituality_alias","pharma_drugs_alias","criminal_activities_alias","information_technology","cyber_security_alias"]
            
            elif "hacking" not in index_name_user and "financials" not in index_name_user and "extremepolitical" not in index_name_user and "religion_spirituality" not in index_name_user and "pharma_drugs" not in index_name_user and "criminal_activities" not in index_name_user and "information_technology" not in index_name_user and "cyber_security" not in index_name_user:
                 return jsonify({"errormsg":"Uh oh, careful with the fields in your request. It has to be exact. Refer the API documentation provided to you for API v2.0.3  Mode 1"}),403
        
        except Exception as e:
            index_name =  ["telegram2_alias","financials","extremepolitical2_alias","religion_spirituality_alias","pharma_drugs_alias","criminal_activities_alias","information_technology","cyber_security_alias"]

        qtext = request.json.get('qtext', None)
        max_results = 500
        start_date = request.json.get('start_date', None)
        end_date = request.json.get('end_date', None)
        sort_order = request.json.get('sort_order', None)
        select_group = request.json.get('select_field', None)
        search_type = request.json.get('search_type', None)
        es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
        print(select_group)

        if qtext == None :
                return jsonify({"errormsg":"Uh oh, careful with the fields in your request. It has to be exact. Refer the API documentation provided to you for API v2.0.3  Mode 1. Error from /report_generator"}),403

        if start_date == "None":
            start_date = "1989-11-10T12:34:00"

        if end_date == "None" or end_date == "now":
            end_date = "now"

        fields_selected = "message"
        fuzzy_selected = "message"
        ''' fields filter based on post/title filter'''

        if select_group == 'conv_name':
            print(';found')
            fields_selected = "conv_name"
        if qtext == 'None':
            max_results = 20

        if ' ' in qtext:
            fuzzie = 'AUTO'

        default_search_filter = {'terms': {"is_group.keyword":  ["True", "False"]}}
        if search_type == 'group':
            default_search_filter = {
                'term': {"is_group.keyword": {"value": "True"}}}
        
        elif search_type == 'channel':
            default_search_filter = {
                'term': {"is_group.keyword": {"value": "False"}}}

        default_search_query = {"match_phrase": {fields_selected: qtext}}
       

        if select_group == 'None':
            default_search_query = {"multi_match": {
                "query": qtext, "type": "phrase", "fields": ["message", "conv_name"]}}

        if sort_order != 'desc' and sort_order != 'asc':
            return jsonify({"errormsg": "sort_order can only be either asc or desc. Error from /report_generator"}), 403

        quer = {"size": max_results, "query": {"bool": {"must": [default_search_query, default_search_filter, {"range": {"date": {
                "gte": f"{start_date}", "lte": f"{end_date}"}}}]}}, "sort": [{"date": {"order": f"desc"}}]}

        # es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
        res = es.search(index=index_name,
                        body=quer)
    
        return_list = []
        message_filter = []
        
        for hit in res['hits']['hits']:
            if hit["_source"]['message'] not in message_filter:
                message_filter.append(hit["_source"]['message'])
                return_list.append(hit["_source"])

        cursor.execute(f"SELECT userid from client_database where username='{current_user}';")
        conn.commit()
        uname = cursor.fetchall()
        user_id= uname[0][0]
        conn.close()
        
        file_name = f'{datetime.datetime.today().strftime("%Y-%m-%d")}_{qtext}_{user_id}.csv'
        file_hash = {'userid': user_id, 'file_name': file_name}
        file_hash_id = hashlib.md5(str(file_hash).encode('UTF-8')).hexdigest()
        file_obj = {'userid': user_id, 'file_name': file_name,
                    'added_date': datetime.datetime.now(), 'keyword': qtext}
        
        if es.indices.exists(index="report_db"):
            print('index found')
            pass
        else:
            es.indices.create(index='report_db', ignore=400)
        
        try:
            res1 = es.get(index="report_db", id=file_hash_id)
            print('mail data found')
            return jsonify({'message': 'Report already exists'})
        except Exception as e:
            program_path = os.getcwd()
            os.chdir(folder_create())
            
            with open(file_name, 'w', encoding='UTF-8') as csvfile:
                csvwriter = csv.writer(csvfile)
                csvwriter.writerow(['Channel_Name', 'Keyword', 'Posts',
                                    'Post_Uploaded_Date', "Channel_or_Group", 'Link'])

                for data in return_list:
                    channel_name = data['conv_name']
                    keyword = qtext
                    posts = data['message']
                    post_uploaded_date = data['date']
                    link = data['link']
                    post_id = data['msgid']
                    new_link = channel_id_adder(link, post_id)
                    is_group = 'Group'

                    try:
                        if data['is_group'] == 'False':
                            is_group = 'Channel'
                    except:
                        pass

                    data_row = [channel_name, keyword, posts,
                                post_uploaded_date, is_group, new_link]
                    csvwriter.writerow(data_row)
            
            os.chdir(program_path)
            
            es.index(index="report_db", body=file_obj, id=file_hash_id)

        return jsonify({'message':'success','report_ratelimit':rate_limit_report})
    except Exception as e:
        return jsonify({'errormsg':'Something happened in the route /report_generator'})


"""
Route for fetching reports for a particular user.
"""
@app.route('/get_report', methods=['GET'])
@jwt_required
def get_report():
    try:
        es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
        jwt_all = get_jwt_identity()
        current_user = jwt_all[0]

            # Function to block usage of old tokens after change of password.
        if check_tokens(jwt_all) != 'successful':
                return check_tokens(jwt_all)[0]
        try:
            conn = psycopg2.connect(database= 'client_database' , user= database_username , password= database_password , host= host_name, port= db_port)
            conn.autocommit = True
            cursor = conn.cursor()
        except Exception as e:
            conn.close()
            print("Database connection failed.")
        
        cursor.execute(f"SELECT userid from client_database where username='{current_user}';")
        conn.commit()
        uname = cursor.fetchall()
        user_id= uname[0][0]
        conn.close()
        
        res = es.search(index='report_db', size=100, body={
            "query": {
                "term": {
                    "userid": user_id

                }
            }
        })
        return jsonify(res['hits']['hits'])
    except Exception as e:
        return jsonify({'message':'Something happened in the API route /get_report'}), 200

"""
sends files as requested.
TODO SECURITY : Check for Security Issues later.
"""
@app.route('/download_report', methods=['POST'])
@jwt_required
def download_report():
    
    file_name = request.json.get('filename', None)
    if file_name == None:
        return jsonify({'errormsg': 'missing file name'})
    safe_path = safe_join(r'/root/csv_reports/', file_name)
    new_file_path = os.path.join(r'/root/csv_reports/', file_name)
    try:
        return send_file(safe_path, as_attachment=True)
    except FileNotFoundError:
        return jsonify({'errormsg': 'error sending file'}),403

"""
Delete generated reports from the csv_reports folder
"""
@app.route('/delete_report', methods=['POST'])
@jwt_required
def delete_report():
    try:
        es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
        file_id = request.json.get('file_id', None)
        file_name = request.json.get('filename', None)
        safe_path = safe_join(r'/root/csv_reports/', file_name)
        os.remove(safe_path)
        print(safe_path)

        res = es.delete(index='report_db', id=file_id)

        return jsonify({'message': 'success.'})
    except Exception as e:
        print(e)
        return jsonify({'errormsg': 'failed to delete'}), 403


"""
Gets unique channels lists to which a particular userID has posted 
The user_id is Telegram userID.
"""
@app.route('/unique_user_data', methods=['POST'])
@jwt_required
def unique_user_data():
    try:
        user_id = request.json.get('user_id', None)
        
        if user_id == None:
            return jsonify({'errormsg': 'plece send correct indices'})
        
        es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
        res = es.search(index= all_index_name, size=0, body={
            "query": {
                "match_phrase": {
                    "id": user_id
                }
            },
            "aggs": {
                "unique_channels": {
                    "terms": {
                        "field": "conv_name.keyword"
                    },
                    "aggs": {
                        "channel_link": {"top_hits": {"size": 1, "_source": {"include": ['link']}}}
                    }
                }
            }
        })
        return jsonify({'data': res['aggregations']["unique_channels"]['buckets']})
    except Exception as e:
        return jsonify({'errormsg':f'Sorry could not process your request at the moment. Pleasy try again later.'}),403


"""
Gets the files shared by a userID
The user_id is Telegram userID.
"""
@app.route('/user_file', methods=['POST'])
@jwt_required
def user_file():
    try:
        user_id = request.json.get('user_id', None)
        es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
        
        if user_id == None:
            return jsonify({'errormsg': 'Please request with the correct indices.'})
        
        res = es.search(index= all_index_name, size=0, body={
            "query": {
                "bool":{
                    "must":[{"match_phrase": {
                    "id": user_id
                }}],
                    'must_not': [
                        {'match': {'filename': 'None'}}
                    ]

                }
                
            },
        
        })

        return jsonify(res)
    except Exception as e:
        return jsonify({'errormsg':'Something happened in the API route /user_file.'}),403


"""
This route extracts all the forwareded, replied posts from a particular userID.
The user_id is Telegram userID.
"""
@app.route('/get_user_data', methods=['POST'])
@jwt_required
def get_user_data():
    try:
        user_id = request.json.get('user_id', None)
        search_type = request.json.get('search_type', None)
        es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
        
        if user_id == None:
            return jsonify({'errormsg': 'Please request with the correct indices'})
        
        
        default_query = {
            "id": user_id
        }
        
        if search_type == 'forwarded':
            default_query = {
                "forwarderid": user_id
            }
        
        elif search_type == 'replied':
            default_query = {
                "reply": user_id
            }

        res = es.search(index=all_index_name, size=1000, body={
            "query": {
                "term": default_query
            },
        })

        return jsonify(res['hits']['hits'])
    except Exception as e:
        return jsonify({'errormsg': 'Something happened in the API route /get_user_data'})


"""
Counts posts, No.of groups, etc a particular user is in.
Needs a userID parameter to use this route.
The user_id is Telegram userID.
"""
@app.route('/get_user_count', methods=['POST'])
@jwt_required
def get_user_count():
    try:

        user_id = request.json.get('user_id', None)
        
        if user_id == None:
            return jsonify({'errormsg': 'please send correct indices'})
        
        es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
        
        group_res = es.count(index= all_index_name, body={
            "query": {
                "bool": {
                    "must": [
                        {"term": {
                            "id": user_id
                        }},
                        {
                            'term': {"is_group.keyword": {"value": "True"}}}

                    ]
                }

            },

        })
        
        channel_res = es.count(index= all_index_name, body={
            "query": {
                "bool": {
                    "must": [
                        {"term": {
                            "id": user_id
                        }},
                        {
                            'term': {"is_group.keyword": {"value": "False"}}}

                    ]
                }

            },

        })
        
        forwaded_count = es.count(index= all_index_name, body={
            "query": {

                "term": {
                    "forwarderid": user_id
                }},


        })
        
        replied = es.count(index= all_index_name, body={
            "query": {

                "term": {
                    "reply": user_id
                }},
        })

        group_data = group_res['count']
        channel_data = channel_res['count']
        total_data = group_data + channel_data
        forwarded = forwaded_count['count']
        return jsonify({'group': group_data, "channel": channel_data, "total": total_data, "forwarded": forwarded, "replied": replied['count']})
    except Exception as e:
        return jsonify({'errormsg': f'Sorry could not process your request at the moment. Pleasy try again later.'})





''' Search after testing api route'''
@ app.route('/search_after_query', methods=['POST'])
def search_after_query():
    try:
        search = request.json.get('qtext', None)
        index_name = request.json.get('index_name', None)
        start = time.time()
        es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
        all_data = []

        resp = es.search(index=index_name, size=1000, body={
            "query": {
                "match_phrase": {
                    "message": search
                }
            },
            "sort": [
                {"date": "asc"},

            ]

        })
        
        search_after_id = resp['hits']['hits'][-1]['sort']
        all_data = resp['hits']['hits']
        data_res = len(resp['hits']['hits'])
        
        while data_res > 1:
            new_resp = es.search(index=index_name, size=1000, body={
                "query": {
                    "match_phrase": {
                        "message": 'hack'
                    }
                },
                "search_after": search_after_id,
                "sort": [
                    {"date": "asc"},

                ]

            })
            
            if len(new_resp['hits']['hits']) == 0:
                data_res = 0
            else:
                print(len(new_resp['hits']['hits']))
                search_after_id = new_resp['hits']['hits'][-1]['sort']
                data_res = len(new_resp['hits']['hits'])
                all_data = all_data + new_resp['hits']['hits']

        end = time.time()
        finish_time = end-start
        print(end-start)

        return jsonify({'total_docs': len(all_data), 'data': all_data,'execution_time': finish_time})
    except Exception as e:
        return jsonify({'errormsg': f'Sorry could not process your request at the moment. Pleasy try again later.'})

"""
Check if a channel name has a different link.
say, for Hacker News , t.me/hackernews, or t.me/carding
This API was built to correct previous errors on data 
indexed and might be useful later to ensure one channel name 
has one unique link within a short period of time.
"""
@app.route('/get_unique_data', methods=["POST"])
def get_unique_data():
    keyword = request.json['keyword']
    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
    res = es.search(index='telegram2_v2',
                    body={
                        'query': {
                            'match_phrase': {
                                "conv_name": keyword,
                            }
                        },
                        "aggs": {
                            "unique_channels": {
                                "terms": {"field": "link.keyword",

                                          "size": 100}
                            }
                        }
                    }
                    )

    return jsonify({'data': res['aggregations']["unique_channels"]['buckets']})


"""
API to search valid BTC address with funds

to create the index, curl -XPUT ... 


mapping = {
    "mappings": {
        "properties": {
            "wallet_address": {
                "type": "text",
                "fields": {
                    "keyword": {
                        "type":  "keyword"
                    }
                }
            }
        }
    }
}

"""
@app.route("/btc_check", methods=["POST","GET"])
def check_btc_address():
    address = request.json["btc_address"]
    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)

    try:
        res = es.search(index = "btcaddress",body= {"query": { "match" : { "wallet_address" : { "query": address }}}})
        return jsonify({"btc_address": res["hits"]["hits"][0]["_source"]["wallet_address"], "found":"True"}), 200

    except Exception as e:
        return jsonify({"btc_address": "Not Available"}), 404 
    


"""
API requests to dehased.com

"""

@app.route("/v2/breach_search", methods=["POST"])
@jwt_required
def breachdata_search_engine():

    # check frequency of requests, if last recorded time and time now is not less than 1, then API requests are too fast.
    try:
        with open("dehashed_counter.txt","r") as readfile:
            
            time_last = readfile.readlines()[0]
            timediff = datetime.datetime.now(timezone.utc) -  dateutil.parser.isoparse(time_last)
            # print(f"Time difference is {timediff.total_seconds()}")

            if timediff.total_seconds() < 1 :
                return jsonify({"errormsg","Too many requests. Please try again later."}), 403, {'Content-Type': 'application/json'}

    except Exception as e:
        with open("dehashed_counter.txt","w") as writefile:
            writefile.write(datetime.datetime.utcnow().isoformat()+'+00:00')


    index_name_deshashed = 'dehashed_data'
    
    # dehashed.com API 
    API_HASH_DEHASHED = "it19vttzz6wvv3qpu3e60fm4mhjy6dwz"

    rate_limit_breach = 0

    ########################################################################
    # Access the identity of the current user with get_jwt_identity
    jwt_all = get_jwt_identity()
    current_user = jwt_all[0]
    #logging for user acessing routes
    f = open("apilogs.txt", "a", encoding='UTF-8')
    #data_to_log = f'''DATETIME:{datetime.datetime.utcnow()}\nIPADDRESS:{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}\nUsername:{username}\n\n'''
    data_to_log = {"DATETIME":f"{datetime.datetime.utcnow().isoformat()+'+00:00'}","IPADDRESS":f"""{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}""","ENDPOINT":"/v2/breach_search","User": f"{current_user}"}
    f.write(str(data_to_log))
    f.write('\n')
    f.close()
    

    # Function to block usage of old tokens after change of password.
    if check_tokens(jwt_all) != 'successful':
        return check_tokens(jwt_all)[0]
    ########################################################################

    print(f"""{colors.green} User {current_user} has successfully logged. Accessing /v2/breach_search API from IP: {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} {colors.default}""")

    # connecting to the database
    try:
        conn_db = psycopg2.connect(database= 'client_database' , user= database_username , password= database_password , host= host_name, port= db_port)
        conn_db.autocommit = True
        cursor_db = conn_db.cursor()

        query_to_db = f"SELECT breached_ratelimit from client_database where username='{current_user}'"
        cursor_db.execute(query_to_db)
        rate_limit_breach = cursor_db.fetchall()[0][0]

    except Exception as e:
        conn_db.close()
        return jsonify({"errormsg": "Are you registered? Please contact us at tesseract@tesseractintelligence.com"}), 403
    
    if rate_limit_breach < 1:
        return jsonify({"errormsg":"You have reached a rate-limit for breach search. Please contact your service provider."}), 403

    # query
    query = request.json.get('query', None) 
    mode = request.json.get('mode', None)
    search_after_id = request.json.get('search_after_id', None)

    search_mode = 'domain'
    filtered_data = []
    
    if mode == 'domain' or mode == 'email' or mode == 'phone' or mode == 'name' or mode == 'username':
        
        if mode == 'domain':
            search_mode = 'domain'    
            # dehashed_request_statement = f"""curl -sb -XGET 'https://api.dehashed.com/search?query=domain:{query}&size=10000' -u tesseract@tesseractintelligence.com:{API_HASH_DEHASHED}  -H 'Accept: application/json'"""
            checks = re.compile('[`!#$%^&()<>?/\|}{~:,+\]\[]')
            check_domainname = len(re.findall(checks, query))

            if check_domainname != 0:
                return jsonify({"errormsg":"The domain name must not contain quotes or invalid characters. Please only use valid characters."}), 403
            
    
        if mode == 'email':
            
            search_mode = 'email'

            # sanitize email  : Reserved chars - = && || > < ! ( ) { } [ ] ^ " ~ * ? : \
            checks = re.compile('[`!#$%^&()<>?/\|}{~:,+\]\[]')
            check_email = len(re.findall(checks, query))

            if check_email != 0:
                return jsonify({"errormsg":"Emails must not contain quotes or invalid characters. Please only use valid characters."}), 403

        if mode == 'phone':
            search_mode = 'phone'
            
            # sanitize phone  : Reserved chars - = && || > < ! ( ) { } [ ] ^ " ~ * ? : \
            checks = re.compile('[`!#$%^&<>?/\|}{~:,\]\[a-zA-Z]')
            check_phone = len(re.findall(checks, query))

            if check_phone != 0:
                return jsonify({"errormsg":"Phones must not contain quotes or invalid characters. Please only use valid characters."}), 403


        if mode == 'name':
            search_mode = 'name'
            
            # sanitize name : Reserved chars  - = && || > < ! ( ) { } [ ] ^ " ~ * ? : \
            checks = re.compile('[`!#$%^&<>?/\|}{~:,\]\[]')
            check_name = len(re.findall(checks, query))

            if check_name != 0:
                return jsonify({"errormsg":"Name must not contain quotes or invalid characters. Please only use valid characters."}), 403



        if mode == 'username':
            search_mode = 'username'
            
            # sanitize name : Reserved chars  - = && || > < ! ( ) { } [ ] ^ " ~ * ? : \
            checks = re.compile('[`!#$%^&<>?/\|}{~:,\]\[]')
            check_username = len(re.findall(checks, query))

            if check_username != 0:
                return jsonify({"errormsg":"Username must not contain quotes or invalid characters. Please only use valid characters."}), 200

        further_process = False

        try:

            es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
            print('hash_runned')
            hash_id = hashlib.md5(str({'query':query,"mode":mode}).encode('UTF-8')).hexdigest()
            if es.indices.exists(index="dehashed_expiry_tracker"):
                
                if es.exists(index='dehashed_expiry_tracker', id=hash_id):
                    data_checker = es.search(index='dehashed_expiry_tracker', size=10, body={
                        "query":{
                            'bool':{
                                'must':[
                                    {
                                         "term":{
                                            "breached_key.keyword":query
                                        }
                                    },
                                    {
                                         "term":{
                                        "mode.keyword":search_mode
                                    }
                                    }
                                ]
                            }
                           
                        }
                    })

                    if len(data_checker['hits']['hits']) > 0:
                        continue_loop = True
                        try: 
                            total_results = data_checker['hits']['hits'][0]['_source']['total_results']
                            if (total_results) >= 10000:
                                continue_loop = False
                                further_process = False

                        except:
                            pass

                        if continue_loop is True:
                            expiry_date = data_checker['hits']['hits'][0]['_source']['expiry_date']
                            new_dt = parse(expiry_date) + datetime.timedelta(days=7)
                            if new_dt < datetime.datetime.now(timezone.utc):
                                further_process = True
                else:
                    further_process = True
            else:
                es.indices.create(index='dehashed_expiry_tracker', ignore=400)
                further_process = True
                    

            quer = {"query": {'bool':{
                                'must':[
                                    {
                                         "term":{
                                            "query.keyword":query
                                        }
                                    },
                                    {
                                         "term":{
                                        "mode.keyword":search_mode
                                    }
                                    }
                                ]
                            }} }
            if further_process is False:
                if es.indices.exists(index="dehashed_data"):
                    
                    data_checker = es.search(index='dehashed_data', size=200, body=quer)
                    
                    if len(data_checker['hits']['hits']) > 1:
                        quer = {"query":
                             {'bool':{
                                'must':[
                                    {
                                         "term":{
                                            "query.keyword":query
                                        }
                                    },
                                    {
                                         "term":{
                                        "mode.keyword":search_mode
                                    }
                                    }
                                ]
                            }},
                                "sort": [{"doc_hash.keyword": {"order": "desc"}}]}
                    
                else:
                    es.indices.create(index='dehashed_data', ignore=400)
                decode_key = "None"
                try:
                    if search_after_id != None and search_after_id != 'None':
                        search_after_validator = pagination_checker_limiter(current_user)
                        if search_after_validator is False:
                            return jsonify({'errormsg':f'Your Pagination limit is reached. Please contact at {COMPANY_EMAIL} for more information.'}), 403
                        
                        decode_key = cryptocode.decrypt(
                            str(search_after_id), '#random_pass1&*$@')

                    else:
                        pass
                except:
                    print('could not decrypt the provided search after key')

                if decode_key != 'None':
                    try:
                        print('activated')
                        quer['search_after'] = [decode_key]
                    except:
                        print('search after could not ')

                db_data = es.search(index='dehashed_data',size=10000, body=quer)
                
                total_results = 0 
                print(1)
                print('len',len(db_data['hits']['hits']))
            
            else:
                dehash_headers = { "accept": "application/json" }       
                print('activated')
                r = requests.get(f'https://api.dehashed.com/search?query={search_mode}:{query}&size=10000', auth=HTTPBasicAuth('tesseract@tesseractintelligence.com', API_HASH_DEHASHED),headers=dehash_headers)
                print(r.status_code)
                if r.status_code != 200:
                    return {"errormsg":f"Something went wrong with your search.Please try again later"}, 403
                results = r.json()
                
                # requests made to dehashed.com API
                print(results["entries"])
                filtered_data = results["entries"]

                if filtered_data == None :
                    return {"errormsg":f"No results. Please try again after some time."}, 403
                
                total_results = results["total"]
                
                for new_data in filtered_data:
                    new_data['query'] = query
                    new_data['total_data'] = total_results
                    doc_hash = hashlib.md5(str(new_data).encode('UTF-8')).hexdigest()
                    new_data['doc_hash'] = doc_hash
                    new_data['mode'] = search_mode
                    
                    hash_obj = {'id': new_data['id'], 'email': new_data['email'], 'query': query,'mode':search_mode}
                    hashasid = hashlib.md5(str(hash_obj).encode('UTF-8')).hexdigest()
                    
                    es.index(index='dehashed_data',body=new_data, id=hashasid,refresh=True)
                
                print(f"{colors.green} ------------------ reading from Elasticsearch -------------------- {colors.default}")
                db_data = es.search(index='dehashed_data', size=200,  body={"query": {"match_phrase": {"query": query}}, "sort": [{"doc_hash.keyword": {"order": "desc"}}]})
        
            encoded_key = 'None'        
            if len(db_data['hits']['hits']) > 1:

                print(f"{colors.green} ------------------ reading from Elasticsearch -------------------- {colors.default}")
                try:
                    print(db_data['hits']['hits'][-1])
                    encoded_key = cryptocode.encrypt(
                        str(db_data['hits']['hits'][-1]['sort'][0]), '#random_pass1&*$@')
                except Exception as e:
                    print(e)
                
                for hit in db_data['hits']['hits']:
                    hit['_source']['id'] = hit['_id']
                    filtered_data.append(hit["_source"])
                if len(filtered_data) > 0:
                    total_results = filtered_data[0]['total_data']
            
            """
            ____________________________________________________________________________________
            RATE_LIMITING CODE
            ____________________________________________________________________________________
            """
            funcall = rate_limiter(current_user)

            try:
                if int(funcall) >= 0:
                    #print(type(funcall))
                    print(f"{colors.green}No restrictions so far.{colors.default}")
            except Exception as e:
                #print(type(funcall))
                print(f"{colors.red}Restrictions in effect. {funcall[0]} {colors.default}")
                return funcall
                
            ratelimit = funcall

            if current_user != 'administrator':
                # connecting to the database
                try:
                    conn_db = psycopg2.connect(database= 'client_database' , user= database_username , password= database_password , host= host_name, port= db_port)
                    conn_db.autocommit = True
                    cursor_db = conn_db.cursor()

                    rate_limit_breach -= 1 
                    query_to_db = f"UPDATE client_database set breached_ratelimit={rate_limit_breach} where username='{current_user}'"
                    cursor_db.execute(query_to_db)
                except Exception as e:
                    conn_db.close()
                    return jsonify({"errormsg": f"ratelimit update failed for ratelimit at /v2/breach_search Please contact us at tesseract@tesseractintelligence.com "}), 403
                
            breach_ratelimit = rate_limit_breach
            
            customer_type = 'TRIAL_CUSTOMER'
            try:
                conn1 = psycopg2.connect(database='client_database', user=database_username,password=database_password, host=host_name, port=db_port)
                conn1.autocommit = True
                cursor1 = conn1.cursor()
                cursor1.execute(f"SELECT customer_type from client_database where username='{current_user}';")
                conn1.commit()
                
                utype = cursor1.fetchall()
                customer_type = str(utype[0][0])
                conn1.close()
            except Exception as e:
                    conn1.close()
            pass
            if customer_type != 'PAID_CUSTOMER':
                if total_results >= 10000:
                    return jsonify({"errormsg": "There is more than 10,000 results for this query. Please contact us at tesseract@tesseractintelligence.com for more information on this query search or to enable this faeture.",'ratelimit':ratelimit,'breach_ratelimit':breach_ratelimit,'total_results':total_results,'search_id': 'None'}), 403, {'Content-Type': 'application/json'}
                
            ingest_data = {"breached_key":query,"expiry_date":datetime.datetime.now(timezone.utc),'total_results':total_results,'mode':search_mode}
            es.index(index='dehashed_expiry_tracker',  body=ingest_data,id = hash_id)
            
            redis_file_saver = 'None'
            if len(filtered_data) > 1:
                redis_file_saver = redis_data_saver({'data': filtered_data}, 1, query)

            # if filtered_data == []:
            #     filtered_data = ['No results. Please try again after some time.']
            #     filtered_data.append({"ratelimit":funcall})
            #     filtered_data.append({"breach_ratelimit":rate_limit_breach})
            #     filtered_data.append({"total_results": 0 })
            # else:
            #     filtered_data.append({"total_results":total_results})
            #     filtered_data.append({"ratelimit":funcall})
            #     filtered_data.append({"breach_ratelimit":rate_limit_breach,"Information":"Breach data search quota also decreases with your account search quota even if you search within breach only."})

            return jsonify({'data':filtered_data,'ratelimit':ratelimit,'breach_ratelimit':breach_ratelimit,'total_results':total_results,'search_id': encoded_key,'file_id': redis_file_saver}), 200, {'Content-Type': 'application/json'}
        except Exception as e:
            print(e)
            return {"errormsg":f"No results. Please try again after some time. "}, 403
            
    else:
        return jsonify({"errormsg","Only domain names,emails,phones,username and name (e.g Adam Smith) are allowed."}), 403



"""
Download breached data report from /v2/breach_search
as a .CSV file.
"""
@app.route('/breach_download', methods=['POST'])
@jwt_required
def dehashed_download():

    size_of_download = 10000 # put anywhere between 1 and 10000

    ########################################################################
    # Access the identity of the current user with get_jwt_identity
    jwt_all = get_jwt_identity()
    current_user = jwt_all[0]

    # Function to block usage of old tokens after change of password.
    if check_tokens(jwt_all) != 'successful':
        return check_tokens(jwt_all)[0]
    ########################################################################

    query = request.json.get('query')
    
    if query == None:
        return jsonify({'errormsg', 'please send valid query'}), 403
    
    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
    count_res = es.count(index='dehashed_data', body={
                        "query": {"match_phrase": {"query": query}}})
    
    # Not allowing downloads on query that results more than 10000 posts
    if count_res['count'] > 10000:
        return jsonify({'errormsg':'Please contact us at tesseract@tesseractintelligence.com to enable this feature.'})
    
    db_data = es.search(index='dehashed_data', size= size_of_download, body={
                        "query": {"match_phrase": {"query": query}}})
    
    if len(db_data['hits']['hits']) < 1:
        return jsonify({'errormsg', 'Sorry, could not download the file'}), 403
    else:
        program_path = os.getcwd()
        os.chdir(folder_create())
        file_name = f'{query}_breached_data.csv'
        
        if '.' in query:
            new_file_name = query.replace('.', '_')
            file_name = f'{new_file_name}_breached_data.csv'
        print(file_name)
        
        rows_name = ['Domain Name', 'ID', 'Database',
                     'Email', 'Username', "Name", 'Password', 'Hashed Password', 'Phone', 'Address', 'Ip Address']
        
        with open(file_name, 'w', encoding='UTF-8') as csvfile:
            csvwriter = csv.writer(csvfile)
            csvwriter.writerow(rows_name)
            
            for data in db_data['hits']['hits']:
                main_parent = data['_source']
                domain = main_parent['query']
                id = main_parent['id']
                database = main_parent['database_name']
                email = main_parent['email']
                username = main_parent['username']
                name = main_parent['name']
                password = main_parent['password']
                hashed_password = main_parent['hashed_password']
                phone = main_parent['phone']
                address = main_parent['address']
                ip_address = main_parent['ip_address']
                data_row = [domain, id, database, email, username, name,
                            password, hashed_password, phone, address, ip_address]
                csvwriter.writerow(data_row)
        
        os.chdir(program_path)
        print(file_name)
        safe_path = safe_join(r'/root/csv_reports/', file_name)
        print(safe_path)
        
        try:
            return send_file(safe_path, as_attachment=True)
        except FileNotFoundError:
            return jsonify({'errormsg': 'Sorry could not retrieve file, Please try again later.'}), 403   

# script for extracting forwarded links presnet of a aprticular channel:
@ app.route('/channel_forwaded_post', methods=['POST'])
@jwt_required
def channel_forwaded_post():
    qtext = request.json.get('qtext', None)
    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)

    try:
        forwarded = es.search(index=all_index_name, size=1000, body={

            'query': {

                'match_phrase': {
                    'forwardedfromchanid': qtext
                },

            },


        })
        return_list =[]
        for hit in forwarded['hits']['hits']:
                #print("inloop")
                return_list.append(hit["_source"])
                #print(return_list)
        return jsonify({'data':return_list})
    except Exception as e:
        return jsonify({'error': e})


"""
API to command scrapers to pause/resume 


Request Example:

to pause:

```
curl -H 'Content-Type: application/json' -d '{"status":"pause"}' https://api.recordedtelegram.com/pause_scrapers
```
and to resume,

```
curl -H 'Content-Type: application/json' -d '{"status":"resume"}' https://api.recordedtelegram.com/pause_scrapers
```

"""
@ app.route('/pause_scrapers', methods=['POST'])
def pause_scrapers():
    try:
        
        qtext = request.json.get('status', None)
        request_from = f"""Request for {qtext} from IP {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} on {datetime.datetime.utcnow().isoformat()+'+00:00'}"""
        
        with open("scraper_pause_records.txt","a") as records:
            records.write(request_from)
            records.write("\n")

        if qtext == "resume":
            r = redis.Redis(host='localhost', port= 6379, db=0)
            r.set("GLOBAL_PAUSE", b'FALSE' )
            print(f"{colors.green}---------------------------------------\nCleaning up REDIS-Cache.\n---------------------------------------\n{colors.green}")
            return jsonify({"message":f"successfully resumed. Request was sent from IP address {request_from}"}), 200    
        
        if qtext == "pause":
            r = redis.Redis(host='localhost', port= 6379, db=0)
            r.set("GLOBAL_PAUSE", b'TRUE' )
            print(f"{colors.green}---------------------------------------\nSETTING REDIS-Cache.\n---------------------------------------\n{colors.green}")
            return jsonify({"message":f"successfully pausing.. Please do not forget to resume after some time. Your IP address was logged for performing this operation."}), 200
        
        return jsonify({"errormsg":f"Please enter the right command. resume or pause. Request sent from {request_from} "}), 200
    except Exception as e:
        return jsonify(str(e)), 200

#note its temporary field for ecxtracting file data should be deleted later
@app.route('/file_struct', methods=["POST"])
def file_struct():
    keyword = request.json.get('keyword')
    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
    total_doc = es.count(index=all_index_name,  body={
                'query': {
                               "match_phrase":{
                                   "filename":keyword
                               }
                          
                           },
        })
    print(total_doc['count'])
    main_num = 1
    
    new_num = round(total_doc['count'] / 10000)
    if new_num > 1 :     
        main_num = new_num
    
    all_data = []
    for i in range(main_num):
        # es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
            channel_query = es.search(index=all_index_name, size=10000, body={
                'query': {
                               "match_phrase":{
                                   "filename":keyword
                               }
                          
                           },
                "aggs": {
                    "unique_channels": {
                        "terms": {"field": "link.keyword",
                                "include": {
                                    "partition": i,
                                    "num_partitions": main_num
                                },
                                "size": 10000}
                    }
                }


            })
       
            response = channel_query
            new_res = response['aggregations']["unique_channels"]['buckets']
            for i in new_res:
                all_data.append(i)

    return jsonify({'data':all_data,'total_docs':total_doc['count']})


# Note: This is a temporray route so sould be deleted later function:counting all the data from file keyword
@app.route('/file_data_counter', methods=["POST"])
def file_data_counter():
    keyword = request.json.get('keyword')
    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
    total_doc = es.count(index=all_index_name, body={
        'query': {
                               "match_phrase": {
                                   "filename": keyword
                               }

        },
    })
    return jsonify({'total_docs': total_doc['count']})


# Note: This is a temporray route so sould be deleted later function:extract all the data from file keyword
@app.route('/file_data_extractor', methods=["POST"])
def file_data_extractor():
    keyword = request.json.get('keyword')
    index_name = request.json.get('index_name', None)
    search_after_id = request.json.get('search_after_id', None)
    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)

    decode_key = "None"
    try:
        if search_after_id != None and search_after_id != 'None':
            decode_key = search_after_id
    except:
        print('could not intiate the provided search after key')
  
    quer = {
        'query': {
            "match_phrase": {
                "filename": keyword
            }

        },
        "sort": [{"date": {"order": f"desc"}}]
    }
    if decode_key != 'None':
        try:
            print('activated')
            quer['search_after'] = [decode_key]
        except:
            print('search after could not ')
    

    channel_query = es.search(
        index=index_name, size=3000, body=quer)
    encoded_key = 'None'
    try:
        if len(channel_query['hits']['hits']) > 1:
            encoded_key = channel_query['hits']['hits'][-1]['sort'][0]
    except:
        print('could not encrypr/add search after key')
    return_list = []
    for hit in channel_query['hits']['hits']:
        return_list.append(hit["_source"])
    return jsonify({'data': return_list, 'search_id': encoded_key})


"""
Indexing Route for Telethon based data from different servers to Elasticsearch
TODO : Change the index_name wherever required

Note: Please do not document this route in the API documentation. Not for customers.
"""
@app.route('/v2/t_indexer/<category_name>', methods=['POST'])
def t_indexer(category_name):
    
    # elasticsearch client initiate
    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)

    try:

        if category_name == "science_index":
            index_name="science_index_alias"

        if category_name == "betting_gambling":
            index_name="betting_gambling_alias"

        if category_name == "adult_content":
            index_name="adult_content_alias"
        
        if category_name == "blogs_vlogs":
            index_name="blogs_vlogs_alias"
        
        if category_name == "education":
            index_name="education_alias"
        
        if category_name == "movies":
            index_name="movies_alias"
        
        if category_name == "travelling":
            index_name="travelling_alias"
        
        if category_name == "gaming":
            index_name="gaming_alias"
        
        if category_name == "music":
            index_name="music_alias"
        
        if category_name == "lifestyle":
            index_name="lifestyle_alias"
        
        if category_name == "books_comics":
            index_name="books_comics_alias"
        
        if category_name == "fashion_beauty":
            index_name="fashion_beauty_alias"
        
        if category_name == "design_arch":
            index_name = "design_arch_alias"
        
        if category_name == "humor_entertainment":
            index_name = "humor_entertainment_alias"
        
        if category_name == "culture_events":
            index_name = "culture_events_alias"

        if category_name == "criminal_activities":
            index_name = "criminal_activities_alias"

        if category_name == "hacking":
            index_name = "telegram2_alias"

        if category_name == "political":
            index_name = "extremepolitical2_alias"

        if category_name == "financials":
            index_name = "financials"

        if category_name == "pharma_drugs":
            index_name = "pharma_drugs_alias"

        if category_name == "religion_spirituality":
            index_name = "religion_spirituality_alias"

        if category_name == "information_technology":
            index_name = "information_technology"

        if category_name == "cyber_security":
            index_name = "cyber_security_alias"
        
        try:
            qtext = request.get_json()

            if qtext == None:
                return jsonify({"errormsg":"data is in wrong format, please check again."})
        except Exception as e:
            return str(e)

        print("Query->", qtext)
        request_from = f"""Request for {qtext} from IP {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} on {datetime.datetime.utcnow().isoformat()+'+00:00'}"""

        # commenting to save server space 
        # with open("crawlerlogs.txt","a") as records:
        #     records.write(request_from)
        #     records.write("\n")

        docx1 = json.loads(qtext)
        print(f"""{colors.cyan} {type(docx1)} {docx1} {colors.default}""")

        docx2 = ''
        # hashing data
 
        try:
            print("hashing")
            docx2 = str({"date":docx1['date'],"message":docx1['message'],"msgid":docx1['msgid']})
            print("selected..now hasing.")
            hashasid = hashlib.md5(docx2.encode('UTF-8')).hexdigest()
            print("hashed...")
            print(hashasid)

            if REINDEXING_FOR_UPDATE == False:
                index_unpresence = index_hex_id_checker(hashasid)
            else:
                index_unpresence = True

            if index_unpresence == False:                      
                return jsonify({"message":f"Document with hashid {hashasid} already exists."}), 200    
            else:
                # # overriding telegram2 with telegram2_v2 as it was removed on 14.JULY.2022. Reason: Index unreachable , went red.
                # if index_name == "telegram2":
                #     index_name = f"{index_name}_v2"

                # res = es.index(index= index_name , body=docx1, id = hashasid)
                # print(f"{colors.blue} Result -> {res['result']} with id {hashasid} {colors.default}")
               
                try:
                    docx1['msgid'] = int(docx1['msgid'])
                    print("hashing")
                    docx2 = str({"date":docx1['date'],"message":docx1['message'],"msgid":docx1['msgid']})
                    print("selected..now hasing.")
                    hashasid = hashlib.md5(docx2.encode('UTF-8')).hexdigest()
                    print("hashed...")
                    print(hashasid)
                    res = es.index(index= f"{index_name}" , body=docx1, id = hashasid)
                    print(f"{colors.blue} Result from V2 -> {res['result']} with id {hashasid} {colors.default}")
                except Exception as e:
                    return jsonify({"errormsg":f"Error while indexing to new index on {index_name} {datetime.datetime.utcnow().isoformat()}+00:00"}), 200

            return jsonify({"message":f"successfully {res['result']} with hashid {hashasid} on {datetime.datetime.utcnow().isoformat()}+00:00"}), 200 

        except Exception as e:
            print(f"{colors.red}hashing failed. logging error to error_indexing_dbtoindex_v1.log {e} {colors.default}")

            # record data that could not be indexed
            with open('error_indexing_dbtoindex_v1.log','a') as indexingerror:
                indexingerror.write(docx2)
                indexingerror.write('\n')
            
            return jsonify({"errormsg":f"something happened while indexing. at /v2/t_indexer : inside loop {e}"}), 200 

    except Exception as e:
        return jsonify({"errormsg":f"something happened while indexing. at /v2/t_indexer {e} "}), 200

#route for extracting users info fromn id 
@app.route('/user_info_data', methods=['POST'])
@jwt_required
def get_specific_user():
    user_id = request.json.get('userid', None)
    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
    if user_id == None:
        return jsonify({'errormsg': 'No such data'}), 403
    else:
        res = es.search(index="onlineusers", size=1, body=({
            "query": {
                "term": {
                    "userid": user_id
                }
            }
        }))
        return_list = []
        if len(res['hits']['hits']) > 0:
            return_list.append(res['hits']['hits'][0]['_source'])

        return jsonify({'data': return_list})


"""
Generates csv file of the provided user_id
"""

@app.route('/user_id_csv_report', methods=["POST"])
@jwt_required
def user_id_csv_report(index_name):
    try:
        user_id = request.json.get('userid', None)
        search_type = request.json.get('search_type', 'None')
        es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)

        if user_id == None:
            return jsonify({'errormsg': 'Please request with the correct indices'}), 403

        default_query = {
            "id": user_id
        }

        if search_type == 'forwarded':
            default_query = {
                "forwarderid": user_id
            }

        elif search_type == 'replied':
            default_query = {
                "reply": user_id
            }

        res = es.search(index=all_index_name, size=1000, body={
            "query": {
                "term": default_query
            },
        })

        return_list = []

        for hit in res['hits']['hits']:
            return_list.append(hit["_source"])
        if len(return_list) < 1:
            return jsonify({f'errormsg': 'Sorry No Data available for user {user_id}'}),403

        file_name = f'{user_id}_{search_type}.csv'

        program_path = os.getcwd()
        os.chdir(folder_create())

        with open(file_name, 'w', encoding='UTF-8') as csvfile:
            csvwriter = csv.writer(csvfile)
            csvwriter.writerow(['UserId', 'Channel_Name', 'Posts      ',
                                "Channel_or_Group", 'Post_Uploaded_Date', 'Link'])

            for data in return_list:
                userid = user_id
                channel_name = data['conv_name']
                posts = data['message']
                post_uploaded_date = data['date']
                link = data['link']
                post_id = data['msgid']
                new_link = channel_id_adder(link, post_id)
                is_group = 'Group'

                try:
                    if data['is_group'] == 'False':
                        is_group = 'Channel'
                except:
                    pass

                data_row = [userid, channel_name, posts,
                            is_group, post_uploaded_date, new_link]
                csvwriter.writerow(data_row)

        os.chdir(program_path)
        safe_path = safe_join( r'/root/csv_reports/', file_name)

        try:
            return send_file(safe_path, as_attachment=True)
        except FileNotFoundError:
            return jsonify({'errormsg': f'Sorry Could not generate file for the user:{user_id}'}),403
    except Exception as e:
        os.chdir(program_path)
        return jsonify({'errormsg': f'Something happened in the route /report_generator'}), 403



@app.route('/v2/profile_search', methods=["POST"])
@jwt_required
@category_access_decorator
def profile_search(index_name):
    # Access the identity of the current user with get_jwt_identity
    jwt_all = get_jwt_identity()
    current_user = jwt_all[0]

    #logging for user acessing routes
    f = open("apilogs.txt", "a", encoding='UTF-8')
    #data_to_log = f'''DATETIME:{datetime.datetime.utcnow()}\nIPADDRESS:{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}\nUsername:{username}\n\n'''
    data_to_log = {"DATETIME":f"{datetime.datetime.utcnow().isoformat()+'+00:00'}","IPADDRESS":f"""{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}""","ENDPOINT":"/v2/profile_search","User": f"{current_user}"}
    f.write(str(data_to_log))
    f.write('\n')
    f.close()


    # Function to block usage of old tokens after change of password.
    if check_tokens(jwt_all) != 'successful':
        return check_tokens(jwt_all)[0]

    
    """
    ____________________________________________________________________________________
    RATE_LIMITING CODE
    ____________________________________________________________________________________
    """
    funcall = rate_limiter(current_user, channelsearch_ratelimit=True)
    print(funcall)

    try:
        if int(funcall[0]) >= 0:
            if int(funcall[1]) >= 0:
                print(f"{colors.green}No restrictions so far. {funcall} {colors.default}")
            else:
                return {"errormsg":"you have consumed your monthly channel/group profile search ratelimit. Please contact your support for more information."}, 403
    except Exception as e:
        #print(type(funcall))
        print(f"{colors.red}Restrictions in effect. {funcall} {colors.default}")
        return funcall

    if not request.is_json:
        return jsonify({"errormsg": "Missing JSON in request"}), 400   
    qtext = request.json.get('qtext', None)
    max_results = request.json.get('max', None)
    fuzzie = request.json.get('fuzzing', 0)
    sort_order = request.json.get('sort_order', None)
    select_group = request.json.get('select_field', None)
    search_type = request.json.get('search_type', None)
    search_filter = request.json.get('search_filter', None)
    search_after_id = request.json.get('search_after_id', None)
    api_mode = request.json.get('api_mode', None)

    if not str(max_results).isnumeric() or max_results > 25:
            return jsonify({"errormsg":"You can not enter special characters inside the field that needs a number, or you want more than 25 results, which is forbidden. API v2.0.3 Mode 1"}),403

    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True) # include hostnames if different Elasticserver, e.g Elasticsearch(['192.168.1.20'])
    print(select_group)
    try:
        qtext = qtext.lower()
    except:
        pass

    fields_selected = "link"

    ''' fields filter based on post/titlefilter'''
    user_list = []
    if select_group == 'conv_name':
        print('found')
        fields_selected = "conv_name"

    if qtext == 'None':
        max_results = 20

    default_slop = 0
    if ' ' in qtext and search_filter == 'contains':
        default_slop = 100

    default_search_filter = {'terms': {"is_group.keyword":  ["True", "False"]}}
    if search_type == 'group':
        default_search_filter = {
            'term': {"is_group.keyword": {"value": "True"}}}
    elif search_type == 'channel':
        default_search_filter = {
            'term': {"is_group.keyword": {"value": "False"}}}

    # by Deafult the search query will be for exact anjd slop will be 0
    default_search_query = {"match_phrase": {
        fields_selected: {
            'query': qtext, 'slop': default_slop
        }
    }}

    # contains filter for regex and partial match
    if search_filter == 'contains' and ' ' not in qtext:
        default_query = 'prefix'
        if '*' in qtext:
            default_query = 'wildcard'

        default_search_query = {
            default_query: {
                fields_selected: qtext

            }
        }
    
    if api_mode == 2:
        default_search_query = {"regexp": {
        regex_validator(qtext, fields_selected) : {"value": f"""{qtext}""", "flags": "ALL",
                                                                     "case_insensitive": "true", "max_determinized_states": 10000, "rewrite": "constant_score"}
    }}

    if sort_order != 'desc' and sort_order != 'asc':
        return jsonify({"errormsg": "sort_order can only be either asc or desc. API route /v2/profile_search"}), 403

    decode_key = "None"
    if search_after_id != None and search_after_id != 'None':
        search_after_validator = pagination_checker_limiter(current_user)
        if search_after_validator is False:
            return jsonify({'errormsg':f'Your Pagination limit is reached. Please contact at {COMPANY_EMAIL} for more information.'}), 403
                        
        decode_key = cryptocode.decrypt(
            str(search_after_id), '#random_pass1&*$@')
    # default_search_query = {"prefix": {fields_selected: qtext}}

    quer = {"size": max_results, "query": {"bool": {"must": [default_search_query, default_search_filter]}},
            "aggs": {
        "unique_post": {
            "terms": {
                "field": f"{fields_selected}.keyword",
                "size": 10000
            },
            "aggs": {
                "top_unique_hits": {
                    "top_hits": {
                        "sort": [
                            {
                                "_score": {
                                    "order": "desc"
                                }
                            }
                        ],
                        "size": 1
                    }
                }
            }

        }
    }, "sort": [{"date": {"order": f"{sort_order}"}}]}
    print(quer)
    count_quer = {
        "query": {"bool": {"must": [default_search_query, default_search_filter]}}}

    if decode_key != 'None':

        quer['search_after'] = [decode_key]

    # es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
    res = es.search(index=index_name,
                    body=quer)
    doc_count = es.count(index=index_name,
                         body=count_quer)

    encoded_key = 'None'
    if len(res['hits']['hits']) > 1:
        encoded_key = cryptocode.encrypt(
            str(res['hits']['hits'][-1]['sort'][0]), '#random_pass1&*$@')

    return_list = []
    scroll_auth = scroll_auth_extractor(current_user)

    duplicate_checker = []
    for hit in res['aggregations']['unique_post']['buckets']:
        duplicate_filter = 'conv_name'
        if fields_selected == 'conv_name':
            duplicate_filter = 'link'
        new_obj = hit['top_unique_hits']['hits']['hits'][0]['_source']
        new_obj['total_data'] = hit['doc_count']
        if new_obj[duplicate_filter] not in duplicate_checker:
            duplicate_checker.append(new_obj[duplicate_filter])
            return_list.append(new_obj)

    if return_list == []:
                return_list = ['No results. Please try again after some time.']

    total_doc_count = 0
    try:
        total_doc_count = len(return_list)
    except:
        pass
    print(duplicate_checker)

    if len(return_list) > 25:
        return_list = return_list[0:25]
    
    return json.dumps({'data': return_list, 'total_db_data': total_doc_count, 'search_id': encoded_key,'scroll_auth':scroll_auth,'rate_limit':funcall}, ensure_ascii=False, indent=0, sort_keys=False).encode('utf-8'), 200, {'Content-Type': 'application/json'}

@app.route('/update_index_file', methods=["POST"])
def update_index_file():
    try:
        es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
        hash_id = request.json.get('hash_id', None)
        file_name = request.json.get('file_name', None)
        file_hash = request.json.get('file_hash', None)
        username = request.json.get('username', None)
        if hash_id == None or file_name == None or file_hash == None or username == None:
            return jsonify({'errormsg': 'Please send correct indices'}), 403

        index_name = 'telegram2_alias'
        try:
            if es.exists(index="financials", id=hash_id):
                index_name = 'financials'

            
            elif es.exists(index="telegram2_alias", id=hash_id):
                index_name = 'telegram2_alias'

            elif es.exists(index="extremepolitical2_alias", id=hash_id):
                index_name = 'extremepolitical2'
            else:
                return jsonify({'errormsg': 'Please send correct hashid as it could not be found'}), 403

        except Exception as e:
            print(e, 'error')

        source_to_update = {
            "doc": {
                "filehash": file_hash,
                "filename": file_name,
                'userdetails': username

            }
        }
        response = es.update(index=index_name,
                             id=hash_id, body=source_to_update)

        return jsonify({'data': response})
    except:
        return jsonify({'errormsg': 'Sorry could nor update the file'}), 403

@app.route('/get_file_hash', methods=['POST'])
def get_file_hash():
    try:
        es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
        hash_id = request.json.get('hash_id', None)

        if hash_id == None:
            return jsonify({'errormsg': 'Please send file hash id'})

        if es.indices.exists(index="file_hash_info"):
            print('index found')
            pass
        else:
            es.indices.create(index='file_hash_info', ignore=400)

        if es.exists(index="file_hash_info", id=hash_id):
            res1 = es.get(index="file_hash_info", id=hash_id)
            return jsonify({'message': 'True','file_hash':res1['_id']})
        else:
            return jsonify({'message': 'False'})
    except:
        return jsonify({'message': 'Sorry could not detacte any such hash id'})


@app.route('/file_hash_indexer', methods=['POST'])
def file_hash_indexer():
    try:
        es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)

        hash_id = request.json.get('hash_id', None)
        filename = request.json.get('filename', None)
        if hash_id == None:
            return jsonify({'errormsg': 'Please send file hash id'})
        res = es.index(index='file_hash_info',
                       body={
                           'hash_id': hash_id,
                           'filename': filename,
                           'date': datetime.datetime.utcnow()
                       }, id=hash_id)
        return jsonify({'message': 'Sucessfully indexed'})
    except:
        return jsonify({'errormsg': 'Sorry could not index the data'})



@app.route('/v2/category_data_count', methods=["GET"])
def category_data_count():

    index_name = "telegram2_alias"
    # es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
    total_group_res = es.count(index= ["telegram2_alias","financials_alias","extremepolitical2_alias","religion_spirituality_alias","pharma_drugs_alias","criminal_activities_alias","information_technology","cyber_security_alias"],
                body={
                    "query": {
                        "match": {
                            "is_group": 'True'
                        }
                    }
                })
    
    total_channel_res = es.count(index= ["telegram2_alias","financials_alias","extremepolitical2_alias","religion_spirituality_alias","pharma_drugs_alias","criminal_activities_alias","information_technology","cyber_security_alias"],
                body={
                    "query": {
                        "match": {
                            "is_group": 'False'
                        }
                    }
                })
    hacking_group_res = es.count(index= index_name,
                body={
                    "query": {
                        "match": {
                            "is_group": 'True'
                        }
                    }
                })
    
    hacking_channel_res = es.count(index= index_name,
                body={
                    "query": {
                        "match": {
                            "is_group": 'False'
                        }
                    }
                })
    
    poltical_group_res = es.count(index= "extremepolitical2_alias",
                body={
                    "query": {
                        "match": {
                            "is_group": 'True'
                        }
                    }
                })
    
    political_channel_res = es.count(index= "extremepolitical2_alias",
                body={
                    "query": {
                        "match": {
                            "is_group": 'False'
                        }
                    }
                })
    finacial_group_res = es.count(index= "financials_alias",
                body={
                    "query": {
                        "match": {
                            "is_group": 'True'
                        }
                    }
                })
    
    financial_channel_res = es.count(index= "financials_alias",
                body={
                    "query": {
                        "match": {
                            "is_group": 'False'
                        }
                    }
                })
    spiritual_group_res = es.count(index= "religion_spirituality_alias",
                body={
                    "query": {
                        "match": {
                            "is_group": 'True'
                        }
                    }
                })
    
    spiritual_channel_res = es.count(index= "religion_spirituality_alias",
                body={
                    "query": {
                        "match": {
                            "is_group": 'False'
                        }
                    }
                })
    pharma_group_res = es.count(index= "pharma_drugs_alias",
                body={
                    "query": {
                        "match": {
                            "is_group": 'True'
                        }
                    }
                })
    
    pharma_channel_res = es.count(index= "pharma_drugs_alias",
                body={
                    "query": {
                        "match": {
                            "is_group": 'False'
                        }
                    }
                })
    criminal_group_res = es.count(index= "criminal_activities_alias",
                body={
                    "query": {
                        "match": {
                            "is_group": 'True'
                        }
                    }
                })
    
    criminal_channel_res = es.count(index= "criminal_activities_alias",
                body={
                    "query": {
                        "match": {
                            "is_group": 'False'
                        }
                    }
                })
    information_technology_group_res = es.count(index= "information_technology_alias",
                body={
                    "query": {
                        "match": {
                            "is_group": 'True'
                        }
                    }
                })
    
    information_technology_channel_res = es.count(index= "information_technology_alias",
                body={
                    "query": {
                        "match": {
                            "is_group": 'False'
                        }
                    }
                })
    
    
    send_res = {
            "Hacking":{
                "No.of total channel posts avaialable": hacking_channel_res['count'],
                "No.of total group posts avaialable": hacking_group_res['count']
            },
            "Political":{
                "No.of total channel posts avaialable": political_channel_res['count'],
                "No.of total group posts avaialable": poltical_group_res['count']
            },
            "Financials":{
                "No.of total channel posts avaialable": financial_channel_res['count'],
                "No.of total group posts avaialable": finacial_group_res['count']
            },
            "Spiritual and Religious":{
                "No.of total channel posts avaialable": spiritual_channel_res['count'],
                "No.of total group posts avaialable": spiritual_group_res['count']
            },
            "Criminal Activities":{
                "No.of total channel posts avaialable": criminal_channel_res['count'],
                "No.of total group posts avaialable": criminal_group_res['count']
            },
            "Pharma and Drugs":{
                "No.of total channel posts avaialable": pharma_channel_res['count'],
                "No.of total group posts avaialable": pharma_group_res['count']
            },
            "Information Technology":{
                "No.of total channel posts avaialable": information_technology_channel_res['count'],
                "No.of total group posts avaialable": information_technology_group_res['count']
            }
        }
    
    
    # response = res['hits']['hits']
    
    return jsonify({'data': send_res})


@app.route('/v2/user_indexer', methods=['POST'])
def user_indexer():
    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
    index_name = 'onlineusers2'
    if not request.is_json:
        return jsonify({"errormsg": "Missing JSON in request"}), 403
    secret_code = request.json.get('passcode', None)
    data = request.json.get('data', None)

    if secret_code == None:
        return jsonify({"errormsg": "Uh oh, careful with the fields in your request. It has to be exactly 'secret_code'."}), 403

    if data == None:
        return jsonify({"errormsg": "Uh oh, careful with the fields in your request. It has to be exactly 'data'."}), 403

    if secret_code == '@lazlxEtIcS3A9rchIydzXiqg2u21fr0m':
        pass
    else:
        return jsonify({"errormsg": "Please enter the correct secret_code"}), 403

     # Creating IDs to make sure the indexed data is not repeated
    tomakeid = str({"userid": data["userid"], "username": data["username"],
                   "userfirstname": data["userfirstname"], "userlastname": data["userlastname"]})
    # print(tomakeid)
    hashasid = hashlib.md5(tomakeid.encode('UTF-8')).hexdigest()
    try:
        print(hashasid)
        es.get(index=index_name, id=hashasid)
        return jsonify({"info": "Data already indexed before. Try something else."}), 200
    except Exception as e:
        try:
            res = es.index(index=index_name, id=hashasid, body=data)
            return jsonify({"info": f"Data eith id:{hashasid} sucessfully  indexed"}), 200
        except:
            return jsonify({"info": "Data could not be  indexed."}), 403

@app.route('/single_user_checker', methods=['POST'])
def single_user_checker():
    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
    secret_code = request.json.get('passcode', None)
    data = request.json.get('data', None)

    if secret_code == None:
        return jsonify({"errormsg": "Uh oh, careful with the fields in your request. It has to be exactly 'secret_code'."}), 403

    if data == None:
        return jsonify({"errormsg": "Uh oh, careful with the fields in your request. It has to be exactly 'data'."}), 403

    if secret_code == '@lazlxEtIcS3A9rchIydzXiqg2u21fr0m':
        pass
    else:
        return jsonify({"errormsg": "Please enter the correct secret_code"}), 403

    tomakeid = str({"userid": data["userid"], "username": data["username"],
                   "userfirstname": data["userfirstname"], "userlastname": data["userlastname"]})
    hashasid = hashlib.md5(tomakeid.encode('UTF-8')).hexdigest()

    try:
        res1 = es.get(index="onlineusers", id=hashasid)
    except:
        return jsonify({"info": "Data could not be  found."}), 403




@app.route('/all_user_extraxtor', methods=['POST'])
def all_user_extraxtor():
    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
    search_after_id = request.json.get('search_after_id', None)
    secret_code = request.json.get('passcode', None)

    if secret_code == '@lazlxEtIcS3A9rchIydzXiqg2u21fr0m':
        pass
    else:
        return jsonify({"errormsg": "Please enter the correct secret_code"}), 403

    decode_key = "None"
    try:
        if search_after_id != None and search_after_id != 'None':
            decode_key = search_after_id
    except:
        print('could not intiate the provided search after key')

    quer = {
        'query': {
            "match_all": {}

        },
        "sort": [{"dateofrecording": {"order": f"desc"}}]
    }
    if decode_key != 'None':
        try:
            print('activated')
            quer['search_after'] = [decode_key]
        except:
            print('search after could not ')

    channel_query = es.search(
        index='onlineusers', size=1000, body=quer)
    encoded_key = 'None'
    try:
        if len(channel_query['hits']['hits']) > 1:
            encoded_key = channel_query['hits']['hits'][-1]['sort'][0]
    except:
        print('could not encrypt/add search after key')
    return_list = []
    for hit in channel_query['hits']['hits']:
        return_list.append(hit["_source"])
    return jsonify({'data': return_list, 'search_id': encoded_key})

@app.route('/get_last_post', methods=["POST"])
def get_last_post():
    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
    secret_code = request.json.get('passcode', None)
    if secret_code == None:
        return jsonify({"errormsg": "Uh oh, careful with the fields in your request. It has to be exactly 'secret_code'."}), 403

    if secret_code == '@lazlxEtIcS3A9rchIydzXiqg2u21fr0m':
        pass
    else:
        return jsonify({"errormsg": "Please enter the correct secret_code"}), 403
    keyword = request.json.get('keyword', None)
    index_name = request.json.get('index', None)

    new_index_name = index_name
    if index_name == None or index_name == "None":
        new_index_name = all_index_name

    new_link = channel_name_converter(keyword)
    
    if keyword == None or index_name == None:
        return jsonify({"errormsg": "Uh oh, careful with the fields in your request. It has to be exactly"}), 403

    res = es.search(index= new_index_name, size=1,
                    body={
                        'query': {
                             "terms": {
                        "link": new_link,


                    }},
                        "sort": [{"date": {"order": f"desc"}}]
                    }

                    )
    latest_msg_id = 'None'
    message = 'False'
    if len(res['hits']['hits']) > 0:
        try:
            latest_msg_id = res['hits']['hits'][0]['_source']['msgid']
            message = 'True'
        except:
            message = 'False'

    return jsonify({'message': message, 'msg_id': latest_msg_id})


@app.route('/telethon/get_last_post', methods=["POST"])
def telethon_get_last_post():
    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
    secret_code = request.json.get('passcode', None)
    if secret_code == None:
        return jsonify({"errormsg": "Uh oh, careful with the fields in your request. It has to be exactly 'secret_code'."}), 403

    if secret_code == '@lazlxEtIcS3A9rchIydzXiqg2u21fr0m':
        pass
    else:
        return jsonify({"errormsg": "Please enter the correct secret_code"}), 403
    keyword = request.json.get('keyword', None)
    index_name = request.json.get('index', None)
    search_type = request.json.get('search_type',None)
    new_link = channel_name_converter(keyword)
    if keyword == None or index_name == None:
        return jsonify({"errormsg": "Uh oh, careful with the fields in your request. It has to be exactly"}), 403
    default_query = {
                             "terms": {
                        "link": new_link,
                    }}
    if search_type == 'telethon':
        default_query = {
                             "term": {
                        "to_id": keyword,
                    }}

    res = es.search(index=all_index_name, size=1,
                    body={
                        'query': default_query,
                        "sort": [{"date": {"order": f"desc"}}]
                    }

                    )
    latest_msg_id = 'None'
    message = 'False'
    if len(res['hits']['hits']) > 0:
        try:
            latest_msg_id = res['hits']['hits'][0]['_source']['msgid']
            message = 'True'
        except:
            message = 'False'

    return jsonify({'message': message, 'msg_id': latest_msg_id})


@app.route('/get_all_index_data', methods=['POST'])
def get_all_index_data():
    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
    secret_code = request.json.get('passcode', None)
    index_name = request.json.get('index', None)
    is_group = request.json.get('is_group', None)
    if is_group == None or index_name == None:
        return jsonify({"errormsg": "Uh oh, careful with the fields in your request. It has to be exactly"}), 403
    if secret_code == None:
        return jsonify({"errormsg": "Uh oh, careful with the fields in your request. It has to be exactly 'secret_code'."}), 403

    if secret_code == '@lazlxEtIcS3A9rchIydzXiqg2u21fr0m':
        pass
    else:
        return jsonify({"errormsg": "Please enter the correct secret_code"}), 403
    all_data = []
    for i in range(20):
        channel_query = es.search(index=index_name, size=0, body={
            'query': {
                "match": {
                    "is_group": is_group
                }
            },
            "aggs": {
                "unique_channels": {
                    "terms": {"field": "link.keyword",
                              "include": {
                                  "partition": i,
                                  "num_partitions": 20
                              },
                              "size": 2000}
                }
            }


        })
        response = channel_query
        new_res = response['aggregations']["unique_channels"]['buckets']
        for i in new_res:
            all_data.append(i)

    # print(viewed['aggregations']['group_by_month']['buckets'])

    return jsonify({'data': all_data})



@app.route('/date_file', methods=['POST'])
def date_file():
    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
    start_date = request.json.get('start_date', None)
    end_date = request.json.get('end_date', None)
    secret_code = request.json.get('passcode', None)
    filext = request.json.get('filext', None)
    if start_date == None or end_date == None:
        return jsonify({"errormsg": "Uh oh, careful with the fields in your request. It has to be exactly"}), 403
    if secret_code == None:
        return jsonify({"errormsg": "Uh oh, careful with the fields in your request. It has to be exactly 'secret_code'."}), 403

    if secret_code == '@lazlxEtIcS3A9rchIydzXiqg2u21fr0m':
        pass
    else:
        return jsonify({"errormsg": "Please enter the correct secret_code"}), 403
    if filext is None or filext == 'all':
        filext = ['jar', 'exe', 'zip', 'rar', 'gz', 'deb', 'apk']

    term_quer = {"term": {
        "fileext.keyword": filext,
    }}
    if filext is None or filext == 'all':
        filext = ['jar', 'exe', 'zip', 'rar', 'gz', 'deb', 'apk']
        term_quer = {"terms": {
            "fileext": filext,
        }}

    res = es.count(index=["telegram2_alias","financials_alias","extremepolitical2_alias","religion_spirituality_alias","pharma_drugs_alias","criminal_activities_alias","information_technology","cyber_security_alias"],
                   body={
                       'query': {
                           'bool': {
                               "must": [
                                   term_quer, {"range": {"date": {
                                       "gte": start_date, "lte": end_date, }}}]
                           }
                       },

                   }

                   )
    channel_res = es.search(index=["telegram2_alias","financials_alias","extremepolitical2_alias","religion_spirituality_alias","pharma_drugs_alias","criminal_activities_alias","information_technology","cyber_security_alias"], size=9000,
                            body={
                                'query': {
                                    'bool': {
                                        "must": [
                                            term_quer, {"range": {"date": {
                                                "gte": start_date, "lte": end_date, }}}]
                                    }
                                },
                                "aggs": {
                                    "unique_channels": {
                                        "terms": {"field": "link.keyword",
                                                  }
                                    }
                                }

                            }

                            )
    total_channel = len(channel_res['aggregations']
                        ['unique_channels']['buckets'])
    total_files = res['count']
    return jsonify({'total_channel': total_channel, 'total_files': total_files})


@app.route('/scraper_tracker', methods=['POST'])
def scraper_tracker():
    try:
        print(request.remote_addr)
        es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
        ip_adress = str(request.environ.get("HTTP_X_REAL_IP", request.remote_addr))
        phone = request.json.get('phone', None)
        api_id = request.json.get('api_id', None)
        api_hash = request.json.get('api_hash', None)
        joined_groups = request.json.get('joined_groups', None)
        status = request.json.get('status', None)
        name = request.json.get('name', None)
        category = request.json.get('category', None)
        if phone is None or api_id is None or api_hash is None or joined_groups is None or status is None:
            return jsonify({"errormsg": "Uh oh, careful with the fields in your request. It has to be exact"}), 403
        secret_code = request.json.get('passcode', None)
        if secret_code == None:
            return jsonify({"errormsg": "Uh oh, careful with the fields in your request. It has to be exactly 'secret_code'."}), 403

        if secret_code == '@lazlxEtIcS3A9rchIydzXiqg2u21fr0m':
            pass
        else:
            return jsonify({"errormsg": "Please enter the correct secret_code"}), 403
        index_presence = index_creater('scrapper_phone_tracker')
        if index_presence == False:
            return jsonify({"errormsg": "Uh oh, could not create the index."}), 403
        data = {'alt_phone': phone, 'api_id': api_id, 'api_hash': api_hash, 'joined_groups': joined_groups,
                'status': status, "ip_adress": ip_adress, "alt_name": name, 'alt_category': category}
        try:
            res = es.index(index='scrapper_phone_tracker', body=data, id=api_id)
            return jsonify({"message": "Sucessfully indexed the data"}), 200
        except:
            return jsonify({"errormsg": "Uh oh, could not index the data."}), 403
    
    except Exception as e:
        return jsonify({"errormsg": f"{e}"}), 200


@app.route('/get_scraper_tracker', methods=['POST'])
def get_scraper_tracker():
    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
    api_id = request.json.get('api_id', None)
    secret_code = request.json.get('passcode', None)
    if api_id is None:
        return jsonify({"errormsg": "Uh oh, careful with the fields in your request. It has to be exact"}), 403
    if secret_code == None:
        return jsonify({"errormsg": "Uh oh, careful with the fields in your request. It has to be exactly 'secret_code'."}), 403

    if secret_code == '@lazlxEtIcS3A9rchIydzXiqg2u21fr0m':
        pass
    else:
        return jsonify({"errormsg": "Please enter the correct secret_code"}), 403
    try:
        res = es.get(index='scrapper_phone_tracker', id=api_id)
        return jsonify({'message': 'True', 'data': res['_source']}), 200
    except:
        return jsonify({'message': 'False'}), 201


@app.route('/get_all_scraper_tracker', methods=['POST'])
def get_all_scraper_tracker():
    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
    secret_code = request.json.get('passcode', None)
    if secret_code == None:
        return jsonify({"errormsg": "Uh oh, careful with the fields in your request. It has to be exactly 'secret_code'."}), 403

    if secret_code == '@lazlxEtIcS3A9rchIydzXiqg2u21fr0m':
        pass
    else:
        return jsonify({"errormsg": "Please enter the correct secret_code"}), 403
    try:
        res = es.search(index='scrapper_phone_tracker', size=50 ,body={
            "query": {
                "match_all": {}
            }
        })
        return jsonify({'data': res['hits']['hits']}), 200
    except:
        return jsonify({'message': 'False'}), 204

@app.route('/v2/add_custom_preference', methods=['POST'])
@jwt_required
def add_custom_preference():


    try:
        es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
        '''
        postgress code
        '''
        jwt_all = get_jwt_identity()
        current_user = jwt_all[0]

        # Function to block usage of old tokens after change of password.
        if check_tokens(jwt_all) != 'successful':
            return check_tokens(jwt_all)[0]

        conn = psycopg2.connect(database='client_database', user=database_username,
                                password=database_password, host=host_name, port=db_port)
        conn.autocommit = True
        cursor = conn.cursor()
        cursor.execute(
            f"SELECT userid from client_database where username='{current_user}';")
        conn.commit()
        uname = cursor.fetchall()
        useridadmin = uname[0][0]

        '''
        route code
        '''

        type = request.json.get('type', None)
        qtext = request.json.get('qtext', None)
        if qtext is None or qtext is 'None' or type is None or type is 'None':
            return jsonify({"errormsg": "Uh oh, careful with the fields in your request. It has to be exact."}), 403
        
        default_search = "term"
        srch_filter = 'conv_name.keyword'
        if type == 'channel_id':
            srch_filter = 'to_id.keyword'
        elif type == 'channel_username':
            default_search = 'match_phrase'
            srch_filter = 'link'
        
        channel_data = es.search(index=["telegram2_alias","financials_alias","extremepolitical2_alias","religion_spirituality_alias","pharma_drugs_alias","criminal_activities_alias","information_technology","cyber_security_alias"], size=1, body={
            'query': {
                default_search: {srch_filter: qtext}
            }

        })

        if len(channel_data['hits']['hits']) < 1:
            return jsonify({'message': f'Sorry could not find channel with id or channel_name with  "{qtext}" '}), 403

        channel_json = channel_data['hits']['hits'][0]['_source']
        channel_name = channel_json['conv_name']
        channel_id = channel_json['to_id']
        date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
     
        new_obj = {'channel_name': channel_name, 'channel_id': channel_id,
                   'user_id': str(useridadmin), 'created_date': date}
        hash_str = str(new_obj)
        hash_obj = {'channel_name': channel_name, 'user_id': str(useridadmin)}
        hashasid = hashlib.md5(str(hash_obj).encode('UTF-8')).hexdigest()

        index_presence = index_creater('user_channel_preference')

        try:
            res = es.get(index='user_channel_preference', id=hashasid)
            return jsonify({'message': f'The channel "{channel_name}" has already beed added. Please try agsin eith new Channel/Group  Name/ID'}), 403
        except Exception as e:
            print(e)
            pass

        user_data = es.search(index='user_channel_preference', size=100, body={
            'query': {
                'match': {
                    'user_id': str(useridadmin)
                }
            }
        })

        if len(user_data['hits']['hits']) >= 100:
            return jsonify({'message': f'You have reached your limit for adding new channels. please contact service provide to extend the limit'}), 403

        try:
            es.index(index='user_channel_preference',
                     id=hashasid, body=new_obj)
            return jsonify({'message': f'successfully added the new channel/Group for userid {useridadmin}'})
        except:
            return jsonify({'error': 'sorry could not add your query at the present.Please contact service provider for more information.'}),403
    except Exception as e:
        print(e)
        return jsonify({"error": e})


@app.route('/v2/get_custom_preference', methods=['GET'])
@jwt_required
def get_custom_preference():
    try:
        es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
        '''
        postgress code
        '''
        jwt_all = get_jwt_identity()
        current_user = jwt_all[0]

        # Function to block usage of old tokens after change of password.
        if check_tokens(jwt_all) != 'successful':
            return check_tokens(jwt_all)[0]

        conn = psycopg2.connect(database='client_database', user=database_username,
                                password=database_password, host=host_name, port=db_port)
        conn.autocommit = True
        cursor = conn.cursor()
        cursor.execute(
            f"SELECT userid from client_database where username='{current_user}';")
        conn.commit()
        uname = cursor.fetchall()
        useridadmin = uname[0][0]
        user_data = es.search(index='user_channel_preference', size=20, body={
            'query': {
                'match': {
                    'user_id': str(useridadmin)
                }
            }
        })
        return_list = []
        print(user_data['hits']['hits'][0]['_source'])
        if len(user_data['hits']['hits']) > 0:
            for i in user_data['hits']['hits']:
                return_list.append(i['_source'])
        return jsonify({'data': return_list})

    except Exception as e:
        print(e)
        return jsonify({'error': f'Sorry could not get Channels/Group or userid {useridadmin} .Please contact service provider for more information.'})


@app.route('/v2/preference_search', methods=['POST'])
@jwt_required
def preference_search():
    try:
        es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
        '''
        postgress code
        '''
        jwt_all = get_jwt_identity()
        current_user = jwt_all[0]

        f = open("apilogs.txt", "a", encoding='UTF-8')
        #data_to_log = f'''DATETIME:{datetime.datetime.utcnow()}\nIPADDRESS:{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}\nUsername:{username}\n\n'''
        data_to_log = {"DATETIME":f"{datetime.datetime.utcnow().isoformat()+'+00:00'}","IPADDRESS":f"""{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}""","ENDPOINT":"/v2/preference_search","User": f"{current_user}"}
        f.write(str(data_to_log))
        f.write('\n')
        f.close()

        # Function to block usage of old tokens after change of password.
        if check_tokens(jwt_all) != 'successful':
            return check_tokens(jwt_all)[0]

        conn = psycopg2.connect(database='client_database', user=database_username,
                                password=database_password, host=host_name, port=db_port)
        conn.autocommit = True
        cursor = conn.cursor()
        cursor.execute(
            f"SELECT userid from client_database where username='{current_user}';")
        conn.commit()
        uname = cursor.fetchall()
        useridadmin = uname[0][0]

        index_name_user = request.json.get('selectCategory', None)
        index_name = []
        funcall = rate_limiter(current_user)

        try:
            if "hacking" in index_name_user:
                index_name.append("telegram2_alias")

            if "financials" in index_name_user:
                index_name.append("financials_alias")

            if "extremepolitical" in index_name_user:
                index_name.append("extremepolitical2_alias")

            if "religion_spirituality" in index_name_user:
                index_name.append("religion_spirituality_alias")

            if "pharma_drugs" in index_name_user:
                index_name.append("pharma_drugs_alias")

            if "criminal_activities" in index_name_user:
                index_name.append("criminal_activities_alias")

            if "information_technology" in index_name_user:
                index_name.append("information_technology")
            if "cyber_security" in index_name_user:
                index_name.append("cyber_security_alias")

            if index_name_user == None or index_name_user == "all":
                index_name =  ["telegram2_alias","financials","extremepolitical2_alias","religion_spirituality_alias","pharma_drugs_alias","criminal_activities_alias","information_technology","cyber_security_alias"]

            elif "hacking" not in index_name_user and "financials" not in index_name_user and "extremepolitical" not in index_name_user and "religion_spirituality" not in index_name_user and "pharma_drugs" not in index_name_user and "criminal_activities" not in index_name_user and "information_technology" not in index_name_user and "cyber_security" not in index_name_user:
                 return jsonify({"errormsg":"Uh oh, careful with the fields in your request. It has to be exact. Refer the API documentation provided to you for API v2.0.3  Mode 1"}),403

        except Exception as e:
            index_name =  ["telegram2_alias","financials","extremepolitical2_alias","religion_spirituality_alias","pharma_drugs_alias","criminal_activities_alias","information_technology","cyber_security_alias"]
        
        qtext = request.json.get('qtext', None)
        max_results = request.json.get('max', None)
        start_date = request.json.get('start_date', None)
        end_date = request.json.get('end_date', None)
        sort_order = request.json.get('sort_order', None)
        select_group = request.json.get('select_field', None)
        search_type = request.json.get('search_type', None)
        search_after_id = request.json.get('search_after_id', None)
        search_filter = request.json.get('search_filter', None)
        default_slop = 0

        if qtext == None or len(qtext) < 2:
            return jsonify({"errormsg":"Seach query should have minimum 2 characters and should not be null"}),403

        if sort_order != 'desc' and sort_order != 'asc':
                return jsonify({"errormsg":"Sort_order can only be either asc or desc. API v2.0.3 MODE 1"}),403

        if ' ' in qtext and search_filter == 'contains':
            default_slop = 100
        
        if max_results == None:
            max_results=10

        if search_filter == 'contains':
            url_regex = re.compile(r"https?://(www\.)?")
            www_sub = re.compile(r"https?://(www\.)?")
            qtext = url_regex.sub('', qtext).strip().strip('/')

        if start_date == "None":
            start_date = "1989-11-10"
      
        if end_date == "None" or end_date == "now":
            end_date = "now"
       

        fields_selected = "message"
        fuzzy_selected = "message"
        ''' fields filter based on post/title filter'''

        if select_group == 'conv_name':
            fields_selected = "conv_name"
        
        if qtext == 'None':
            max_results = 20

        if ' ' in qtext:
            fuzzie = 'AUTO'

        default_search_filter = {
            'terms': {"is_group.keyword":  ["True", "False"]}}
        if search_type == 'group':
            default_search_filter = {
                'term': {"is_group.keyword": {"value": "True"}}}
        elif search_type == 'channel':
            default_search_filter = {
                'term': {"is_group.keyword": {"value": "False"}}}

        default_search_query = {"match_phrase": {
            fields_selected: {
                'query': qtext, 'slop': default_slop
            }
        }}
        if select_group == 'None':
            default_search_query = {"multi_match": {
                "query": qtext, "type": "phrase", "fields": ["message", "conv_name"], "slop": default_slop}}

        if sort_order != 'desc' and sort_order != 'asc':
            return jsonify({"errormsg": "Sort_order can only be either asc or desc. API v2.0.3 MODE 1"}), 403

        if search_filter == 'contains' and ' ' not in qtext:
            default_query = 'prefix'
            if '*' in qtext:
                default_query = 'wildcard'

            default_search_query = {
                default_query: {
                    "message.keyword": {
                        "value": qtext, "boost": 1.0}

                }
            }

            if select_group == 'None':
                default_search_query = {"bool": {
                    "should": [
                        {default_query: {
                            "message": qtext

                        }},
                        {default_query: {
                            "conv_name": qtext

                        }}
                    ]
                }}
            try:
                contains_count_quer = {"query": {"bool": {"must": [default_search_query, default_search_filter, {
                    "range": {"date": {"gte": f"{start_date}", "lte": f"{end_date}"}}}]}}}
                contains_doc_count = es.count(index=all_index_name,
                                              body=contains_count_quer)
                if contains_doc_count['count'] <= 0:
                    default_search_query = {
                        "query_string": {
                            "query": f"*{qtext}*",
                            "fields": ["message"]
                        }
                    }
            except:
                print('query string not activated')

        # extracting using channels
        user_data = es.search(index='user_channel_preference', size=20, body={
            'query': {
                'match': {
                    'user_id': str(useridadmin)
                }
            }
        })
        channel_names = []

        if len(user_data['hits']['hits']) < 1:
            return jsonify({'message': f'You have no preference channel. Please add channel on preference setting first'}), 403
        else:
            for i in user_data['hits']['hits']:
                new_obj = {
                    "term": {"conv_name.keyword": i['_source']['channel_name']}}
                channel_names.append(new_obj)

        quer = {
            'query': {
                "bool": {
                    "must": [
                        default_search_query, default_search_filter, {
                            "range": {"date": {"gte": f"{start_date}", "lte": f"{end_date}", }}},
                        {
                            "bool": {
                                "should": channel_names
                            }
                        }


                    ],

                }

            },
            "sort": [{"date": {"order": f"{sort_order}"}}]
        }
        # Adding decoded search after key to query if it passed on the api
        decode_key = "None"
        try:
            if search_after_id != None and search_after_id != 'None':
                search_after_validator = pagination_checker_limiter(current_user)
                if search_after_validator is False:
                        return jsonify({'errormsg':f'Your Pagination limit is reached. Please contact at {COMPANY_EMAIL} for more information.'}), 403
                        
                decode_key = cryptocode.decrypt(
                    str(search_after_id), '#random_pass1&*$@')
        except:
            print('could not decrypt the provided search after key')

        if decode_key != 'None':
            try:
                print('activated')
                quer['search_after'] = [decode_key]
            except:
                print('search after could not be intiated')
        res = es.search(index=index_name,
                        size=max_results, body=quer)
        if len(res['hits']['hits']) < 1:
            return jsonify({'message': f'Sorry could not find any data. Please try other search other queries'}), 403

        # encrypting search_after key for passing it on frontend
        encoded_key = 'None'
        try:
            if len(res['hits']['hits']) >= 1:
           
                encoded_key = cryptocode.encrypt(
                    str(res['hits']['hits'][-1]['sort'][0]), '#random_pass1&*$@')
        except:
            print('could not encrypt/add search after key')

        return_list = []
        for hit in res['hits']['hits']:
            return_list.append(hit["_source"])

        scroll_auth = scroll_auth_extractor(current_user)

        return jsonify({'data': return_list, 'search_id': encoded_key,"ratelimit":funcall,'scroll_auth':scroll_auth})

    except Exception as e:
        print(e)
        return jsonify({"error": 'Sorry could not retrieve the data at the moment.Please contact service provide for more information.'})

@app.route('/v2/bulk/indexer',methods=['POST'])
def bulk_index():
    try:
        es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
        data = request.json.get('data',None)
        index_name = request.json.get('index_name',None)
        new_index_name = [index_name]
        if index_name != 'uncategorized':
            new_index_name.append(f'{index_name}_v2')
            
            
        chunk_size = 10000
        if len(data) < 10000:
            chunk_size = len(data)
        for i_name in new_index_name:
            for ok, result in helpers.streaming_bulk(es, data_generator(i_name,data), chunk_size=chunk_size, refresh=False, request_timeout=60*3,  yield_ok=False, raise_on_error=False):
                    print()
                    if not ok:
                    
                        print(
                            f' unable to index the doc with id {result["index"]["_id"]}')
            #             time.sleep(5)
        return jsonify({'message':'sucess'})
    except:
        return jsonify({'message':'could not index the data'}) , 403 

@app.route('/v2/bulk/user_indexer',methods=['POST'])

@app.route('/v2/bulk/user_indexer',methods=['POST'])
def bulk_user_indexer():
    try:
        es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
        data = request.json.get('data',None)
        chunk_size = 10000
        if len(data) < 10000:
            chunk_size = len(data)
        for ok, result in helpers.streaming_bulk(es, user_data_generator('onlineusers2',data), chunk_size=chunk_size, refresh=False, request_timeout=60*3,  yield_ok=False, raise_on_error=False):
                print()
                if not ok:
                
                    print(
                        f' unable to index the doc with id {result["index"]["_id"]}')
        return jsonify({'message':'sucessfully indexed data'})
    except:
        return jsonify({'message':'could not index the data'}) , 403   


"""
Deletes user added channels preference 
"""
@app.route('/delete_channel_preference', methods=["POST"])
@jwt_required
def delete_channel_preference():
    try:
        es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
        hash_id = request.json.get('hash_id', None)
        res = es.delete(index='user_channel_preference', id=hash_id)

        return jsonify({'status': 'succesfully deleted the channels.'})
    except Exception as e:
        return jsonify({'data': 'delete was unsuccessfull'})

@app.route('/custom_search_counter', methods=["POST"])
def custom_search_counter():
    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
    keyword = request.json.get('keyword', None)
    logical_filter = request.json.get('logical_filter', None)
    index_name_request = request.json.get('index_name', None)
    secret_code = request.json.get('passcode', None)
    index_name = index_name_request

    if secret_code == '@lazlxEtIcS3A9rchIydzXiqg2u21fr0m':
        pass
    else:
        return jsonify({"errormsg": "Please enter the correct secret_code"}), 403
    if keyword is None or logical_filter == None or index_name == None:
        return jsonify({"errormsg": "Uh oh, careful with the fields in your request. It has to be exact"}), 403
    if index_name_request == 'all':
        index_name = all_index_name
    logical_query = 'should'
    if logical_filter == 'and' or logical_filter == 'AND':
        logical_query = 'must'
    all_data = []
    for i in keyword:
        new_obj = {"match_phrase": {
            "message": i
        }}
        all_data.append(new_obj)
    quer = {
        'query': {
            'bool': {
                logical_query: all_data
            }
        }
    }

    # es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
    total_doc = es.count(index=index_name, body=quer)
    return jsonify({'total_docs': total_doc['count']})


@app.route('/custom_search_data', methods=["POST"])
def custom_search_data():
    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
    keyword = request.json.get('keyword', None)
    logical_filter = request.json.get('logical_filter', None)
    index_name_request = request.json.get('index_name', None)
    search_after_id = request.json.get('search_after_id', None)
    secret_code = request.json.get('passcode', None)
    index_name = index_name_request
    if keyword is None or logical_filter == None or index_name == None:
        return jsonify({"errormsg": "Uh oh, careful with the fields in your request. It has to be exact"}), 403
    if secret_code == '@lazlxEtIcS3A9rchIydzXiqg2u21fr0m':
        pass
    else:
        return jsonify({"errormsg": "Please enter the correct secret_code"}), 403
    if index_name_request == 'all':
        index_name = all_index_name

    decode_key = "None"
    try:
        if search_after_id != None and search_after_id != 'None':                        
            decode_key = search_after_id
    except:
        print('could not intiate the provided search after key')

    logical_query = 'should'
    if logical_filter == 'and' or logical_filter == 'AND':
        logical_query = 'must'
    all_data = []
    for i in keyword:
        new_obj = {"match_phrase": {
            "message": i
        }}
        all_data.append(new_obj)

    quer = {
        'query': {
            'bool': {
                logical_query: all_data
            }
        },
        "sort": [{"date": {"order": f"desc"}}]
    }

    if decode_key != 'None':
        try:
            print('activated')
            quer['search_after'] = [decode_key]
        except:
            print('search after could not ')

    channel_query = es.search(
        index=index_name, size=3000, body=quer)
    encoded_key = 'None'
    try:
        if len(channel_query['hits']['hits']) > 1:
            encoded_key = channel_query['hits']['hits'][-1]['sort'][0]
    except:
        print('could not encrypr/add search after key')
    return_list = []
    for hit in channel_query['hits']['hits']:
        return_list.append(hit["_source"])
    return jsonify({'data': return_list, 'search_id': encoded_key})

@app.route('/individual_channel_posts', methods=['POST'])
@stats_decorator
@jwt_required
@maxResults_decorator
def individual_channel_posts(default_query):
    try:
        es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
        jwt_all = get_jwt_identity()
        current_user = jwt_all[0]

        f = open("apilogs.txt", "a", encoding='UTF-8')
        #data_to_log = f'''DATETIME:{datetime.datetime.utcnow()}\nIPADDRESS:{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}\nUsername:{username}\n\n'''
        data_to_log = {"DATETIME":f"{datetime.datetime.utcnow().isoformat()+'+00:00'}","IPADDRESS":f"""{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}""","ENDPOINT":"/individual_channel_posts","User": f"{current_user}"}
        f.write(str(data_to_log))
        f.write('\n')
        f.close()


        # Function to block usage of old tokens after change of password.
        if check_tokens(jwt_all) != 'successful':
            return check_tokens(jwt_all)[0]

        filter = request.json.get('filter', None)
        start_date = request.json.get('start_date', None)
        end_date = request.json.get('end_date', None)
        max = request.json.get('max', None)
        sort_order = request.json.get('sort_order', None)
        search_after_id = request.json.get('search_after_id', None)
        if sort_order is None:
            sort_order = 'desc'
        else:
            if sort_order != 'asc' and sort_order != 'desc':
                return jsonify({'errormsg': 'Please send valid sort order filter. It must be either asc or desc.'}), 403

        if start_date == "None" or start_date is None:
            start_date = "1989-11-10"


        if end_date == "None" or end_date == "now" or end_date is None:
            end_date = "now"

        # if qtext == None or qtext == 'None':
        #     return jsonify({"errormsg": "Uh oh, careful with the fields in your request. It has to be exact."}), 403
        default_size = 1000
        if max != None:
            default_size = max
        print(default_query)
        query = {
            "query": {
                "bool": {
                    "must": [default_query, {"range": {"date": {
                        "gte": f"{start_date}", "lte": f"{end_date}", }}}]
                }

            },
            "sort": [{"date": {"order": f"{sort_order}"}}]

        }
        if filter is not None:
            if filter == 'forwarded':
                query['query']['bool']['must_not'] = [
                    {'match': {'forwardedfromchanid': 'None'}}
                ]

            elif filter == 'replied':
                query['query']['bool']['must_not'] = [
                    {'match': {'reply': 'None'}}
                ]
            elif filter == "file":
                query['query']['bool']['must_not'] = [
                    {'match': {'filename': 'None'}}
                ]
        decode_key = "None"
        try:
            if search_after_id != None and search_after_id != 'None':
                search_after_validator = pagination_checker_limiter(current_user)
                if search_after_validator is False:
                        return jsonify({'errormsg':f'Your Pagination limit is reached. Please contact at {COMPANY_EMAIL} for more information.'}), 403
                        
                decode_key = cryptocode.decrypt(
                    str(search_after_id), '#random_pass1&*$@')
        except:
            print('could not decrypt the provided search after key')
        if decode_key != 'None':
            try:
                print('activated')
                query['search_after'] = [decode_key]
            except:
                print('search after could not ')
        print(query)
        res = es.search(index=all_index_name,
                        size=default_size, body=query)
        return_list = []
        print(return_list)
        encoded_key = 'None'
        if len(res['hits']['hits']) > 0:
            encoded_key = cryptocode.encrypt(
                        str(res['hits']['hits'][-1]['sort'][0]), '#random_pass1&*$@')
            for hit in res['hits']['hits']:
                # print("inloop")
                return_list.append(hit["_source"])
            
        funcall = rate_limiter(current_user)
        scroll_auth = scroll_auth_extractor(current_user)
        return jsonify({'data':return_list, 'ratelimit':funcall,'search_id': encoded_key,'scroll_auth':scroll_auth})
    except Exception as e:
        print(e)
        return jsonify({'errormsg': 'Sorry could not process your request at the moment. Please contact service provider for further more info.'}),403
        
@app.route('/missing_id_channel', methods=['POST'])
def missing_id_channel():
    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
    all_data = []
    index_name = request.json.get('index_name', None)
    secret_code = request.json.get('passcode', None)

    if index_name == None or index_name == 'None':
        return jsonify({"errormsg": "Uh oh, careful with the fields in your request. It has to be exact."}), 403

    if secret_code == '@lazlxEtIcS3A9rchIydzXiqg2u21fr0m':
        pass
    else:
        return jsonify({"errormsg": "Please enter the correct secret_code"}), 403

    for i in range(20):
        channel_query = es.search(index=index_name, size=0, body={
            'query': {
                'match': {
                    'is_group': 'False'
                }
            },
            "aggs": {
                "unique_channels": {
                    "terms": {"field": "link.keyword",
                              "include": {
                                  "partition": i,
                                  "num_partitions": 20
                              },
                              "size": 10000}
                }
            }


        })
        response = channel_query
        new_res = response['aggregations']["unique_channels"]['buckets']
        for i in new_res:
            all_data.append(i)
    return jsonify({"length": len(all_data), "data": all_data})


@app.route('/id_count', methods=['POST'])
def id_count():
    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
    index_name = request.json.get('index_name', None)
    channel_username = request.json.get('channel_username', None)
    secret_code = request.json.get('passcode', None)

    if index_name == None or index_name == 'None' or channel_username == None:
        return jsonify({"errormsg": "Uh oh, careful with the fields in your request. It has to be exact."}), 403

    if secret_code == '@lazlxEtIcS3A9rchIydzXiqg2u21fr0m':
        pass
    else:
        return jsonify({"errormsg": "Please enter the correct secret_code"}), 403

    total_id_data = es.count(index=index_name, body={
        'query': {
            'bool': {
                "must": [
                    {
                        "terms": {
                            "link": channel_username
                        }
                    }
                ],
                'must_not': [
                    {'match': {'to_id': 'None'}}
                ]

            }
        }
    })
    total_no_id_data = es.count(index=index_name, body={
        'query': {
            'bool': {
                "must": [
                    {
                        "terms": {
                                "link": channel_username
                                }
                    },

                    {'match': {'to_id': 'None'}}


                ],

            }
        }
    })
    total_data = es.count(index=index_name, body={
        'query': {
            'bool': {
                "must": [
                    {
                        "terms": {
                            "link": channel_username
                        }
                    }

                ],

            }
        }
    })

    return jsonify({"id_data": total_id_data['count'], "total_un_id_data": total_no_id_data['count'], 'total_data': total_data['count']})


@app.route('/id_extractor', methods=['POST'])
def id_extractor():
    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
    index_name = request.json.get('index_name', None)
    channel_username = request.json.get('channel_username', None)
    secret_code = request.json.get('passcode', None)

    if index_name == None or index_name == 'None' or channel_username == None:
        return jsonify({"errormsg": "Uh oh, careful with the fields in your request. It has to be exact."}), 403

    if secret_code == '@lazlxEtIcS3A9rchIydzXiqg2u21fr0m':
        pass
    else:
        return jsonify({"errormsg": "Please enter the correct secret_code"}), 403

    res = es.search(index=index_name, size=1, body={
        'query': {
            'bool': {
                "must": [
                    {
                        "terms": {
                            "link": channel_username
                        }
                    }
                ],
                'must_not': [
                    {'match': {'to_id': 'None'}}
                ]

            }
        }
    })
    print(res['hits']['hits'][0]['_source']['to_id'])

    return jsonify({"id": res['hits']['hits'][0]['_source']['to_id']})


@app.route('/update_channel_id', methods=['POST'])
def update_channel_id():
    try:
        es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
        index_name = request.json.get('index_name', None)
        channel_username = request.json.get('channel_username', None)
        channel_id = request.json.get('channel_id', None)
        secret_code = request.json.get('passcode', None)

        if index_name == None or index_name == 'None' or channel_username == None or channel_id == None:
            return jsonify({"errormsg": "Uh oh, careful with the fields in your request. It has to be exact."}), 403

        if secret_code == '@lazlxEtIcS3A9rchIydzXiqg2u21fr0m':
            pass
        else:
            return jsonify({"errormsg": "Please enter the correct secret_code"}), 403

        res_update = es.update_by_query(index=index_name, body={
            'query': {
                'bool': {
                    "must": [
                        {
                            "terms": {
                                "link": channel_username
                            }
                        },

                        {'match': {'to_id': 'None'}}


                    ],

                }
            },
            "script": f"ctx._source.to_id = {channel_id}"
        },

        )
        return jsonify({'message':'sucess'})
    except Exception as e:
        return jsonify({'errormsg':e})


@app.route("/v2/darkweb_search", methods=['GET', 'POST'])
@jwt_required
def v2_my_index():
    try:
        jwt_all = get_jwt_identity()
        current_user = jwt_all[0]

        if check_tokens(jwt_all) != 'successful':
            return check_tokens(jwt_all)[0]

        darkowl_ratelimit = 0
        try:
            conn_db = psycopg2.connect(database= 'client_database' , user= database_username , password= database_password , host= host_name, port= db_port)
            conn_db.autocommit = True
            cursor_db = conn_db.cursor()

            query_to_db = f"SELECT darkowl_ratelimit from client_database where username='{current_user}'"
            cursor_db.execute(query_to_db)
            darkowl_ratelimit = cursor_db.fetchall()[0][0]

        except Exception as e:
            conn_db.close()
            return jsonify({"errormsg": "Are you registered? Please contact us at tesseract@tesseractintelligence.com"}), 403, {'Content-Type': 'application/json'}
    
        if darkowl_ratelimit < 1:
            return jsonify({"Error":"You have reached a rate-limit for breach search. Please contact your service provider."}), 403 , {'Content-Type': 'application/json'}

        current_status = False

        query = request.json.get('query', None)
        offset = request.json.get('pagination_value', None)
        # either value should be r, h or d, refer to https://docs.api.darkowl.com/#operation/search
        sort = request.json.get('sort_order', None)
        count = request.json.get(
            'number_of_results', None)  # from 0 to 20 only
        # true if de-duplication is OFF, else false
        similar = request.json.get('similar_results', None)
        # true if de-duplication is OFF, else false
        from_date = request.json.get('from', None)
        # true if de-duplication is OFF, else false
        to_date = request.json.get('to', None)
        # default is false, set to true i
        # f to load results with empty text body
        empty = request.json.get('load_empty', None)
        ccn = request.json.get('ccn', None)
        ssn = request.json.get('ssn', None)
        email = request.json.get('email', None)
        emailDomain = request.json.get('email_domain', None)
        ipAddress = request.json.get('ip_address', None)
        cryptoAddress = request.json.get('crypto_address', None)
        source = request.json.get('source',None)
        logical_operator = request.json.get('logical_operator', 'AND')

        logical_val = '&'

        
        if logical_operator == 'OR' or logical_operator == 'or':
            logical_val = '|'
            logical_operator = 'OR'
        elif logical_operator == 'not' or logical_operator == 'NOT':
            logical_val = '!'
            logical_operator='NOT'

        query_str = '?q'
        if query == None and email == None and emailDomain == None and ipAddress == None and cryptoAddress == None and ccn == None and ssn == None:
            return jsonify({'errormsg': 'Please provide suitable search queries.'}), 403

        if query != None:
            value = additional_value_checker('query', query, logical_val)
            new_query_value = value_adder(
                current_status, value, query_str, logical_val)
            query_str = new_query_value
            current_status = True

        if email != None:
            email_checker = email_validator(email)
            if email_checker is False:
                return jsonify({'errormsg': 'Please send a valid email address format.'}), 403
            value = additional_value_checker('email', email, logical_val)
            new_query_value = value_adder(
                current_status, value, query_str, logical_operator)
            query_str = new_query_value
            current_status = True

        if emailDomain != None:
            if '@' in emailDomain:
                return jsonify({'errormsg': '@ symbols should not be present in email domain. Use domain names only, e.g www.hotmail.com'}), 403
            value = additional_value_checker(
                'emailDomain', emailDomain, logical_val)
            new_query_value = value_adder(
                current_status, value, query_str, logical_operator)
            query_str = new_query_value
            current_status = True

        if ipAddress != None:
            ip_checker = ip_validator(ipAddress)
            if ip_checker is False:
                return jsonify({'errormsg': 'Please send valid IP address formats only.'}), 403
            value = additional_value_checker(
                'ipAddress', ipAddress, logical_val)
            new_query_value = value_adder(
                current_status, value, query_str, logical_operator)
            query_str = new_query_value
            current_status = True

        if cryptoAddress != None:
            value = additional_value_checker(
                'cryptoAddress', cryptoAddress, logical_val)
            new_query_value = value_adder(
                current_status, value, query_str, logical_operator)
            query_str = new_query_value
            current_status = True

        if ccn != None:
            value = additional_value_checker('ccn', ccn, logical_val)
            new_query_value = value_adder(
                current_status, value, query_str, logical_operator)
            query_str = new_query_value
            current_status = True

        if ssn != None:
            value = additional_value_checker('ssn', ssn, logical_val)
            new_query_value = value_adder(
                current_status, value, query_str, logical_operator)
            query_str = new_query_value
            current_status = True

        if source != None:
            list_of_source = ['discord','irc','leak','onion','opennic','telegram','zeronet','ftp','i2p']
            if source not in list_of_source:
                return jsonify({'errormsg': f'Please send valid source value. Note: Data Source should be following {list_of_source} '}), 403
            value = f'source={source}'
            new_query_value = value_adder(
                current_status, value, query_str,  '&')
            query_str = new_query_value


        if offset != None:
            try:
                int(offset)
                print('runned')
            except:
                return jsonify({'errormsg': 'Please send valid offset value. Note: Must be integer.'}), 403
            value = f'offset={offset}'
            new_query_value = value_adder(
                current_status, value, query_str, '&')
            query_str = new_query_value
           
        if sort != None:
            sort_val = 'r'
            if sort != 'relevance' and sort != 'date':
                return jsonify({'errormsg': 'Please send valid sort value. Either "relevance" or "date" for descending results.'}), 403

            if sort == 'date':
                sort_val = 'd'

            value = f'sort={sort_val}'
            new_query_value = value_adder(
                current_status, value, query_str, '&')
            query_str = new_query_value
          

        if count != None:
            try:
                int(count)
                print('runned')
            except:
                return jsonify({'errormsg': 'Please send valid no_of_results value. Note:Must be integer.'}), 403
            value = f'count={count}'
            new_query_value = value_adder(
                current_status, value, query_str, '&')
            query_str = new_query_value
  
        
        if from_date != None:
            try:
                year, month, day = from_date.split('-')
                new_date = datetime.datetime(int(year), int(
                    month), int(day)).strftime("%Y-%m-%dT%H:%M:%SZ")
                value = f'from={new_date}'
                new_query_value = value_adder(
                    current_status, value, query_str, '&')
                query_str = new_query_value
            except:
                return jsonify({'errormsg': 'Please send valid date value. Note:Must be in YYYY-mm-dd format.'}), 403

        if to_date != None:
            try:
                year, month, day = to_date.split('-')
                new_date = datetime.datetime(int(year), int(
                    month), int(day)).strftime("%Y-%m-%dT%H:%M:%SZ")
                value = f'to={new_date}'
                new_query_value = value_adder(
                    current_status, value, query_str, '&')
                query_str = new_query_value
            except:
                return jsonify({'errormsg': 'Please send valid date value. Note: Must be in YYYY-mm-dd format.'}), 403

        

        if similar != None:
            sim_val=True
            if similar != 'False' and similar != 'True':
                return jsonify({'errormsg': 'Please send valid similar_results value. Note: Must be in Boolean Format.'}), 403
            if similar == 'False':
                sim_val = False
            value = f'similar={sim_val}'
            new_query_value = value_adder(
                current_status, value, query_str, '&')
            query_str = new_query_value
          

        if empty != None:
            if empty != 'true' and empty != 'false' and empty != 'all':
                return jsonify({'errormsg': 'Please send valid load_empty value. Note: Must be either false or true or all'}), 403
            value = f'empty={empty}'
            new_query_value = value_adder(
                current_status, value, query_str, '&')
            query_str = new_query_value
       
        query = query_str
        print(query)
        
        if current_user != 'administrator':
                # connecting to the database
                try:
                    conn_db = psycopg2.connect(database= 'client_database' , user= database_username , password= database_password , host= host_name, port= db_port)
                    conn_db.autocommit = True
                    cursor_db = conn_db.cursor()

                    darkowl_ratelimit -= 1 
                    query_to_db = f"UPDATE client_database set darkowl_ratelimit={darkowl_ratelimit} where username='{current_user}'"
                    cursor_db.execute(query_to_db)
                except Exception as e:
                    conn_db.close()
                    return jsonify({"errormsg": f"ratelimit update failed for ratelimit at /v2/darkweb_search Please contact us at tesseract@tesseractintelligence.com {e} "}), 403, {'Content-Type': 'application/json'}

        response2 = v2_perform_query_search(query_str)
        
        #Note : searched_query ids only for development phase should be removed later
        return jsonify({"data": response2,"ratelimit":darkowl_ratelimit,'searched_query':query}), 200
    except Exception as e:
        return jsonify({"errormsg": f'Sorry could not process your request at the moment.Please contact service provider'}), 403


@app.route("/v2/usedquotas", methods=['GET', 'POST'])
def usage():
    try:
        passcode  = request.json.get('passcode', None)
        if passcode != 'darkowl_password_!2#@$%^jd9&*x':
            return {"errormsg":"Password required."}

        host = 'api.darkowl.com'
        endpoint = '/api/v1/usage'

        # Generate search string
        # search = payloadToString(payload)
        url = f'https://{host}{endpoint}'
        absPath = endpoint

        date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')

        auth = generate_auth_header(absPath, 'GET', privateKey, publicKey, date)
        headers = {'Authorization': auth,
                'X-VISION-DATE': date, 'Accept': 'application/json'}
        
        r = requests.get(url, headers=headers)
        
        if r.status_code == 200:
            return r.json()
        else:
            print(r.content)
            return jsonify({"data":r.content}), 200
    
    except Exception as e:
        print("Error from perform query search", e)
        return jsonify({"errormsg":f"Sorry could not process your request at the moment. Pleasy try again later."}), 200


@app.route("/v2/entity/email/<address>", methods=['GET', 'POST'])
def v2_entity(address):
    try:

        passcode  = request.json.get('passcode', None)
        if passcode != 'darkowl_password_!2#@$%^jd9&*x':
            return {"errormsg":"Password required."}
                
        host = 'api.darkowl.com'
        endpoint = '/api/v1/entity/email-address'

        # Generate search string
        # search = payloadToString(payload)
        url = f'https://{host}{endpoint}'
        absPath = endpoint +'?address=' + address

        print("requested absPath -> ", absPath)
        date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')

        auth = generate_auth_header(absPath, 'GET', privateKey, publicKey, date)
        headers = {'Authorization': auth, 'X-VISION-DATE': date, 'Accept': 'application/json'}
        
        r = requests.get(url, headers=headers)
        
        if r.status_code == 200:
            return r.json(), 200
        else:
            print(r.content)
            return {"data":r.content}, 200
    
    except Exception as e:
        print("Error from perform query search", e)
        return jsonify({"errormsg":f"Some error "}), 403

@app.route('/posts_csv_report', methods=["POST"])
@jwt_required
def posts_csv_report():
    try:
        r = redis.Redis(db=1)
        file_hash = request.json.get('file_hash', None)
        if file_hash is None or file_hash is 'None':
            return jsonify({'errormsg': 'Please send valid value'})
        decoed_key = cryptocode.decrypt(str(file_hash), '#random_pass1&*$@')
        if r.exists(decoed_key) == 0:
            return jsonify({'errormsg': 'No data found for the keyword'})
        new_data = r.get(decoed_key).decode()
        conv_data = ast.literal_eval(new_data)
        search_value = decoed_key.rsplit('$')[-1]
        print(search_value)

        new_date = datetime.datetime.now().isoformat()

        file_name = f'{search_value}_{new_date}.csv'

        program_path = os.getcwd()
        os.chdir(folder_create())

        with open(file_name, 'w', encoding='UTF-8') as csvfile:
            csvwriter = csv.writer(csvfile)
            csvwriter.writerow(['Channel_Name', 'Posts      ',"Channel_or_Group", 'FileName', 'Filsize', 'Post_Uploaded_Date', 'Link'])

            for data in conv_data['data']:
                channel_name = data['conv_name']
                posts = data['message']
                post_uploaded_date = data['date']
                link = data['link']
                post_id = data['msgid']
                filename = data['filename']
                filesize = data['filesize']
                new_link = channel_id_adder(link, post_id)
                is_group = 'Group'

                try:
                    if data['is_group'] == 'False':
                        is_group = 'Channel'
                except:
                    pass

                data_row = [channel_name, posts,
                            is_group, filename, filesize, post_uploaded_date, new_link]
                csvwriter.writerow(data_row)

        os.chdir(program_path)
        safe_path = safe_join(
            r'/root/csv_reports/', file_name)

        return send_file(safe_path, as_attachment=True)
    except Exception as e:
        return jsonify({'errormsg': f'Something happened in the route /report_generator'}), 403

@app.route('/get_channel_notification_data', methods=['POST'])
def get_channel_notification_data():
    secret_code = request.json.get('passcode', None)
    if secret_code == None:
        return jsonify({"errormsg":"Uh oh, careful with the fields in your request. It has to be exactly 'secret_code'."}),403
    if secret_code == '@lazlxEtIcS3A9rchIydzXiqg2u21fr0m':
        pass
    else:
        return jsonify({"errormsg":"Please enter the correct secret_code"}),403
    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
    res = es.search(index='user_notification', size=100, body={
        "query": {
                    "term": {
                        "notification_type": "channel",


                    },

                    }
    })
    return_list = []
    for hit in res['hits']['hits']:
        return_list.append(hit["_source"])
    return jsonify({'data': return_list})

@app.route('/index_extractor', methods=['POST'])
def index_extractor():
    secret_code = request.json.get('passcode', None)
    link = request.json.get('link', None)
    new_link = channel_name_converter(link)
    if secret_code == None:
        return jsonify({"errormsg": "Uh oh, careful with the fields in your request. It has to be exactly 'secret_code'."}), 403
    if secret_code == '@lazlxEtIcS3A9rchIydzXiqg2u21fr0m':
        pass
    else:
        return jsonify({"errormsg": "Please enter the correct secret_code"}), 403
    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
    res = es.search(index=all_index_name, size=1, body={
        "query": {
                    "terms": {
                        "link": new_link,


                    },

                    }
    })
    index_name = 'None'
    if len(res['hits']['hits']) > 0:
        index_name = res['hits']['hits'][0]['_index']
    return jsonify({'data': index_name})

#Note this a temporary route so should be deleted after use
@app.route('/get_user_with_phone', methods=['GET'])
def get_user_with_phone():
    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
    res = es.count(index='onlineusers', body={"query":{
    "bool": {
                    "must": [
                        {
                            "match_all":{}
                        }
                    ],
                    'must_not': [
                        {'match': {'phone': 'None'}}
                    ]
                }}

})
    return jsonify({'data': res['count']})

@app.route('/redundency_extractor', methods=['POST'])
def redundency_extractor():
    link = request.json.get('link', None)
    secret_code = request.json.get('passcode', None)

    if link is None:
        return jsonify({'errormsg': 'Please send valid link'}), 403

    if secret_code == None:
        return jsonify({"errormsg": "Uh oh, careful with the fields in your request. It has to be exactly 'secret_code'."}), 403
    
    if secret_code == '@lazlxEtIcS3A9rchIydzXiqg2u21fr0m':
        pass
    else:
        return jsonify({"errormsg": "Please enter the correct secret_code"}), 403
    try:
        link = link.lower()
    except:
        pass
    qtext = channel_name_converter(link)
    all_data = []

    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
    for i in range(20):
        res = es.search(index=all_index_name, size=0, body={
            'query': {
                "terms": {
                        "link": qtext
                        }

            },
            "aggs": {
                "unique_channels": {
                    "terms": {"field": "conv_name.keyword",
                              "include": {
                                  "partition": i,
                                  "num_partitions": 20
                              },
                              "size": 10000}
                }
            }
        })
        response = res
        new_res = response['aggregations']["unique_channels"]['buckets']
        for i in new_res:
            all_data.append(i)
    return jsonify({"length": len(all_data), "data": all_data})


"""
Gets the list of groups/channels with a particular link in it
"""
@app.route('/all_data_redundant_extractor', methods=['POST'])
def all_data_redundant_extractor():
    conv_name = request.json.get('conv_name', None)
    link = request.json.get('link', None)
    search_after_id = request.json.get('search_after_id', None)

    secret_code = request.json.get('passcode', None)

    if conv_name is None:
        return jsonify({'errormsg': 'Please send valid link'}), 403

    if secret_code == None:
        return jsonify({"errormsg": "Uh oh, careful with the fields in your request. It has to be exactly 'secret_code'."}), 403

    if secret_code == '@lazlxEtIcS3A9rchIydzXiqg2u21fr0m':
        pass
    else:
        return jsonify({"errormsg": "Please enter the correct secret_code"}), 403
    quer = {
        'query': {
            'bool': {
                "must": [
                    {
                        "term": {
                            "conv_name.keyword": conv_name
                        }
                    },
                    {
                        "term": {
                            "link.keyword": link
                        }
                    }
                ]
            }


        },
        "sort": [{"date": {"order": f"desc"}}]
    }
    if search_after_id != None and search_after_id != 'None':
        try:
            quer['search_after'] = [search_after_id]
        except:
            pass

    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
    res = es.search(index=all_index_name, size=2000, body=quer)

    return jsonify({"data": res})


"""
Extracts the link from channel/group names
"""
@app.route('/link_extractor', methods=['POST'])
def link_extractor():
    conv_name = request.json.get('conv_name', None)
    secret_code = request.json.get('passcode', None)

    if conv_name is None:
        return jsonify({'errormsg': 'Please send valid link'}), 403

    if secret_code == None:
        return jsonify({"errormsg": "Uh oh, careful with the fields in your request. It has to be exactly 'secret_code'."}), 403

    if secret_code == '@lazlxEtIcS3A9rchIydzXiqg2u21fr0m':
        pass
    else:
        return jsonify({"errormsg": "Please enter the correct secret_code"}), 403
    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
    res = es.search(index=all_index_name, size=0, body={
        'query': {
            "term": {
                    "conv_name.keyword": conv_name
                    }

        },
        "aggs": {
            "unique_channels": {
                "terms": {"field": "link.keyword"}
            }
        }
    })
    response = res
    new_res = response['aggregations']["unique_channels"]['buckets']

    return jsonify({"data": new_res})

@app.route('/invalid_phone', methods=['GET'])
def invalid_phone():
    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
    res = es.count(index='onlineusers', body={
        'query': {
            'bool': {
                'must_not': [{
                    "regexp": {
                        "phone": {"value": "[0-9]{10,}|None", "flags": "ALL",
                                  "case_insensitive": "true", "max_determinized_states": 10000, "rewrite": "constant_score"}
                    },

                }]
            }
        }
    })
    user_name_mixup = es.count(index='onlineusers', body={
        'query': {
            'bool': {
                'must': [{
                    "regexp": {
                        "username": {"value": "[0-9]{9,}", "flags": "ALL",
                                     "case_insensitive": "true", "max_determinized_states": 10000, "rewrite": "constant_score"}
                    },

                },

                    {
                    "regexp": {
                        "userid": {"value": "[0-9]{10,}", "flags": "ALL",
                                   "case_insensitive": "true", "max_determinized_states": 10000, "rewrite": "constant_score"}
                    },

                }
                ],
                'must_not': [{
                    "regexp": {
                        "phone": {"value": "[0-9]{10,}|None", "flags": "ALL",
                                  "case_insensitive": "true", "max_determinized_states": 10000, "rewrite": "constant_score"}
                    },

                }]
            }
        }
    })
    return jsonify({'total_data': res['count'],'phone_mixed_data':user_name_mixup['count']})

@ app.route('/update_user_phone', methods=['POST'])
def update_user_phone():
    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
    try:
        secret_code = request.json.get('passcode', None)

        if secret_code == '@lazlxEtIcS3A9rchIydzXiqg2u21fr0m':
            pass
        else:
            return jsonify({"errormsg": "Please enter the correct secret_code"}), 403

        res_update = es.update_by_query(index='onlineusers', body={
            'query': {
            'bool': {
                'must_not': [{
                    "regexp": {
                        "phone": {"value": "[0-9]{10,}|None", "flags": "ALL",
                                  "case_insensitive": "true", "max_determinized_states": 10000, "rewrite": "constant_score"}
                    },

                }]
            }
        },
            "script": f"ctx._source.phone = 'None'"
        },

        )
        return jsonify({'message': 'sucess'})
    except Exception as e:
        return jsonify({'errormsg': e})

@app.route('/update_phone_with_id', methods=['POST'])
def update_phone_with_id():
    try:
        secret_code = request.json.get('passcode', None)

        if secret_code == '@lazlxEtIcS3A9rchIydzXiqg2u21fr0m':
            pass
        else:
            return jsonify({"errormsg": "Please enter the correct secret_code"}), 403

        es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
        res_update = es.update_by_query(index='onlineusers', body={
            'query': {
            'bool': {
                'must': [{
                    "regexp": {
                        "username": {"value": "[0-9]{9,}", "flags": "ALL",
                                     "case_insensitive": "true", "max_determinized_states": 10000, "rewrite": "constant_score"}
                    },

                },

                    {
                    "regexp": {
                        "userid": {"value": "[0-9]{10,}", "flags": "ALL",
                                   "case_insensitive": "true", "max_determinized_states": 10000, "rewrite": "constant_score"}
                    },

                }
                ],
                'must_not': [{
                    "regexp": {
                        "phone": {"value": "[0-9]{10,}|None", "flags": "ALL",
                                  "case_insensitive": "true", "max_determinized_states": 10000, "rewrite": "constant_score"}
                    },

                }]
            }
        },
            "script": f"ctx._source.phone = ctx._source.userid;ctx._source.userid = ctx._source.username;ctx._source.username = 'None'"
        },

        )
        return jsonify({'message': 'sucess'})
    except Exception as e:
        return jsonify({'errormsg': e})

@app.route('/scrapper_post_checker', methods=["POST"])
def scrapper_redundant_post_checker():
    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
    secret_code = request.json.get('passcode', None)
    if secret_code == None:
        return jsonify({"errormsg": "Uh oh, careful with the fields in your request. It has to be exactly 'secret_code'."}), 403

    if secret_code == '@lazlxEtIcS3A9rchIydzXiqg2u21fr0m':
        pass
    else:
        return jsonify({"errormsg": "Please enter the correct secret_code"}), 403
    keyword = request.json.get('keyword', None)
    post_no = request.json.get('post_no', None)

    if keyword is None or post_no is None:
        return jsonify({'errormsg':'Please send valid parameters through the scrapers'}),403

    if str(post_no).isnumeric() == False:
        return jsonify({'errormsg':'Please send valid parameters through the scrapers'}),403
    else:
        if int(post_no) > 1:
            post_no = (int(post_no)-1)
        else:
            post_no = post_no
    
    qtext_filter = channel_name_converter(keyword)
    res = es.search(index=all_index_name, size=1,
                    body={
                        'query': {
                            'bool':{
                                'must':[
                                    {
                                        "terms": {
                                        "link": qtext_filter
                                    }
                                    },
                                    {
                                        "term": {
                                        "msgid": post_no
                                    }
                                    }
                                ]

                            }
                        
                    }
                    }

                    )
    message = 'False'
    if len(res['hits']['hits']) > 0:
        try:
            message = 'True'
        except:
            message = 'False'

    return jsonify({'message': message,})

# Note this is temporary and should be deleted later
@app.route('/channel_id_checker', methods=['POST'])
def channel_id_checker():
    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
    channel_id = request.json.get('id', None)
    secret_code = request.json.get('passcode', None)

    if secret_code == None:
        return jsonify({"errormsg": "Uh oh, careful with the fields in your request. It has to be exactly 'secret_code'."}), 403

    if secret_code == '@lazlxEtIcS3A9rchIydzXiqg2u21fr0m':
        pass
    else:
        return jsonify({"errormsg": "Please enter the correct secret_code"}), 403

    if channel_id is None:
        return jsonify({'errormsg': 'Please send valid parameters through the scrapers'}), 403

    res = es.search(index=all_index_name, size=1, body={
        'query': {
            "term": {
                "to_id": channel_id
            }
        }
    })
    if len(res) > 0:
        return jsonify(res['hits']['hits'][0]['_source'])
    return jsonify({'errormsg': 'No data found for the channel'}),403


@app.route('/msgid_posts', methods=['POST'])
@stats_decorator
@jwt_required
def msgid_posts(default_query):
    try:
        es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)

        # Access the identity of the current user with get_jwt_identity
        jwt_all = get_jwt_identity()
        current_user = jwt_all[0]

        #logging for user acessing routes
        f = open("apilogs.txt", "a", encoding='UTF-8')
        #data_to_log = f'''DATETIME:{datetime.datetime.utcnow()}\nIPADDRESS:{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}\nUsername:{username}\n\n'''
        data_to_log = {"DATETIME":f"{datetime.datetime.utcnow().isoformat()+'+00:00'}","IPADDRESS":f"""{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}""","ENDPOINT":"/msgid_posts","User": f"{current_user}"}
        f.write(str(data_to_log))
        f.write('\n')
        f.close()

        # Function to block usage of old tokens after change of password.
        if check_tokens(jwt_all) != 'successful':
            return check_tokens(jwt_all)[0]

        print(f"""{colors.green} User {current_user} has successfully logged. Accessing /file_search API from IP: {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} {colors.default}""")

        # check if a json request was made
        if not request.is_json:
            return jsonify({"errormsg": "Missing JSON in request"}), 400

        """
        ____________________________________________________________________________________
        RATE_LIMITING CODE
        ____________________________________________________________________________________
        """
        funcall = rate_limiter(current_user)

        try:
            if int(funcall) >= 0:
                #print(type(funcall))
                print(f"{colors.green}No restrictions so far. {funcall} {colors.default}")
        except Exception as e:
            #print(type(funcall))
            print(f"{colors.red}Restrictions in effect. {funcall[0]} {colors.default}")
            return funcall


        filter = request.json.get('filter', None)
        msg_id = request.json.get('msgid', None)
        if msg_id is None and str(msg_id).isnumeric():
            return jsonify({'errormsg': 'Please send valid parameters'}), 400

        prev_post = 'None'
        next_post = 'None'
        try:
            new_msg_id = int(msg_id)
            if new_msg_id > 5:
                prev_post = int(new_msg_id - 5)
            else:
                prev_post = 0
            next_post = int(new_msg_id + 5)
        except:
            pass
        query = {
            "query": {
                "bool": {
                    "must": [default_query, {"range": {"msgid": {
                        "gte": f"{prev_post}", "lte": f"{next_post}", }}}]
                }

            },
            "sort": [{"date": {"order": f"asc"}}]

        }
        if filter is not None:
            if filter == 'forwarded':
                query['query']['bool']['must_not'] = [
                    {'match': {'forwardedfromchanid': 'None'}}
                ]

            elif filter == 'replied':
                query['query']['bool']['must_not'] = [
                    {'match': {'reply': 'None'}}
                ]
            elif filter == "file":
                query['query']['bool']['must_not'] = [
                    {'match': {'filename': 'None'}}
                ]
        res = es.search(index= all_index_name ,
                        size=100, body=query)
        return_list = []
        if len(res['hits']['hits']) > 0:
            for hit in res['hits']['hits']:
                if int(hit["_source"]['msgid']) >= prev_post and int(hit["_source"]['msgid']) <= next_post:
                    return_list.append(hit["_source"])
        return jsonify({'data': return_list})
    except Exception as e:
        print(e)
        return jsonify({'data': 'Sorry could not process your request at the moment. Please contact service provider for further more info.'}), 400

@app.route('/docker_ip_tracker', methods=["POST"])
def docker_ip_tracker():
    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
    secret_code = request.json.get('passcode', None)
    if secret_code == None:
        return jsonify({"errormsg": "Uh oh, careful with the fields in your request. It has to be exactly 'secret_code'."}), 403

    if secret_code == '@lazlxEtIcS3A9rchIydzXiqg2u21fr0m':
        pass
    else:
        return jsonify({"errormsg": "Please enter the correct secret_code"}), 403
    ip_address = request.json.get('ip_address', None)
    status = request.json.get('status', None)
    docker_image = request.json.get('docker_image', None)
    

    if ip_address is None or status is None or docker_image is None:
        return jsonify({'errormsg': 'Please send valid parameters through the scrapers'}), 403


    #creation of docker es index
    if es.indices.exists(index="docker_ip"):
            print('index founbd')
            pass
    else:
            es.indices.create(index='docker_ip', ignore=400)
    new_obj = {"docker_image":docker_image}
    body_obj = {"ip_address":ip_address,"status":status,"docker_image":docker_image}
    hash_str = str(new_obj)
    hashasid = hashlib.md5(hash_str.encode('UTF-8')).hexdigest()
    try:
        res = es.index(index='docker_ip', body=body_obj,id=hashasid )
        return jsonify({'message': f'sucessfully added the data for dockerimage {docker_image}'}),200
    except Exception as e:
            print(e)
            return jsonify({'error': 'sorry could not insert the data'}),400

@app.route('/docker_ip_getter', methods=["get"])
def docker_ip_getter():
    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
    secret_code = request.json.get('passcode', None)
    if secret_code == None:
        return jsonify({"errormsg": "Uh oh, careful with the fields in your request. It has to be exactly 'secret_code'."}), 403

    if secret_code == '@lazlxEtIcS3A9rchIydzXiqg2u21fr0m':
        pass
    else:
        return jsonify({"errormsg": "Please enter the correct secret_code"}), 403
    try:
        res = es.search(index='docker_ip', size=100,body={
            'query':{
                'match_all':{}
            }
        } )
        return_list = []
        if len(res['hits']['hits']) >= 1:
            for hit in res['hits']['hits']:
                return_list.append(hit["_source"])
        return jsonify({'data':return_list}),200
    except Exception as e:
            print(e)
            return jsonify({'error': 'sorry could not process the request at the moment'}),400

@app.route('/channel_scrape_checker', methods=["POST"])
def channel_scrape_checker():
    es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
    secret_code = request.json.get('passcode', None)
    if secret_code == None:
        return jsonify({"errormsg": "Uh oh, careful with the fields in your request. It has to be exactly 'secret_code'."}), 403

    if secret_code == '@lazlxEtIcS3A9rchIydzXiqg2u21fr0m':
        pass
    else:
        return jsonify({"errormsg": "Please enter the correct secret_code"}), 403
    keyword = request.json.get('keyword', None)

    if keyword == None:
        return jsonify({"errormsg": "Uh oh, careful with the fields in your request. It has to be exactly"}), 403
    qtext_filter = channel_name_converter(keyword)
    res = es.search(index=all_index_name, size=1,
                    body={
                        'query': {
                                        "terms": {
                                        "link": qtext_filter
                                    }
                    }
                    }
                    )
    status = 'Unscrapped'
    if len(res['hits']['hits']) > 0:
        try:
            status = 'Scrapped'
        except:
            message = 'Unscrapped'

    return jsonify({'message': status})

def bulk_index_scipter(arr,index_name):
    for data in arr:
        hex_str = {'date': data['date'],'message': data['message'], 'msgid': data['msgid']}
        hash_id = hashlib.md5(str(hex_str).encode('UTF-8')).hexdigest()
        yield{
                    "_index": index_name,
                    "_type": '_doc',
                    "_id": hash_id,
                    "_source": data
                }


@app.route('/v2/indexer/edu_bulk_index', methods=['POST'])
def edu_bulk_index():
    es = Elasticsearch(elastichost)
    secret_code = request.json.get('passcode', None)
    index_name = request.json.get('index_name',None)
    data = request.json.get('data',None)
    bulk_size = request.json.get('bulk_size',None)
    default_chunk_size=1000
    if bulk_size != None:
        try:
            default_chunk_size = int(bulk_size)
        except:
            pass


    if secret_code == None:
            return jsonify({"errormsg": "Uh oh, careful with the fields in your request. It has to be exactly 'secret_code'."}), 403
    if secret_code == '@lazlxEtIcS3A9rchIydzXiqg2u21fr0m':
            pass
    else:
            return jsonify({"errormsg": "Please enter the correct secret_code"}), 403
    if index_name is None or data is None:
        return jsonify({'errormsg': 'Please send valid parameters through the scrapers'}), 403
    new_index_name = index_name
    if index_name != 'uncategorized':
            new_index_name= f'{index_name}_v2'
    # check if a json request was made
    try:
        fail = 0
      
        try:
            print(new_index_name,'index_name')
            for ok, result in helpers.streaming_bulk(es, bulk_index_scipter(data,new_index_name), chunk_size=default_chunk_size, refresh=False, request_timeout=60*3,  yield_ok=False):
            
                if not ok:
                    fail += 1
        except:
            pass
        return jsonify({"info": f"failed:{fail} indexed:{(len(data)-fail)}"}), 200
    except Exception as e:
        return jsonify({"info": f"""Request not valid. the following error occurred{e}"""}), 400
    
@app.route('/v2/indexer/uncat_index', methods=['POST'])
def uncat_index():
    es = Elasticsearch(elastichost)
    secret_code = request.json.get('passcode', None)
    data = request.json.get('data',None)
    bulk_size = request.json.get('bulk_size',None)
    default_chunk_size=1000
    if bulk_size != None:
        try:
            default_chunk_size = int(bulk_size)
        except:
            pass

    if secret_code == None:
            return jsonify({"errormsg": "Uh oh, careful with the fields in your request. It has to be exactly 'secret_code'."}), 403
    if secret_code == '@lazlxEtIcS3A9rchIydzXiqg2u21fr0m':
            pass
    else:
            return jsonify({"errormsg": "Please enter the correct secret_code"}), 403

    # check if a json request was made
    try:
        fail = 0
        try:
            for ok, result in helpers.streaming_bulk(es, bulk_index_scipter(data,'uncategorized'), chunk_size=default_chunk_size, refresh=False, request_timeout=60*3,  yield_ok=False):
            
                if not ok:
                    fail += 1
        except:
            pass
        return jsonify({"info": f"failed:{fail} indexed:{(len(data)-fail)}"}), 200
    except Exception as e:
        return jsonify({"info": f"""Request not valid. the following error occurred{e}"""}), 400

def user_bulk_index_scipter(arr, index_name):
    for data in arr:
        hashid_data = str({"userid": data["userid"], "username": data["username"],
                           "userfirstname": data["userfirstname"], "userlastname": data["userlastname"]})
        hash_id = hashlib.md5(hashid_data.encode('UTF-8')).hexdigest()
        yield{
            "_index": index_name,
            "_type": '_doc',
            "_id": hash_id,
            "_source": data
        }

@app.route('/v2/telethon_userbulk', methods=['POST'])
def telethon_userbulk():
    es = Elasticsearch(elastichost)
    secret_code = request.json.get('passcode', None)
    index_name = request.json.get('index_name', None)
    data = request.json.get('data', None)
    if secret_code == None:
        return jsonify({"errormsg": "Uh oh, careful with the fields in your request. It has to be exactly 'secret_code'."}), 403
    if secret_code == '@lazlxEtIcS3A9rchIydzXiqg2u21fr0m':
        pass
    else:
        return jsonify({"errormsg": "Please enter the correct secret_code"}), 403
    if index_name is None or data is None:
        return jsonify({'errormsg': 'Please send valid parameters through the scrapers'}), 403
    # check if a json request was made
    try:

        fail = 0
        for ok, result in helpers.streaming_bulk(es, user_bulk_index_scipter(data, index_name), chunk_size=1000, refresh=False, request_timeout=60*3,  yield_ok=False):

            if not ok:
                fail += 1
        return jsonify({"info": f"failed:{fail} indexed:{(len(data)-fail)}"}), 200
    except:
        return jsonify({"info": f"""Request not valid."""}), 400


"""
Ingests maigret data to ES
"""
@app.route('/v2/username_scanner_index', methods=['POST'])
def username_scanner_index():
    es = Elasticsearch(elastichost)
    secret_code = request.json.get('passcode', None)
    data = request.json.get('data', None)
    hash_id = request.json.get('hash_id', None)

    if secret_code == None or data == None:
        return jsonify({"errormsg": "Uh oh, careful with the fields in your request. It has to be exact."}), 403

    if secret_code == '@lazlxEtIcS3A9rchIydzXiqg2u21fr0m':
        pass

    else:
        return jsonify({"errormsg": "Please enter the correct secret_code"}), 403

    if es.indices.exists(index="maigret_index"):
        print('index founbd')
        pass
    else:
        es.indices.create(index='maigret_index', ignore=400)
    new_obj = {'data': data}
    res = es.index(index='maigret_index', body=new_obj, id=hash_id)
    return jsonify({'messsage': 'sucess'})





"""
Extracts maigret data from ES and executes maigret library
Refer -> https://github.com/soxoj/maigret 
"""
#maigret code need to be delted later
# @app.route('/get_username_scanner', methods=['POST'])
# #@jwt_required
# def get_username_scanner():
#     try:
#         es = Elasticsearch(elastichost)
        
#         try:
#             username = request.json.get('username', None)
#         except Exception as e:
#             return jsonify({"errormsg": "Please enter only allowed characters or check your input again."}),403

#         if username == None:
#             return jsonify({"errormsg": "Uh oh, careful with the fields in your request. It has to be exact."}), 403
        
#         if '>' in username or '[' in username or ']' in username or "\\" in username or "/" in username or "'" in username or '"' in username: 
#             return jsonify({"errormsg": "Uh oh, careful with the fields in your request. Some special characters like backslashes, quotes etc are not allowed in the search."}), 403

#         # os.chdir(r'/root/maigret/maigret/')
#         search_cmd = '-C'
#         input_email_validator = email_validator(username)
        
#         if input_email_validator == True:
#             search_cmd = '-J'

        
#         new_array = ['python3', '/root/maigret/maigret.py',username, '-a', search_cmd]

#         if search_cmd == '-J':
#             new_array.append('ndjson')

#         sub_res = subprocess.Popen( new_array ,  stdout=subprocess.PIPE)
#         sub_res.wait()

#         result_str = sub_res.stdout.read()
#         encoded_key = hashlib.md5(str(username).encode('UTF-8')).hexdigest()
#         res = es.get(index="maigret_index", id=encoded_key)
#         return_list = res['_source']['data']
#         return jsonify({'data': return_list})
#     except Exception as e:
#         return jsonify({'errormsg':'sorry could noit process request at the moment'}),403

@app.route('/get_username_scanner', methods=['POST'])
@jwt_required
def get_username_scanner():
    try:
        
        try:
            username = request.json.get('username', None)
        except Exception as e:
            return jsonify({"errormsg": "Please enter only allowed characters or check your input again."}),403

        if username == None:
            return jsonify({"errormsg": "Uh oh, careful with the fields in your request. It has to be exact."}), 403
        
        if '>' in username or '[' in username or ']' in username or "\\" in username or "/" in username or "'" in username or '"' in username: 
            return jsonify({"errormsg": "Uh oh, careful with the fields in your request. Some special characters like backslashes, quotes etc are not allowed in the search."}), 403
        res = Scraper_facade(username).scraper_initator()
        return jsonify({'data': res})
        # os.chdir(r'/root/maigret/maigret/')

    except Exception as e:
        return jsonify({'errormsg':'sorry could noit process request at the moment'}),403


"""
Report downloader for Maigret user search
"""
@app.route('/download_username_scanner', methods=['POST'])
#@jwt_required
def download_username_scanner():
    es = Elasticsearch(elastichost)
    try:
        username = request.json.get('username', None)
    except Exception as e:
        return jsonify({"errormsg": "Please enter only allowed characters or check your input again."}),403
    
    download_type = request.json.get('download_type', None)
    user_extract_loc = r'/root/telegram/reports'

    if username == None or download_type == None:
        return jsonify({"errormsg": "Uh oh, careful with the fields in your request. It has to be exact."}), 403
    
    if '>' in username or '[' in username or ']' in username or "\\" in username or "/" in username or "'" in username or '"' in username: 
        return jsonify({"errormsg": "Uh oh, careful with the fields in your request. Some special characters like backslashes, quotes etc are not allowed in the search."}), 403


    """
    special char sanitize
    """
    checks = re.compile('[!#$%^&()<>?/\|}{~:]')

    if(checks.search(username) == None):
        print("Valid format of username.")
    else:
        return jsonify({"errormsg": "You can not enter special characters inside the field except '_, @ , -, .'. From /download_username_scanner API."}), 403

    # os.chdir(r'/root/maigret/maigret/')
    download_type = download_type.lower()
    filename = f'report_{username}.{download_type}'

    safe_path = safe_join(user_extract_loc, filename)
    file_loc = os.path.join(user_extract_loc, filename)

    if os.path.exists(safe_path):
        return send_file(safe_path, as_attachment=True)
    search_cmd = '-C'
    if download_type == 'pdf':
        search_cmd = '-P'
    sub_res = subprocess.Popen(
        ['python3', '/root/maigret/maigret.py',
         username, '-a', search_cmd],  stdout=subprocess.PIPE)
    sub_res.wait()

    result_str = sub_res.stdout.read()
    return send_file(safe_path, as_attachment=True)

"""
Expiration Mail sender
"""
@app.route('/v2/report_expiration_sender', methods=['POST'])
def report_expiration_sender():
    try:
        es = Elasticsearch(elastichost)
        password = None 
        email = request.json.get('email', None)
        username = request.json.get('username', None)
        date = request.json.get('date', None)
        secret_code = request.json.get('passcode', None)

        if secret_code == None or email == None or username == None or date  == None:
            return jsonify({"errormsg": "Uh oh, careful with the fields in your request. It has to be exact."}), 403

        if secret_code == '@lazlxEtIcS3A9rchIydzXiqg2u21fr0m':
            pass

        else:
            return jsonify({"errormsg": "Please enter the correct secret_code"}), 403

        if es.indices.exists(index="user_token_expiry"):
            print('index found')
            pass
        else:
            es.indices.create(index='user_token_expiry', ignore=400)
        
        hashasid = hashlib.md5(str(email).encode('UTF-8')).hexdigest()
        try:
            res1 = es.get(index="user_token_expiry", id=hashasid)
            return jsonify({'message': f'Date:{datetime.datetime.utcnow().isoformat()}\tThe email has already been sent to the user:\t{username} with email:\t{email}'})
        except:
            pass
        body_obj = {'email': email, 'username': username, 'date': date}
        
        try:
            responseM = cred_mail_sender(email,username,None,date,'expiration_notice')
            if responseM == True:
                es.index(index='user_token_expiry', id=hashasid, body=body_obj)
                return jsonify({'messsage': f'successfully sent mail to username {username} and email {email}'})
        except Exception as e:
            return jsonify({"errormsg":f"Something went wrong while sending reminder email. {responseM} "}),403
    except Exception as e:
        return jsonify({"errormsg":f"Something went wrong with email.Please try again later "}),403


"""
Deactivates/Reactivates/Deletes customer accounts in Bulk.
"""
@app.route('/v2/bulkOps', methods=['POST'])
@jwt_required
def bulk_ops():
    try:
        # Access the identity of the current user with get_jwt_identity
        jwt_all = get_jwt_identity()
        current_user = jwt_all[0]
        print(f"""{colors.green} User {current_user} has successfully logged. Accessing /v2/admin/getallclients API from IP: {request.environ.get("HTTP_X_REAL_IP", request.remote_addr)} {colors.default}""")
        
        if current_user != 'administrator':
            
            # write access logs
            try:
                with open("unauthorizedbulkOps_accesslogs.txt","a", encoding="UTF-8") as bulkOpsWrite:
                    data_to_log = f'''DATETIME:{datetime.datetime.utcnow().isoformat()+'+00:00'}\nIPADDRESS:{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}\nUsername:{current_user}\n\n'''
                    bulkOpsWrite.write(data_to_log)
            except Exception as e:
                pass
        
            return jsonify({"errormsg":"Only administrator account is allowed to use this route."}), 403
        
        # write access logs from administrator actions
        try:
            with open("bulkOps_accesslogs.txt","a", encoding="UTF-8") as bulkOpsWrite:
                data_to_log = f'''DATETIME:{datetime.datetime.utcnow().isoformat()+'+00:00'}\nIPADDRESS:{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}\nUsername:{current_user}\n\n'''
                bulkOpsWrite.write(data_to_log)
        except Exception as e:
            pass
        
        list_of_emails = request.json.get('email_list', None)
        
        if not isinstance(list_of_emails,list):
            return jsonify({"errormsg":"Should be a list type."}), 403 , {'Content-Type': 'application/json'}
        
        set_authorization = request.json.get('set_auth_to', None) # either True or False

        delete_accounts = False
        delete_accounts = request.json.get('delete_selected', None) # either True or False
        delete_accounts_pass = request.json.get('delete_password', None) # either True or False

        if list_of_emails == None or list_of_emails == [] :
            return jsonify({"errormsg":"Empty email list will not work."}), 403
        
        if (set_authorization != 'False' and set_authorization != 'True' and set_authorization != 'None'):
            return jsonify({"errormsg":"Invalid value for authorization. Set either True, False or None"}), 403


        status_message = []

        conn = psycopg2.connect(database= "client_database", user= database_username , password= database_password , host= host_name, port= db_port)
        cursor = conn.cursor()
        conn.autocommit = True

        for some in list_of_emails:
            
            if set_authorization != None or set_authorization!= 'None':
                try:
                    print(f"on email {some}")
                    q =f"""UPDATE client_database set isauthorized='{set_authorization}' where email='{some}' and username!='administrator'"""
                    cursor.execute(q)
                    
                    if set_authorization == True or set_authorization == 'True':
                        stat_msg = f"{colors.green}{some} has been activated.{colors.default}"
                        print(stat_msg)
                        status_message.append(stat_msg)
                    
                    if set_authorization == False or set_authorization == 'False':
                        stat_msg2 = f"{colors.red}{some} has been deactivated.{colors.default}"
                        print(stat_msg2)
                        status_message.append(stat_msg2)

                except Exception as e:
                    print(e,"error at:", some)

            if delete_accounts == True or delete_accounts == 'True':
                if delete_accounts_pass == "aa4b3f95c5a2e0b38be795d0c9be07e3f73f8dc80cee9fc2cc859b029199cc10":
                    try:
                        string_del = f"""DELETE from client_database where email='{some}' and username!='administrator'"""
                        print(string_del)
                        cursor.execute(string_del)
                        stat_del = f"{some} has been deleted."
                        print(stat_del)
                        status_message.append(stat_del)

                        # write access logs from administrator actions
                        try:
                            with open("bulkDeleteByAdministrator.log","a", encoding="UTF-8") as bulkOpsWrite:
                                data_to_log = f'''DATETIME:{datetime.datetime.utcnow().isoformat()+'+00:00'}\nIPADDRESS:{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}\nUsername:{current_user}\nDeletedEmail:{some}\n\n'''
                                bulkOpsWrite.write(data_to_log)
                        except Exception as e:
                            pass

                    except Exception as e:
                        print(e,"error at:", some)
        
        try:
            q1 =f"""SELECT count(*) from client_database where isauthorized='False'"""
            cursor.execute(q1)
            m = cursor.fetchall()[0][0]

            q2 =f"""SELECT count(*) from client_database"""
            cursor.execute(q2)
            z = cursor.fetchall()[0][0]

            print(f"{m} accounts are deactivated out of {z} total accounts.")
            
            # return success message
            return jsonify({"data": status_message}), 200 , {'Content-Type': 'application/json'}
        except Exception as e:
            print("Count error.")
    
    except Exception as e:
        return jsonify({"errormsg":"Some error in /v2/bulkOps"}), 200 , {'Content-Type': 'application/json'}


@app.route('/v2_user_channel_search_data', methods=["GET"])
@jwt_required
def v2_user_channel_search_data():
    
    # Access the identity of the current user with get_jwt_identity
    jwt_all = get_jwt_identity()
    current_user = jwt_all[0]
    
    # Function to block usage of old tokens after change of password.
    if check_tokens(jwt_all) != 'successful':
        return check_tokens(jwt_all)[0]

    # check if a json request was made
    if not request.is_json:
        return jsonify({"errormsg": "Missing JSON in request"}), 400

    if current_user == 'administrator':

        es = Elasticsearch(elastichost)
        #creating index incase no such index is present
        if es.indices.exists(index="user_channel_search"):
                print("Index user_channel_search exists.")
        
        else:
            print("Creating index user_channel_search")
            es.indices.create(index='user_channel_search', ignore=400)
            
        res = es.search(index='user_channel_search', size=100,
                        query={"match_all":{}}
                        )
        return_list = []
        if len(res['hits']['hits']) > 0:
            for hit in res['hits']['hits']:
                return_list.append(hit['_source'])
        if len(return_list) < 1:
            return jsonify({"msg": "No user channel search data available"}), 200
        else:
            return jsonify({'data': return_list})
    else:
        return jsonify({"errormsg": "You dont have permission to acess this route"}), 400
 
@app.route('/forwaded_counter',methods=['GET'])
def forwaded_conuter():
    es = Elasticsearch(elastichost)
    res= es.count(index=all_index_name,body={
    "query": {
        "exists": {
            "field": "forwardedromchanid"
        }
         }
        }
        )
    print(res)
    return jsonify(res)
    

@ app.route('/forwaded_data_extractor', methods=['POST'])
def forwaded_data_extractor():
    try:
        search_after_id = request.json.get('search_after_id', None)
        es = Elasticsearch(elastichost, timeout=30, max_retries=10, retry_on_timeout=True)
        all_data = []
        decode_key = "None"
        try:
            if search_after_id != None and search_after_id != 'None':
                decode_key = search_after_id
        except:
            print('could not intiate the provided search after key')
        quer = {
            "query": {
                 "exists": {
            "field": "forwardedromchanid"
        }
            },
            "sort": [
                {"date": "asc"},

            ]

        }
        if decode_key != 'None':
            try:
                print('activated')
                quer['search_after'] = [decode_key]
            except:
                print('search after could not ')
        resp = es.search(index=all_index_name, size=1000, body=quer)
        encoded_key = 'None'
        try:
            if len(resp['hits']['hits']) > 1:
                encoded_key = resp['hits']['hits'][-1]['sort'][0]
        except:
            print('could not encrypr/add search after key')
        return_list = []
        for hit in resp['hits']['hits']:
            return_list.append(hit["_source"])

        return jsonify({'data': return_list, 'search_id': encoded_key})
    except Exception as e:
        return jsonify({'errormsg': f'{e}'})

"""
Download breached data report from /v2/breach_search
as a .CSV file.
"""
@app.route('/v2/breach_csv_report', methods=['POST'])
@jwt_required
def breach_csv_report():
    try:

        size_of_download = 10000 # put anywhere between 1 and 10000

        ########################################################################
        # Access the identity of the current user with get_jwt_identity
        jwt_all = get_jwt_identity()
        current_user = jwt_all[0]
        

        # Function to block usage of old tokens after change of password.
        if check_tokens(jwt_all) != 'successful':
            return check_tokens(jwt_all)[0]
        ########################################################################
        
        #logging for user acessing routes
        f = open("apilogs.txt", "a", encoding='UTF-8')
        #data_to_log = f'''DATETIME:{datetime.datetime.utcnow()}\nIPADDRESS:{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}\nUsername:{username}\n\n'''
        data_to_log = {"DATETIME":f"{datetime.datetime.utcnow().isoformat()+'+00:00'}","IPADDRESS":f"""{request.environ.get("HTTP_X_REAL_IP", request.remote_addr)}""","ENDPOINT":"/v2/breach_csv_report","User": f"{current_user}"}
        f.write(str(data_to_log))
        f.write('\n')
        f.close()

        r = redis.Redis(db=1)
        file_hash = request.json.get('file_hash', None)
        if file_hash is None or file_hash is 'None':
            return jsonify({'errormsg': 'Please send valid value'})
        decoed_key = cryptocode.decrypt(str(file_hash), '#random_pass1&*$@')
        if r.exists(decoed_key) == 0:
            return jsonify({'errormsg': 'No data found for the keyword'})
        new_data = r.get(decoed_key).decode()
        conv_data = ast.literal_eval(new_data)
        search_value = decoed_key.rsplit('$')[-1]
        if '.' in search_value:
            search_value = search_value.replace('.', '_')
        print(search_value)

        new_date = datetime.datetime.now().isoformat()

        file_name = f'{search_value}_{new_date}_breached_data.csv'

        program_path = os.getcwd()
        os.chdir(folder_create())

            
        rows_name = ['Domain Name','Database',
                        'Email', 'Username', "Name", 'Password', 'Hashed Password', 'Phone', 'Ip Address']
        
        with open(file_name, 'w', encoding='UTF-8') as csvfile:
            csvwriter = csv.writer(csvfile)
            csvwriter.writerow(rows_name)
            
            for data in conv_data['data']:
                main_parent = data
                domain = main_parent['query']
                database = main_parent['database_name']
                email = main_parent['email']
                username = main_parent['username']
                name = main_parent['name']
                password = main_parent['password']
                hashed_password = main_parent['hashed_password']
                phone = main_parent['phone']
                ip_address = main_parent['ip_address']
                data_row = [domain, database, email, username, name,
                            password, hashed_password, phone, ip_address]
                csvwriter.writerow(data_row)
            
        os.chdir(program_path)
        print(file_name)
        safe_path = safe_join(r'/root/csv_reports/', file_name)
        print(safe_path)
            
        try:
            return send_file(safe_path, as_attachment=True)
        except FileNotFoundError:
            return jsonify({'errormsg': 'Sorry could not retrieve file at the moment, Please try again later.'}), 403   
    except:
        return jsonify({'errormsg': 'Sorry could not retrieve file at the moment, Please try again later.'}), 403   

###############################################################
if  __name__ == '__main__':
    app.run( host = '127.0.0.1', threaded = True, debug = False )



#======================================
#         E N D  O F  C O D E         #
#======================================
