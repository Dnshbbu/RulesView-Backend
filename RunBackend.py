from flask import Flask, jsonify, abort, make_response
from flask_restful import Api, Resource, reqparse, fields, marshal, abort
from py2neo import *
import json
from flask_cors import CORS
from ipaddress import *
import werkzeug
import os
from netaddr import *
import re
import random
import time
import CSVSplit_generalised_v3
import logging
import RawRuleslist
import configparser
import Heavylifting as inherit


app = Flask(__name__, static_url_path="")
api = Api(app)
CORS(app) #to prevent CORS issue in the browsers
parser = reqparse.RequestParser() #to parse args in the post request

#config object to pull the password from conf file
config = configparser.ConfigParser()
config.read('conf/creds.ini')

# UPLOAD_FOLDER = 'uploads/'
UPLOAD_FOLDER = config.get('uploads', 'UPLOAD_FOLDER')

# Gets or creates a logger
logger = logging.getLogger(__name__)

# set log level
logger.setLevel(logging.INFO)


dirLogFolder = config.get('logs', 'LOGS_FOLDER')

# Create target Directory if don't exist
if not os.path.exists(dirLogFolder):
    os.mkdir(dirLogFolder)
    print("[*] Directory \'"+dirLogFolder+"\' Created ")
else:    
    print("[*] Directory \'"+dirLogFolder+"\' already exists")

# define file handler and set formatter
LOG_FILE = config.get('logs', 'LOGS_FOLDER')+'\\sample.log'
file_handler = logging.FileHandler(LOG_FILE)
formatter = logging.Formatter(
    '%(asctime)s | %(levelname)s | %(name)s | %(funcName)s | :%(lineno)s | %(message)s', datefmt='%y-%m-%d %H:%M:%S')
file_handler.setFormatter(formatter)

# add file handler to logger
logger.addHandler(file_handler)

# All rules

#get all relationship types
class allRels(Resource):
    def get(self):
        try:
            logger.info("ClassName: === " + self.__class__.__name__+" ===")
            statement = "MATCH (n:Hosts)-[r]-(m:Hosts) RETURN DISTINCT type(r) as rels"
            logger.info("Query: " + statement)
            out = inherit.allRels(statement)
            message = ""
            return [out,message]
        except Exception as e:
            logger.exception("%s", e)

#get all firewall names and policynames with grouping for dropdown
class GetAllFwPolicies(Resource):
    def get(self):
        try:
            logger.info("ClassName: === " + self.__class__.__name__+" ===")
            # logger.info("Query: " + statement)            
            db,fwpolicies = RawRuleslist.getalltablenames()
            
            #Loop to group the policyname and firewallname, and provide data to the frontend in required format
            allpolicies =[]
            x = 0
            while x<len(db):
                out={}
                po_wrap=[]
                print(db[x])
                print(fwpolicies[x])
                for i in fwpolicies[x]:
                    for j in i:
                        out = {}
                        po ={}
                        po = {"value": j, "viewValue": j}
                        po_wrap.append(po)
                out = {"name": db[x], "pokemon": po_wrap}
                allpolicies.append(out)
                x+=1
            return[allpolicies,db]  #allpolicies: policies with firewall grouping; db: firewallnames      
            
        except Exception as e:
            logger.exception("%s", e)
    
#get all group nodes and links for Group heirarchy page
class GroupHeirarchy(Resource):
    def get(self):
        try:
            logger.info("ClassName: === " + self.__class__.__name__+" ===")
            statement = "MERGE (d:Groups) RETURN d"
            #statement ="MERGE (d:Hosts) RETURN d"
            logger.info("Query: " + statement)
            # inherit = HeavyLifting()
            NoDupNode,Link = inherit.groupheirarchy(statement)
            out = {}
            out = {"nodes": NoDupNode, "edges": Link}
            return out

        except Exception as e:
            logger.exception("%s", e)


###see if necessary;;;;
class allGroups(Resource):
    def get(self):
        try:
            logger.info("ClassName: === " + self.__class__.__name__+" ===")
            statement = "MERGE (d:Groups) RETURN d"
            logger.info("Query: " + statement)
            # inherit = HeavyLifting()
            out = inherit.allGroups(statement)
            return out
        except Exception as e:
            logger.exception("%s", e)


# Search nodes
class SearchNetwork(Resource):
    def post(self):
        try:
            logger.info("ClassName: === " + self.__class__.__name__+" ===")
            parser.add_argument('searchnode', type=str)
            args = parser.parse_args()
            checkip = args['searchnode']
            statement = "MATCH (n:Hosts) RETURN n LIMIT 10000"
            logger.info("Query: " + statement)
            # inherit = HeavyLifting()
            MatchRel, finalgrouping = inherit.check(statement, checkip)
            finalformat = finalformating()
            NoDupNode, Link = finalformat.format_w_grouping(
                MatchRel, finalgrouping)
            out = {}
            out = {"nodes": NoDupNode, "edges": Link}
            print(out)
            return out
        except Exception as e:
            logger.exception("%s", e)

#final formating to provide to frontend
class finalformating():
    def format_w_grouping(self, MatchRel, finalgrouping, GrpNodes):
        Link = []
        Node = []
        NoDupNode = []

        for y in MatchRel:
            for z in y:
                nodes_s = {}
                nodes_datawrapper_s = {}
                action_taken_s = 0
                action_taken_d = 0

                # print("===========================printing z=====================")
                # print(z)
                # for k in z['s'].keys():
                #     nodes_grp[k] = z['s'][k]
                #     #print(k,z['s'][k])
                #     print(nodes_grp)
                for x in finalgrouping:
                    nodes_datawrapper_s = {}
                    nodes_s = {}
                    if z['s']['Name'] == x['ChildName']:
                        action_taken_s = 1
                        # nodes_grp = {}
                        # for k in z['s'].keys():  # Add all properties
                        #     nodes_grp[k] = z['s'][k]
                        # # print(nodes_grp)
                        # nodes_datawrapper_grp = {}
                        # nodes_grp['id'] = x['Parent_IP']
                        # nodes_grp['color'] = x['color']
                        # nodes_datawrapper_grp['data'] = nodes_grp
                        # Node.append(nodes_datawrapper_grp)
                        nodes_s = {}
                        nodes_datawrapper_s = {}
                        nodes_s['id'] = z['s']['Name']
                        nodes_s['parent'] = x['ParentName']
                        nodes_s['color'] = x['color']
                        for k in z['s'].keys():  # Add all properties
                            nodes_s[k] = z['s'][k]
                        # print(nodes_grp)
                        nodes_datawrapper_s['data'] = nodes_s
                        Node.append(nodes_datawrapper_s)
                        break
                if action_taken_s == 0:
                    nodes_s['id'] = z['s']['Name']
                    for k in z['s'].keys():   # Add all properties
                        nodes_s[k] = z['s'][k]
                    nodes_datawrapper_s['data'] = nodes_s
                    Node.append(nodes_datawrapper_s)
                    # else:
                    #       nodes_s['id']=z['s']['Name']
                    #       nodes_datawrapper_s['data']=nodes_s
                    #       Node.append(nodes_datawrapper_s)
                    # break
                # Node.append(nodes_datawrapper_s)
                for y in finalgrouping:
                    action_taken_d = 0
                    nodes_datawrapper_d = {}
                    nodes_d = {}
                    if z['d']['Name'] == y['ChildName']:
                        action_taken_d = 1
                        # nodes_grp = {}
                        # for k in z['d'].keys():  # Add all properties
                        #     nodes_grp[k] = z['d'][k]
                        # # print(nodes_grp)
                        # nodes_datawrapper_grp = {}
                        # nodes_grp['id'] = y['Parent_IP']
                        # nodes_grp['color'] = y['color']
                        # nodes_datawrapper_grp['data'] = nodes_grp
                        # Node.append(nodes_datawrapper_grp)
                        nodes_d = {}
                        nodes_d['id'] = z['d']['Name']
                        nodes_d['parent'] = y['ParentName']
                        nodes_d['color'] = y['color']
                        for k in z['d'].keys():   # Add all properties
                            nodes_d[k] = z['d'][k]
                        # print(nodes_grp)
                        nodes_datawrapper_d['data'] = nodes_d
                        Node.append(nodes_datawrapper_d)
                        break
                if action_taken_d == 0:
                    nodes_d['id'] = z['d']['Name']
                    for k in z['d'].keys():    # Add all properties
                        nodes_d[k] = z['d'][k]
                    # print(nodes_grp)
                    nodes_datawrapper_d['data'] = nodes_d
                    Node.append(nodes_datawrapper_d)
                    # else:
                    #       nodes_d['id']=z['d']['Name']
                    #       nodes_datawrapper_d['data']=nodes_d
                    #       Node.append(nodes_datawrapper_d)
                    # break
                # Node.append(nodes_datawrapper_d)
        for eve in GrpNodes:
            print("+++++++++++++++++++ Printing every nodes in groups+++++++++++")
            print(eve)
            nodes_datawrapper_grp = {}
            nodes_datawrapper_grp['data'] = eve
            Node.append(nodes_datawrapper_grp)
        for x in Node:
            if x not in NoDupNode:
                NoDupNode.append(x)
        for y in MatchRel:
            for z in y:
                links_datawrapper = {}
                links = {}
                links['source'] = z['s']['Name']
                links['target'] = z['d']['Name']
                links['service'] = z['r']['name']
                for k in z['r'].keys():   # Add all properties
                    links[k] = z['r'][k]
                # print(z['r'])
                links_datawrapper['data'] = links
                Link.append(links_datawrapper)
        # print(NoDupNode,Link)
        return(NoDupNode, Link)

#Search relationship
class Relationship(Resource):
    def get(self, searchterm, limit):
        try:
            logger.info("ClassName: === " + self.__class__.__name__+" ===")
            statement = "MATCH p=(s:Hosts)-[r:`"+searchterm + \
                "`]->(d:Hosts) RETURN s,d,r LIMIT "+limit
            # inherit = HeavyLifting()
            logger.info("Query: " + statement)
            MatchRel, finalgrouping, GrpNodes = inherit.GetRelationshipFromNeo4jv3(
                statement)
            finalformat = finalformating()
            NoDupNode, Link = finalformat.format_w_grouping(
                MatchRel, finalgrouping, GrpNodes)
            out = {}
            out = {"nodes": NoDupNode, "edges": Link}
            return out
        except Exception as e:
            logger.exception("%s", e)

#get selected rule number from sqlite table to neo4j
class GetSelectedRules(Resource):
    def post(self):
        try:
            logger.info("ClassName: === " + self.__class__.__name__+" ===")
            parser.add_argument('selectedruleno', type=str)
            parser.add_argument('firewallname', type=str)
            parser.add_argument('policyname', type=str)
            args = parser.parse_args()
            selectedruleno = str(args['selectedruleno'])
            firewallname = str(args['firewallname'])
            policyname = str(args['policyname'])
            
            selectedruleno  = json.loads(selectedruleno)
            
            selectednum=""
            selrulno =0
            while selrulno<len(selectedruleno):
                if (selrulno==len(selectedruleno)-1):
                    selectednum = selectednum+"r.`No.`=\'"+str(selectedruleno[selrulno])+"\'" 
                else:
                    selectednum = selectednum+"r.`No.`=\'"+str(selectedruleno[selrulno])+"\' OR "
                selrulno+=1
            statement = "MATCH (s:Hosts)-[r{`policyname`:\'"+policyname+"\',`firewallname`:\'"+firewallname+"\'}]->(d:Hosts) WHERE "+selectednum+" RETURN s,d,r"
            print(statement)
            
            logger.info("Query: " + statement)
            
            # inherit = HeavyLifting()            
            MatchRel, finalgrouping, GrpNodes, message, status = inherit.getselectrules(statement)
            finalformat = finalformating()
            NoDupNode, Link = finalformat.format_w_grouping(MatchRel, finalgrouping, GrpNodes)
            out = {}
            out = {"nodes": NoDupNode, "edges": Link}
            # return [out,message]
            return {
                        'data': out,
                        'message': message,
                        'status': status
                    }

        except Exception as e:
            logger.exception("%s", e)

#get content for db,table from sqlite
class GetFwRules(Resource):
    def post(self):
        try:
            logger.info("ClassName: === " + self.__class__.__name__+" ===")
            parser.add_argument('dbname', type=str)
            parser.add_argument('tablename', type=str)
            args = parser.parse_args()
            db = args['dbname']
            tablename = args['tablename']
            rulesfromsqlite = RawRuleslist.ReadSqlite(db,tablename)
            return (rulesfromsqlite)

        except Exception as e:
            logger.exception("%s", e)

#search path from source to destination
class SearchPath(Resource):
    def post(self):
        try:
            logger.info("ClassName: === " + self.__class__.__name__+" ===")
            parser.add_argument('pathsource', type=str)
            parser.add_argument('pathdest', type=str)
            parser.add_argument('pathrel', type=str)
            args = parser.parse_args()
            pathsource = args['pathsource']
            pathdest = args['pathdest']
            pathrel = args['pathrel']
            statement = "MATCH (s:Hosts{IPAddress:'"+pathsource+"'}),(d:Hosts{IPAddress:'" + \
                pathdest+"'}), r = allShortestPaths((s)-[*]->(d)) RETURN r"
            print(
                "-------------------------------------------------------------------------------------------")
            logger.info("Query: " + statement)
            # print(statement)
            # inherit = HeavyLifting()
            MatchRel, finalgrouping = inherit.custquery(statement)
            print("=================================Relationships output 1========================================")
            Link = []
            Node = []
            NoDupNode = []
            for y in MatchRel:
                for z in y:
                    nodes_s = {}
                    nodes_datawrapper_s = {}
                    action_taken_s = 0
                    action_taken_d = 0
                    for x in finalgrouping:
                        nodes_datawrapper_s = {}
                        nodes_s = {}
                        if z['s']['Name'] == x['ChildName']:
                            action_taken_s = 1
                            nodes_grp = {}
                            nodes_datawrapper_grp = {}
                            nodes_grp['id'] = x['Parent_IP']
                            nodes_grp['color'] = x['color']
                            nodes_datawrapper_grp['data'] = nodes_grp
                            Node.append(nodes_datawrapper_grp)
                            nodes_s = {}
                            nodes_datawrapper_s = {}
                            nodes_s['id'] = z['s']['Name']
                            nodes_s['parent'] = x['Parent_IP']
                            nodes_s['color'] = x['color']
                            nodes_datawrapper_s['data'] = nodes_s
                            Node.append(nodes_datawrapper_s)
                            break
                    if action_taken_s == 0:
                        nodes_s['id'] = z['s']['Name']
                        nodes_datawrapper_s['data'] = nodes_s
                        Node.append(nodes_datawrapper_s)
                        # else:
                        #       nodes_s['id']=z['s']['Name']
                        #       nodes_datawrapper_s['data']=nodes_s
                        #       Node.append(nodes_datawrapper_s)
                        # break
                    # Node.append(nodes_datawrapper_s)
                    for y in finalgrouping:
                        action_taken_d = 0
                        nodes_datawrapper_d = {}
                        nodes_d = {}
                        if z['d']['Name'] == y['ChildName']:
                            action_taken_d = 1
                            nodes_grp = {}
                            nodes_datawrapper_grp = {}
                            nodes_grp['id'] = y['Parent_IP']
                            nodes_grp['color'] = y['color']
                            nodes_datawrapper_grp['data'] = nodes_grp
                            Node.append(nodes_datawrapper_grp)
                            nodes_d = {}
                            nodes_d['id'] = z['d']['Name']
                            nodes_d['parent'] = y['Parent_IP']
                            nodes_d['color'] = y['color']
                            nodes_datawrapper_d['data'] = nodes_d
                            Node.append(nodes_datawrapper_d)
                            break
                    if action_taken_d == 0:
                        nodes_d['id'] = z['d']['Name']
                        nodes_datawrapper_d['data'] = nodes_d
                        Node.append(nodes_datawrapper_d)
                        # else:
                        #       nodes_d['id']=z['d']['Name']
                        #       nodes_datawrapper_d['data']=nodes_d
                        #       Node.append(nodes_datawrapper_d)
                        # break
                    # Node.append(nodes_datawrapper_d)
            for x in Node:
                if x not in NoDupNode:
                    NoDupNode.append(x)
            print(MatchRel)
            for y in MatchRel:
                for z in y:
                    links_datawrapper = {}
                    links = {}
                    print(z['s']['Name'])
                    print(z['r'])
                    links['source'] = z['s']['Name']
                    links['target'] = z['d']['Name']
                    links['service'] = z['r']
                    links_datawrapper['data'] = links
                    print(links)
                    Link.append(links_datawrapper)
            out = {}
            out = {"nodes": NoDupNode, "edges": Link}
            print(out)
            return out
        except Exception as e:
            logger.exception("%s", e)

# Default rules
class DefaultRules(Resource):
    def post(self):
        try:
            logger.info("ClassName: === " + self.__class__.__name__+" ===")
            parser.add_argument('defaultquery', type=str)
            args = parser.parse_args()
            defaultquery = args['defaultquery']

            # Insecure protocols
            if defaultquery == "default01":
                statement = "MATCH p=(s:Hosts)-[r:ftp|:telnet]->(d:Hosts) RETURN s,r,d LIMIT 50"

            # Any relationships
            if defaultquery == "default02":
                statement = "MATCH (s:Hosts)-[r:Any]->(d:Hosts) RETURN s,r,d LIMIT 50"

            logger.info("Query: " + statement)
            
            # inherit = HeavyLifting()            
            MatchRel, finalgrouping, GrpNodes = inherit.defaultrules(statement)

            finalformat = finalformating()
            
            NoDupNode, Link = finalformat.format_w_grouping(
                MatchRel, finalgrouping, GrpNodes)
            out = {}
            out = {"nodes": NoDupNode, "edges": Link}
            print(out)
            return out
        except Exception as e:
            logger.exception("%s", e)


# Add groups to neo4j database
class CreateGroup(Resource):
    def post(self):
        try:
            logger.info("ClassName: === " + self.__class__.__name__+" ===")
            parser.add_argument('groupips', type=str)
            parser.add_argument('groupname', type=str)
            parser.add_argument('groupcolor', type=str)
            args = parser.parse_args()
            statement = "MERGE (d:Groups{Name:'"+args['groupname'] + \
                "', IPAddress: '"+args['groupips'] + \
                "',color: '"+args['groupcolor']+"'}) RETURN d"
            logger.info("Query: " + statement)
            # inherit = HeavyLifting()
            output = inherit.CreateGroup(statement)
            return output
        except Exception as e:
            logger.exception("%s", e)


# Custom cypher query
class CustQuery(Resource):
    def post(self):
        try:
            logger.info("ClassName: === " + self.__class__.__name__+" ===")
            parser.add_argument('custquery', type=str)
            args = parser.parse_args()
            statement = args['custquery']
            logger.info("Query: " + statement)
            if (statement[:4] != "LOAD"):
                # print(statement)
                # inherit = HeavyLifting()
                MatchRel, finalgrouping = inherit.custquery(statement)
                print(
                    "=================================Relationships output 1========================================")
                Link = []
                Node = []
                NoDupNode = []
                for y in MatchRel:
                    for z in y:
                        nodes_s = {}
                        nodes_datawrapper_s = {}
                        action_taken_s = 0
                        action_taken_d = 0
                        for x in finalgrouping:
                            nodes_datawrapper_s = {}
                            nodes_s = {}
                            if z['s']['Name'] == x['ChildName']:
                                action_taken_s = 1
                                nodes_grp = {}
                                nodes_datawrapper_grp = {}
                                nodes_grp['id'] = x['Parent_IP']
                                nodes_grp['color'] = x['color']
                                nodes_datawrapper_grp['data'] = nodes_grp
                                Node.append(nodes_datawrapper_grp)
                                nodes_s = {}
                                nodes_datawrapper_s = {}
                                nodes_s['id'] = z['s']['Name']
                                nodes_s['parent'] = x['Parent_IP']
                                nodes_s['color'] = x['color']
                                nodes_datawrapper_s['data'] = nodes_s
                                Node.append(nodes_datawrapper_s)
                                break
                        if action_taken_s == 0:
                            nodes_s['id'] = z['s']['Name']
                            nodes_datawrapper_s['data'] = nodes_s
                            Node.append(nodes_datawrapper_s)
                            # else:
                            #       nodes_s['id']=z['s']['Name']
                            #       nodes_datawrapper_s['data']=nodes_s
                            #       Node.append(nodes_datawrapper_s)
                            # break
                        # Node.append(nodes_datawrapper_s)
                        for y in finalgrouping:
                            action_taken_d = 0
                            nodes_datawrapper_d = {}
                            nodes_d = {}
                            if z['d']['Name'] == y['ChildName']:
                                action_taken_d = 1
                                nodes_grp = {}
                                nodes_datawrapper_grp = {}
                                nodes_grp['id'] = y['Parent_IP']
                                nodes_grp['color'] = y['color']
                                nodes_datawrapper_grp['data'] = nodes_grp
                                Node.append(nodes_datawrapper_grp)
                                nodes_d = {}
                                nodes_d['id'] = z['d']['Name']
                                nodes_d['parent'] = y['Parent_IP']
                                nodes_d['color'] = y['color']
                                nodes_datawrapper_d['data'] = nodes_d
                                Node.append(nodes_datawrapper_d)
                                break
                        if action_taken_d == 0:
                            nodes_d['id'] = z['d']['Name']
                            nodes_datawrapper_d['data'] = nodes_d
                            Node.append(nodes_datawrapper_d)
                            # else:
                            #       nodes_d['id']=z['d']['Name']
                            #       nodes_datawrapper_d['data']=nodes_d
                            #       Node.append(nodes_datawrapper_d)
                            # break
                        # Node.append(nodes_datawrapper_d)
                for x in Node:
                    if x not in NoDupNode:
                        NoDupNode.append(x)
                print(MatchRel)
                # return (testing1)
                for y in MatchRel:
                    for z in y:
                        links_datawrapper = {}
                        links = {}
                        print(z['s']['Name'])
                        print(z['r'])
                        links['source'] = z['s']['Name']
                        links['target'] = z['d']['Name']
                        links['service'] = z['r']
                        links_datawrapper['data'] = links
                        print(links)
                        Link.append(links_datawrapper)
                out = {}
                out = {"nodes": NoDupNode, "edges": Link}
                print(out)
                return out
            if (statement[:4] == "LOAD"):
                # inherit = HeavyLifting()
                uploadednotification = inherit.uploadwithcustquery(statement)
                print(uploadednotification)
                # up=[]
                up_values = []
                retup = {}
                for i in uploadednotification:
                    up = {}
                    print(i)
                    print(uploadednotification[i])
                    up['a'] = i
                    up['b'] = uploadednotification[i]
                    up_values.append(up)
                retup = {'up_values': up_values}
                return(retup)
        except Exception as e:
            logger.exception("%s", e)


# Upload Files
class UploadFiles(Resource):
    def post(self):
        try:
            logger.info("ClassName: === " + self.__class__.__name__+" ===")
            parser.add_argument(
                'file', type=werkzeug.datastructures.FileStorage, location='files')
            parser.add_argument('typeoffile', type=str)
            parser.add_argument('firewallname', type=str)
            parser.add_argument('policyname', type=str)
            parser.add_argument('src_select', type=str)
            parser.add_argument('dst_select', type=str)
            parser.add_argument('ser_select', type=str)
            parser.add_argument('typeofservice', type=str)
            parser.add_argument('header_row')

            data = parser.parse_args()

            firewallname = data['firewallname']
            policyname = data['policyname']
            src_select = data['src_select']
            dst_select = data['dst_select']
            ser_select = data['ser_select']
            typeoffile = data['typeoffile']
            header_row = data['header_row']
            typeofservice = data['typeofservice']

            header_lst = json.loads(header_row)

            if data['file'] == "":
                return {
                    'data': '',
                    'message': 'No file found',
                    'status': 'error'
                }
            photo = data['file']

            if photo:
                if not os.path.exists(UPLOAD_FOLDER):
                    os.mkdir(UPLOAD_FOLDER)
                    print("[*] Directory \'"+UPLOAD_FOLDER+"\' Created ")
                else:
                    print("[*] Directory \'"+UPLOAD_FOLDER+"\' already exists")

                filename = photo.filename
                photo.save(os.path.join(UPLOAD_FOLDER, filename))
                

                print("[*] \'"+filename+"\' created in uploads folder")

                if (typeoffile == 'rules'):
                    src = int(src_select)
                    dst = int(dst_select)
                    ser = int(ser_select)

                    tocreatetable = RawRuleslist.CreateTable(firewallname,policyname,typeoffile,header_lst)
                    logger.info("CreateTable status:"+tocreatetable)
                    if tocreatetable == "Table created":
                        touploadtosqlite = RawRuleslist.uploadSqlite(
                            filename,firewallname,policyname, src_select, dst_select, ser_select)
                        touploadtodb = CSVSplit_generalised_v3.toSplit(
                        filename, src_select, dst_select, ser_select)
                        yyy = 0
                        rel_prop = "`name`:rule.`"+header_lst[ser]+"`"
                        while yyy < len(header_lst):
                            if (yyy != src and yyy != dst and yyy != ser and header_lst[yyy] != 'name'):
                                rel_prop = rel_prop+",`" + \
                                    header_lst[yyy]+"`:rule.`"+header_lst[yyy]+"`"
                                print(rel_prop)
                            yyy += 1
                        rel_prop = rel_prop+",`policyname`:\'"+policyname+"\'"+",`firewallname`:\'"+firewallname+"\'"
                        print(rel_prop)
                        user=config.get('neo4j', 'user')
                        password=config.get('neo4j', 'passwd')
                        graph2 = Graph(host=config.get('neo4j', 'host'),auth=(user,password))      
                        statement = "LOAD CSV WITH HEADERS FROM 'file:///"+touploadtodb+".csv' AS rule match (s:Hosts {Name:rule.`"+header_lst[src]+"`}) match (d:Hosts {Name:rule.`"+header_lst[
                            dst]+"`}) call apoc.create.relationship(s,rule.`"+header_lst[ser]+"`,{"+rel_prop+"},d) yield rel RETURN rel.name"
                        logger.info(statement)
                        output = graph2.run(statement).data()
                        return {
                            'data': '',
                            'message': filename+' uploaded !',
                            'tofollow1': "1. Copy \'"+touploadtodb+"\' to the import directory of your Neo4j db; ",
                            'tofollow2': "2.  Run the following query in the Custom Query section to upload the file to Neo4j;  "+"\t"+" \"LOAD CSV WITH HEADERS FROM 'file:///"+touploadtodb+".csv' AS rule match (s:Hosts {Name:rule.`"+header_lst[src]+"`}) match (d:Hosts {Name:rule.`"+header_lst[dst]+"`}) call apoc.create.relationship(s,rule.`"+header_lst[ser]+"`,{"+rel_prop+"},d) yield rel RETURN rel.name\" ",
                            'status': 'success'
                        }
                    else:
                         return {
                                'data': '',
                                'message': 'Something went wrong',
                                'status': 'error'
                         }
                if (typeoffile == 'netobj'):
                    tocreatetable = RawRuleslist.CreateTable(firewallname,filename,typeoffile,header_lst)
                    if tocreatetable == "Table created":
                        touploadtosqlite = RawRuleslist.uploadSqlitenetobj(
                            filename,firewallname)
                        inherit.segregateIandE(firewallname)
                        touploadtodb = CSVSplit_generalised_v3.savetoImportDir(filename)                    
                        yyy = 0
                        node_prop = "Name:rule.Name,IPAddress:rule.`IPv4 address`,Mask:coalesce(rule.Mask,'NA'),Comments:coalesce(rule.Comments,'NA')"
                        # rel_prop = "`name`:rule.`"+header_lst[ser]+"`"
                        while yyy < len(header_lst):
                            if (header_lst[yyy] != 'Name' and header_lst[yyy] != 'IPv4 address' and header_lst[yyy] != 'Comments'):
                                node_prop = node_prop+",`" + \
                                    header_lst[yyy] + \
                                    "`:coalesce(rule.`" + \
                                    header_lst[yyy]+"`,'NA')"
                            yyy += 1
                        node_prop = node_prop+",`firewallname`:\'"+firewallname+"\'"
                        user=config.get('neo4j', 'user')
                        password=config.get('neo4j', 'passwd')
                        graph2 = Graph(host=config.get('neo4j', 'host'),auth=(user,password))      
                        statement = "LOAD CSV WITH HEADERS FROM 'file:///"+filename+"' AS rule MERGE (s:Hosts {"+node_prop+"})"
                        logger.info(statement)
                        output = graph2.run(statement).data()
                        logger.info(output)
                        # print("copy \'"+filename +
                        #       "\' to the import directory of your Neo4j db ")
                        # print(
                        #     "Run the below query in the Custom Query section to upload the file to Neo4j")
                        # print("=============")
                        # print("LOAD CSV WITH HEADERS FROM 'file:///" +
                        #       filename+"' AS rule MERGE (s:Hosts {"+node_prop+"}) ")
                        # print("=============")
                        return {
                            'data': '',
                            'message': filename+' uploaded !',
                            'tofollow1': "1. Copy \'"+filename+"\' to the import directory of your Neo4j db; ",
                            'tofollow2': "2.  Run the following query in the Custom Query section to upload the file to Neo4j;  "+"\t"+" \"LOAD CSV WITH HEADERS FROM 'file:///"+filename+"' AS rule MERGE (s:Hosts {"+node_prop+"})\" ",
                            'status': 'success'
                        }
                if (typeoffile == 'services'):

                    tocreatetable = RawRuleslist.CreateTable(firewallname,filename,typeoffile,header_lst)
                    if tocreatetable == "Table created":
                        touploadtosqlite = RawRuleslist.uploadSqliteservices(
                            filename,firewallname,filename)
                        #inherit.segregateIntExtConn(firewallname,filename)
                        touploadtodb = CSVSplit_generalised_v3.savetoImportDir(filename)                    
                        yyy = 0
                        node_prop = "Name:rule.Name,Comments:coalesce(rule.Comments,'NA')"
                        # rel_prop = "`name`:rule.`"+header_lst[ser]+"`"
                        while yyy < len(header_lst):
                            if (header_lst[yyy] != 'Name' and header_lst[yyy] != 'Comments'):
                                node_prop = node_prop+",`" + \
                                    header_lst[yyy] + \
                                    "`:coalesce(rule.`" + \
                                    header_lst[yyy]+"`,'NA')"
                            yyy += 1
                        node_prop = node_prop+",`servicename`:\'"+filename+"\'"+",`firewallname`:\'"+firewallname+"\'"
                        user=config.get('neo4j', 'user')
                        password=config.get('neo4j', 'passwd')
                        graph2 = Graph(host=config.get('neo4j', 'host'),auth=(user,password))      
                        statement = "LOAD CSV WITH HEADERS FROM 'file:///"+filename+"' AS rule MERGE (s:Services {"+node_prop+"})"
                        logger.info(statement)
                        output = graph2.run(statement).data()
                        logger.info(output)
                        return{
                        'data': '',
                        'message': filename+' uploaded !',
                        'status': 'success'
                        }   
                    else:
                         return {
                                'data': '',
                                'message': 'Something went wrong',
                                'status': 'error'
                         }                

                return {
                    'data': '',
                    'message': 'Something went wrong',
                    'status': 'error'
                }
                
                
        except Exception as e:
            logger.exception("%s", e)

#Risk calculator
class CalculateRisk(Resource):
    def post(self):
        try:
            logger.info("ClassName: === " + self.__class__.__name__+" ===")
            logger.info("******* Risk Calculator ******* ")            
            parser.add_argument('db_name', type=str)
            parser.add_argument('table_name', type=str)

            data = parser.parse_args()
            print(data)

            db_name = data['db_name']
            table_name = data['table_name']

            out = inherit.riskcalculator(db_name,table_name)
            if out['status']=="success":
                return {
                'data': '',
                'message': out['message'],
                'status': 'success'
                }
            else:
                return {
                'data': '',
                'message': "Some error occured",
                'status': 'error'
                }

        except Exception as e:
            logger.exception("%s", e)
            return {
                'data': '',
                'message': 'Some error occured in calculating risks',
                'status': 'error'
            }


# Risk Config rule 1
class RiskConfig(Resource):
    def post(self):
        try:
            logger.info("ClassName: === " + self.__class__.__name__+" ===")
            
            parser.add_argument('onecolumn', type=str)
            parser.add_argument('twocolumns', type=str)
            parser.add_argument('threecolumns', type=str)
            data = parser.parse_args()
            onecolumn = data['onecolumn']
            twocolumns = data['twocolumns']
            threecolumns = data['threecolumns']
            stat = inherit.updateriskconfig(onecolumn,twocolumns,threecolumns)
            if stat=="updated":
                return {
                    'message': 'Updated!',
                    'status': 'Success'
                }
            return {
                    'message': 'Some error occured',
                    'status': 'Error'
                }
        except Exception as e:
            logger.exception("%s", e)


# Retrieve Risk Config
class RetrieveRiskConfig(Resource):
    def get(self):
        try:
            logger.info("ClassName: === " + self.__class__.__name__+" ===")
            onecolumn,twocolumns,threecolumns,insecureriskvalue,itoeriskvalue,etoiriskvalue= inherit.retrieveriskconfig()
            return[onecolumn,twocolumns,threecolumns,insecureriskvalue,itoeriskvalue,etoiriskvalue]
        except Exception as e:
            logger.exception("%s", e)

# Retrieve InsecureProto Config
class RetrieveInsecureProtoConfig(Resource):
    def post(self):
        try:
            logger.info("ClassName: === " + self.__class__.__name__+" ===")
            
            parser.add_argument('dbname', type=str)
            parser.add_argument('tablename', type=str)
            parser.add_argument('reqfrom', type=str)
            data = parser.parse_args()
            dbname = data['dbname']
            tablename = data['tablename']
            reqfrom = data['reqfrom']
            print(data)
            allservices,queryresult1,queryresult2,queryresult3= RawRuleslist.retrieveinsecureprotoconfig(dbname,tablename)
            return [allservices,queryresult1,queryresult2,queryresult3]
        except Exception as e:
            logger.exception("%s", e)

# Retrieve RiskReason
class RetrieveRiskReason(Resource):
    def post(self):
        try:
            logger.info("ClassName: === " + self.__class__.__name__+" ===")
            
            parser.add_argument('dbname', type=str)
            parser.add_argument('tablename', type=str)
            parser.add_argument('riskid', type=str)
            data = parser.parse_args()
            dbname = data['dbname']
            tablename = data['tablename']
            riskid = data['riskid']
            print(data)
            out = RawRuleslist.retrieveriskreason(dbname,tablename,riskid)
            print(out)
            every_wrap=[]
            for every in out:
                every1 = every.split(';')
                for every2 in every1:
                    if every2!="":
                        out1={}
                        every3 = every2.split(',')
                        out1 = {"riskid": every3[0], "service": every3[1],"reason": every3[2], "riskvalue": every3[3]}
                        every_wrap.append(out1)

            return {
                'data': every_wrap,
                'message': 'Retrieved Risk score details',
                'status': 'success'
            }
        except Exception as e:
            logger.exception("%s", e)


# Save InsecureProto Config
class SaveInsecureProto(Resource):
    def post(self):
        try:
            logger.info("ClassName: === " + self.__class__.__name__+" ===")
            parser.add_argument('dbname', type=str)
            parser.add_argument('tablename', type=str)        
            parser.add_argument('saveinsecureproto', type=str)                        
            parser.add_argument('insecureriskvalue', type=str)
            parser.add_argument('itoeriskvalue', type=str)
            parser.add_argument('etoiriskvalue', type=str)
            parser.add_argument('iswhat', type=str)
            data = parser.parse_args()
            dbname = data['dbname']
            tablename = data['tablename']
            saveinsecureproto = data['saveinsecureproto']
            insecureriskvalue = data['insecureriskvalue']
            itoeriskvalue = data['itoeriskvalue']
            etoiriskvalue = data['etoiriskvalue']
            iswhat = data['iswhat']
            saveinsecureproto_lst = json.loads(saveinsecureproto) #Very important: convert json to python list
            if iswhat=="insecureproto":
                config.set("riskconfigAny","insecureriskvalue",insecureriskvalue)
                with open('conf/creds.ini', 'w') as configfile:
                    config.write(configfile)
                colname="Insecure"
            if iswhat=="inttoext":
                config.set("riskconfigAny","itoeriskvalue",itoeriskvalue)
                with open('conf/creds.ini', 'w') as configfile:
                    config.write(configfile)
                colname="ItoE"
            if iswhat=="exttoint":
                config.set("riskconfigAny","etoiriskvalue",etoiriskvalue)
                with open('conf/creds.ini', 'w') as configfile:
                    config.write(configfile)
                colname="EtoI"
            stat = RawRuleslist.updateinsecureproto(dbname, tablename,colname, saveinsecureproto_lst)
            if stat=="updated":
                   return {
                        'message': 'Updated!',
                        'status': 'Success'
                    }
            #allservices,queryresult1,queryresult2,queryresult3= RawRuleslist.retrieveinsecureprotoconfig(dbname,tablename)
            #return [allservices,queryresult1,queryresult2,queryresult3]
        except Exception as e:
            logger.exception("%s", e)




'''GET URLs'''
api.add_resource(allRels, '/todo/api/allrels', endpoint='allrels')
# Test: Get: http://127.0.0.1:5000/todo/api/allrels
api.add_resource(allGroups, '/todo/api/allgroups', endpoint='allgroups')
# Test: Get: http://127.0.0.1:5000/todo/api/allgroups
api.add_resource(GetAllFwPolicies, '/todo/api/getallfwpolicies', endpoint='getallfwpolicies')
# Test: http://127.0.0.1:5000/todo/api/getallfwpolicies
api.add_resource(GroupHeirarchy, '/todo/api/grpheirarchy', endpoint='grpheirarchy')
# Test: http://127.0.0.1:5000/todo/api/grpheirarchy

'''Riskconfig'''
api.add_resource(RiskConfig, '/todo/api/updateriskconfig', endpoint='updateriskconfig')
api.add_resource(CalculateRisk, '/todo/api/calculaterisk', endpoint='calculaterisk')
# Test: http://127.0.0.1:5000/todo/api/calculaterisk
api.add_resource(RetrieveRiskConfig, '/todo/api/retrieveriskconfig', endpoint='retrieveriskconfig')
api.add_resource(RetrieveInsecureProtoConfig, '/todo/api/retrieveinsecureprotoconfig', endpoint='retrieveinsecureprotoconfig')
api.add_resource(SaveInsecureProto, '/todo/api/saveinsecureproto', endpoint='saveinsecureproto')
api.add_resource(RetrieveRiskReason, '/todo/api/getriskreason', endpoint='getriskreason')


'''POST URLs'''
api.add_resource(DefaultRules, '/todo/api/defaultrules',
                 endpoint='defaultrules')
api.add_resource(CreateGroup, '/todo/api/creategroup', endpoint='creategroup')
api.add_resource(UploadFiles, '/todo/api/upload', endpoint='uploadfiles')
api.add_resource(GetFwRules, '/todo/api/getfwrules', endpoint='getfwrules')
api.add_resource(GetSelectedRules, '/todo/api/getselectedrules', endpoint='getselectedrules')


api.add_resource(SearchNetwork, '/todo/api/search', endpoint='searchnetwork')
# Test: http://127.0.0.1:5000/todo/api/check/194.127.24.64
api.add_resource(Relationship, '/todo/api/search/<string:searchterm>/<string:limit>',
                 endpoint='searchwithlimit')  # Test: http://127.0.0.1:5000/todo/api/search/https/10
api.add_resource(SearchPath, '/todo/api/searchpath', endpoint='searchpath')
api.add_resource(CustQuery, '/todo/api/custquery', endpoint='custquery')




if __name__ == '__main__':
    app.run(debug=True)


