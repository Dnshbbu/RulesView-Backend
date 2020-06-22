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
import sqlite3



#config object to pull the password from conf file
config = configparser.ConfigParser()
config.read('conf/creds.ini')


# UPLOAD_FOLDER = 'uploads/'
UPLOAD_FOLDER = config.get('uploads', 'UPLOAD_FOLDER')
db_location=config.get('sqliteDB', 'database_folder')


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

# %(filename)s:%(lineno)s - %(funcName)20s()

# add file handler to logger
logger.addHandler(file_handler)

def updateriskconfig(onecolumn,twocolumns,threecolumns):
    config.set("riskconfigAny","onecolumn",onecolumn)
    config.set("riskconfigAny","twocolumns",twocolumns)
    config.set("riskconfigAny","threecolumns",threecolumns)
    with open('conf/creds.ini', 'w') as configfile:
        config.write(configfile)
    return('updated')


def retrieveriskconfig():
    onecolumn= config.get('riskconfigAny', 'onecolumn')
    twocolumns= config.get('riskconfigAny', 'twocolumns')
    threecolumns= config.get('riskconfigAny', 'threecolumns')
    insecureproto= config.get('riskconfigAny', 'insecureriskvalue')
    itoeriskvalue= config.get('riskconfigAny', 'itoeriskvalue')
    etoiriskvalue= config.get('riskconfigAny', 'etoiriskvalue')
    return(onecolumn,twocolumns,threecolumns,insecureproto,itoeriskvalue,etoiriskvalue)

def segregateIandE(db_name):
    table_name="netobj"   

    allrows = RawRuleslist.ReadSqlitenetobj(db_name,table_name)
    for x in allrows:
        idvalue = x['Name']
        ipvalue=x['IPv4']      
        mask=x['Mask']
        riskvalue='yes'

        if x['Mask']!='NA':
            print('NA is not there')
            cip = ipvalue+"/"+mask
            #ipnetwork=IPNetwork[cip]
            ipnetwork=IPNetwork(cip)
            ip=ipnetwork
        if "-" in ipvalue:
            print("- is there")
            ipranges = ipvalue.split('-')
            iprange =IPRange(ipranges[0].strip(),ipranges[1].strip())
            ip=iprange
        else:
            print('NA is there')
            #ip=IPAddress[ipvalue]
            ip = IPAddress(ipvalue)
            
        #print(ip_address(var_121).is_private)  
        if ip.is_private():
            column_name="Internal"
            riskvalue="\'yes\'"
            id_column="Name"
            idvalue = "\'"+idvalue+"\'"
            RawRuleslist.UpdateTable(db_name, table_name, column_name,riskvalue, id_column, idvalue)
        else:
            column_name="External"
            riskvalue="\'yes\'"
            id_column="Name"
            idvalue = "\'"+idvalue+"\'"
            RawRuleslist.UpdateTable(db_name, table_name, column_name, riskvalue,id_column, idvalue)

        
def segregateIntExtConn(db_name,table_name):
    try:
        allrows = RawRuleslist.ReadSqlite(db_name,table_name)

        sqlite_file = db_location+"\\\\"+db_name+'.db' 
        value="\'yes\'"  
        # Connecting to the database file
        conn = sqlite3.connect(sqlite_file)
        conn.row_factory = lambda cursor, row: row[0]
        c = conn.cursor()

        tablename2 = "netobj"
        colname2="External"    
        #query to get rows which has External=yes
        c.execute("SELECT Name from {tn} where {cn}={val}".format(tn=tablename2, cn=colname2,val=value))
        queryresult2 =c.fetchall()
        logger.info("queryresults")

        for x in allrows:
            idvalue=x['No']   
            if x['Action']=="Accept":
                individualsource1 = str(x['Source']).split(';')
                for xy in individualsource1:
                    if xy in queryresult2:
                        individualdestination1 = str(x['Destination']).split(';')
                        for xz in individualdestination1:
                            if xz in queryresult2:
                                column_name="ExttoExt"
                                riskvalue="\'yes\'"
                                id_column="No"
                                # idvalue = x['Name']
                                # idvalue = "\'"+idvalue+"\'"     
                                table_name=table_name
                                RawRuleslist.UpdateTable(db_name, table_name, column_name, riskvalue,id_column, idvalue)
                                break
                            else:
                                column_name="ExttoInt"
                                riskvalue="\'yes\'"
                                id_column="No"
                                # idvalue = "\'"+idvalue+"\'"                                  
                                table_name=table_name
                                RawRuleslist.UpdateTable(db_name, table_name, column_name, riskvalue,id_column, idvalue)
                    else:
                        individualdestination1 = str(x['Destination']).split(';')
                        for xz in individualdestination1:
                            if xz in queryresult2:
                                column_name="InttoExt"
                                riskvalue="\'yes\'"
                                id_column="No"
                                # idvalue = x['Name']
                                # idvalue = "\'"+idvalue+"\'"                                   
                                table_name=table_name                              
                                RawRuleslist.UpdateTable(db_name, table_name, column_name, riskvalue,id_column, idvalue)
                            else:
                                column_name="InttoInt"
                                riskvalue="\'yes\'"
                                id_column="No"
                                # idvalue = "\'"+idvalue+"\'"                                 
                                table_name=table_name                                
                                RawRuleslist.UpdateTable(db_name, table_name, column_name, riskvalue,id_column, idvalue)
    except Exception as e:
        logger.exception("%s", e)

def riskcalculator(db_name,table_name):
    try:
        segregateIandE(db_name)
        segregateIntExtConn(db_name,table_name)
        riskcalculator_parked(db_name,table_name)
        return {
                'data': '',
                'message': 'Risk updated!',
                'status': 'success'
            }
        
    except Exception as e:
        logger.exception("%s", e)

    
# class HeavyLifting():
def riskcalculator_parked(db_name,table_name):
    try:
        allrows = RawRuleslist.ReadSqlite(db_name,table_name)

        # if source, destination or service has any fields
        onecolumn= config.get('riskconfigAny', 'onecolumn')
        twocolumns= config.get('riskconfigAny', 'twocolumns')
        threecolumns= config.get('riskconfigAny', 'threecolumns')
        insecureriskvalue= config.get('riskconfigAny', 'insecureriskvalue')
        itoeriskvalue= config.get('riskconfigAny', 'itoeriskvalue')
        etoiriskvalue= config.get('riskconfigAny', 'etoiriskvalue')

        
        id_column = "No" 

        sqlite_file = db_location+"\\\\"+db_name+'.db' 
        value="\'yes\'"  
        # Connecting to the database file
        conn = sqlite3.connect(sqlite_file)
        conn.row_factory = lambda cursor, row: row[0]
        c = conn.cursor()

        tablename = "services"
        colname="Insecure"    
        #query to get rows which has insecure=yes
        c.execute("SELECT Name from {tn} where {cn}={val}".format(tn=tablename, cn=colname,val=value))
        queryresult1 =c.fetchall()
 

        
        colname="ItoE"    
        #query to get rows which has InttoExt=yes
        c.execute("SELECT Name from {tn} where {cn}={val}".format(tn=tablename, cn=colname,val=value))
        queryresult2 =c.fetchall()


        
        colname="EtoI"    
        #query to get rows which has ExttoInt=yes
        c.execute("SELECT Name from {tn} where {cn}={val}".format(tn=tablename, cn=colname,val=value))
        queryresult3 =c.fetchall()


        for x in allrows:
            riskvalue = 0
            riskreason = ""
            idvalue=x['No'] 
            id_column = "No" 
            #Any in columns- Risk assignment
            if x['Action']=="Accept":
                if (x['Source']=="Any" and x['Destination']=="Any" and x['Service']=="Any"):
                    riskvalue=riskvalue+int(threecolumns)
                    riskreason = riskreason+"1,-,"+"All three columns have Any "+","+str(threecolumns)+";"
                elif ((x['Source']=="Any" and x['Destination']=="Any") or (x['Destination']=="Any" and x['Service']=="Any") or ( x['Service']=="Any" and x['Source']=="Any")):
                    riskvalue=riskvalue+int(twocolumns)
                    riskreason = riskreason+"1,-,"+"Two columns have Any "+","+str(twocolumns)+";"
                elif (x['Source']=="Any" or x['Destination']=="Any" or x['Service']=="Any"):
                    riskvalue=riskvalue+int(onecolumn)  
                    riskreason = riskreason+"1,-,"+"One column has Any"+","+str(onecolumn)+";"
        
            if x['Action']=="Accept":
                individualservice = str(x['Service']).split(';')
                '''Insecure protocols- Risk assignment'''
                for xy in individualservice:
                    if xy in queryresult1:
                        riskvalue=riskvalue+int(insecureriskvalue)
                        riskreason = riskreason+"2"+","+xy+","+"Insecure proto"+","+str(insecureriskvalue)+";"
            column_name = "Risk"
            logger.info(riskreason)
            logger.info(riskvalue)
            RawRuleslist.UpdateTable(db_name, table_name, column_name,riskvalue, id_column,  idvalue) 
            column_name = "RiskReason"
            riskreason="\'"+riskreason+"\'"
            RawRuleslist.UpdateTable(db_name, table_name, column_name,riskreason, id_column,  idvalue) 


        colname="InttoExt"    
        queryresult11 = RawRuleslist.ReadSqlitewSelected(db_name,table_name,colname)

        for x in queryresult11:
            riskvalue = x['Risk']
            riskreason = x['RiskReason']
            idvalue=x['No'] 
            id_column = "No" 
            #riskreason = riskreason.replace("'", "")
            
            if x['Action']=="Accept":              
                individualservice = str(x['Service']).split(';')
                '''Internal to External connections- Risk assignment'''
                for xy in individualservice:
                    if xy not in queryresult2:
                        riskvalue=riskvalue+int(itoeriskvalue)
                        riskreason = riskreason+"3"+","+xy+","+"Int to Ext conn - non approved"+","+str(itoeriskvalue)+";"
            column_name = "Risk"
            RawRuleslist.UpdateTable(db_name, table_name, column_name,riskvalue, id_column,  idvalue) 
            column_name = "RiskReason"
            riskreason="\'"+riskreason+"\'"
            RawRuleslist.UpdateTable(db_name, table_name, column_name,riskreason, id_column,  idvalue) 

        colname="ExttoInt"    
        queryresult12 = RawRuleslist.ReadSqlitewSelected(db_name,table_name,colname)

        for x in queryresult12:
            id_column = "No" 
            idvalue=x['No'] 
            riskvalue = x['Risk']
            riskreason = x['RiskReason']
            #riskreason = riskreason.replace("'", "")
            
            if x['Action']=="Accept":
                individualservice = str(x['Service']).split(';')
                logger.info(individualservice)
                '''External to Internal connections- Risk assignment'''
                for xy in individualservice:
                    if xy not in queryresult3:
                        riskvalue=riskvalue+int(etoiriskvalue)  
                        riskreason = riskreason+"4"+","+xy+","+"Ext to Int conn - non approved"+","+str(etoiriskvalue)+";"
            
            column_name = "Risk"
            RawRuleslist.UpdateTable(db_name, table_name, column_name,riskvalue, id_column,  idvalue) 
            column_name = "RiskReason"
            riskreason="\'"+riskreason+"\'"
            RawRuleslist.UpdateTable(db_name, table_name, column_name,riskreason, id_column,  idvalue) 
        return {
                'data': '',
                'message': 'Risk updated!',
                'status': 'success'
            }
    except Exception as e:
        logger.exception("%s", e)
        return {
                'data': '',
                'message': 'Some error occured',
                'status': 'error'
            }



def getselectrules(statement):
    user=config.get('neo4j', 'user')
    password=config.get('neo4j', 'passwd')
    graph2 = Graph(host=config.get('neo4j', 'host'),auth=(user,password))
    output = graph2.run(statement).data()
    print(output)
    output1 = []
    if (output==[]):
        finalgrouping =[]
        GrpNodes =[]
        logger.error("Error: Neo4j didnt return any output for the query")
        message = "Error: Neo4j didnt return any output for the query"
        status = 'error'
        print(message)
    else:    
        output1.append(output)
        finalgrouping, GrpNodes = FinalGroupingv2(output1)
        message = "Query completed successfully"
        status = 'success'
        print(message)
                
    return(output1, finalgrouping, GrpNodes, message, status)

def uploadwithcustquery(statement):
    user=config.get('neo4j', 'user')
    password=config.get('neo4j', 'passwd')
    graph2 = Graph(host=config.get('neo4j', 'host'),auth=(user,password))
    output = graph2.run(statement).stats()
    return(output)

def getfwrulesneo4j( statement):
    user=config.get('neo4j', 'user')
    password=config.get('neo4j', 'passwd')
    graph2 = Graph(host=config.get('neo4j', 'host'),auth=(user,password))
    output = graph2.run(statement).data()
    RawRuleslist.InsertTable(output)    
    return (rules)

def defaultrules(  statement):
    user=config.get('neo4j', 'user')
    password=config.get('neo4j', 'passwd')
    graph2 = Graph(host=config.get('neo4j', 'host'),auth=(user,password))
    output = graph2.run(statement).data()
    output1 = []
    output1.append(output)
    finalgrouping, GrpNodes =  FinalGroupingv2(output1)
    return(output1, finalgrouping, GrpNodes)

def custquery(  statement):
    user=config.get('neo4j', 'user')
    password=config.get('neo4j', 'passwd')
    graph = Graph(host=config.get('neo4j', 'host'),auth=(user,password))
    output = graph.run(statement).data()
    id_Node = []
    NoDup_id_Node = []
    Created_rels = []
    for rel in output:
        mi = re.compile("\([_]*(?P<grouping>[0-9]*)\)")
        mi_rels = re.compile("\)(?P<grouping>.*?)\(")
        mi_rels_only_name = re.compile("\).*?\[\:(?P<grouping>\w+)\s\{")
        tomatch = rel['r']
        m = mi.findall(str(tomatch))
        mi_rels_data = mi_rels.findall(str(tomatch))
        mi_rels_data_only_name = mi_rels_only_name.findall(str(tomatch))
        print("================mi_nodes_data==============")
        print(m)
        print("================mi_rels_data==============")
        # print(mi_rels_data)

        for one in m:
            id_rels = {}
            intone = int(one)
            ab = graph.nodes.get(intone)
            id_rels['id'] = one
            id_rels['id_prop'] = ab
            id_Node.append(id_rels)
            # print (ab)
        for x in id_Node:
            if x not in NoDup_id_Node:
                NoDup_id_Node.append(x)
        xx = 0
        yy = 1
        for i in mi_rels_data:
            if ">" in i:
                create_rel = {}
                # print("forward")
                print(i)
                for id in NoDup_id_Node:
                    if m[xx] == id['id']:
                        create_rel['s'] = id['id_prop']
                # for id in NoDup_id_Node:
                    if m[yy] == id['id']:
                        create_rel['d'] = id['id_prop']
                create_rel['r'] = mi_rels_data_only_name[xx]
                print("source: "+m[xx]+"   destination: "+m[yy])
                print(create_rel)
                Created_rels.append(create_rel)
                print(
                    "======================Created_rels===========================")
                print(Created_rels)
                print(
                    "======================Created_rels===========================")
                # break
            else:
                # print("backward")
                create_rel = {}
                print(i)
                for id in NoDup_id_Node:
                    if m[yy] == id['id']:
                        create_rel['s'] = id['id_prop']  # Source
                # for id in NoDup_id_Node:
                    if m[xx] == id['id']:
                        create_rel['d'] = id['id_prop']  # Destination
                # create_rel['r']="(_"+m[xx]+")"+i+"(_"+m[yy]+")"
                # print(i['name'])
                create_rel['r'] = mi_rels_data_only_name[xx]
                # create_rel['r']="(_"+m[xx]+")"+i+"(_"+m[yy]+")"
                print("source: "+m[yy]+"   destination: "+m[xx])
                print(create_rel)
                Created_rels.append(create_rel)
                print(
                    "======================Created_rels===========================")
                print(Created_rels)
                print(
                    "======================Created_rels===========================")
                # break
            xx += 1
            yy += 1
    print("=!@#======    Create rels   ==========!@#=")
    print(Created_rels)

    output1 = []
    output1.append(Created_rels)
    finalgrouping =  FinalGrouping(output1)
    # print("################################################################3")
    # print(finalgrouping)
    return(output1, finalgrouping)

def allRels(statement):
    user=config.get('neo4j', 'user')
    password=config.get('neo4j', 'passwd')
    graph = Graph(host=config.get('neo4j', 'host'),auth=(user,password))
    output = graph.run(statement).data()
    return (output)

def allGroups(statement):
    user=config.get('neo4j', 'user')
    password=config.get('neo4j', 'passwd')
    graph = Graph(host=config.get('neo4j', 'host'),auth=(user,password))
    output = graph.run(statement).data()
    return (output)

def CreateGroup(  statement):
    user=config.get('neo4j', 'user')
    password=config.get('neo4j', 'passwd')
    graph = Graph(host=config.get('neo4j', 'host'),auth=(user,password))
    output = graph.run(statement).data()
    return output

def check(  statement, checkip):
    user=config.get('neo4j', 'user')
    password=config.get('neo4j', 'passwd')
    graph = Graph(host=config.get('neo4j', 'host'),auth=(user,password))
    output = graph.run(statement).data()
    Node = []
    NameAndIP = []
    NoDupNode = []
    MatchNetwork = []
    MatchNodes = []
    print("Printing Output")
    print(output)
    for item in output:
        nodes_source = {}
        name_ip = {}
        nodes_source['Name'] = item['n']['Name']
        nodes_source['IPAddress'] = item['n']['IPAddress']
        nodes_source['Mask'] = item['n']['Mask']
        nodes_source['Comments'] = item['n']['Comments']
        Node.append(nodes_source)
        # & (item['n']['IPAddress']!="10.15.208.0") & (item['n']['IPAddress']!="10.18.112.0")
        if (item['n']['Mask'] != "NA"):
            cip = item['n']['IPAddress']+"/"+item['n']['Mask']
            name_ip['Name'] = item['n']['Name']
            name_ip['IPAddress'] = item['n']['IPAddress']
            name_ip['Comments'] = item['n']['Comments']
            name_ip['Network'] = cip
            NameAndIP.append(name_ip)
        # & (item['n']['IPAddress']!="10.15.208.0") & (item['n']['IPAddress']!="10.18.112.0")
        if (item['n']['Mask'] == "NA"):
            name_ip['Name'] = item['n']['Name']
            name_ip['Network'] = item['n']['IPAddress']
            name_ip['Comments'] = item['n']['Comments']
            NameAndIP.append(name_ip)
    # tocheck_ip="194.127.24.66"
    # tocheck_ip="10.197.167.96"
    tocheck_ip = checkip
    # print("Printing tocheck_ip")
    # print(ip_network(tocheck_ip,strict=False))
    # print("Printing NameAndIP")
    # print(NameAndIP)
    # print(checkip)
    MatchRel = []

    for y in NameAndIP:
        if ("-" in y['Network']):
            # if m.group('IP_start')=="0.0.0.0" and m.group('IP_end')=="255.255.255.255":
            if y['Network'] == "0.0.0.0 - 255.255.255.255":
                MatchNetwork.append(y)
            else:
                ip_range_to_match = y['Network']
                m = re.search(
                    "^(?P<IP_start>.\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+\-\s+(?P<IP_end>.\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$", ip_range_to_match)
                iprange = IPRange(m.group('IP_start'), m.group('IP_end'))
                if tocheck_ip in iprange:
                    MatchNetwork.append(y)
        else:
            # if (tocheck_ip == y['Network']):
            #       MatchNetwork.append(y)
            # if not for strict=false, typeerror will be raised as "with hostbits set"!
            ab = ip_network(y['Network'], strict=False)
            if (IPv4Address(tocheck_ip) in IPv4Network(ab)):
                    # print(y) #print(y['Name'])
                MatchNetwork.append(y)

    print("Printing MatchNetwork")
    print(MatchNetwork)
    for z in MatchNetwork:
        graph_z = Graph(password="myneo2")
        # statement="MATCH (s:Hosts {Name:'"+z['Name']+"'})-[r]-(d:Hosts) RETURN s,d,r"
        statement1 = "MATCH (s:Hosts)-[r]->(d:Hosts) WHERE s.Name='" + \
            z['Name']+"' RETURN s,d,r"
        statement2 = "MATCH (s:Hosts)-[r]->(d:Hosts) WHERE d.Name='" + \
            z['Name']+"' RETURN s,d,r"
        # MATCH p=(s:Hosts)-[r:"+searchterm+"]->(d:Hosts) RETURN s as source,d as target,r as service LIMIT 5 #to search
        print(statement1)
        output1 = graph_z.run(statement1).data()
        print(len(output1))
        print(output1)
        print(statement2)
        output2 = graph_z.run(statement2).data()
        print(len(output2))
        print(output2)
        print("Printing matched nodes relationships")
        # MatchNodes.append
        if output1 != []:
            MatchRel.append(output1)
        if output2 != []:
            MatchRel.append(output2)
    # out={}
    # out={"MatchNetwork":MatchNetwork}
    print("=====================================================================================")
    print(MatchRel)
    finalgrouping =  FinalGrouping(MatchRel)
    print("finalgroupingtest1")
    print(finalgrouping)
    return(MatchRel, finalgrouping)

def Convert_to_IP_Network(  output):
    Node = []
    NoDupNode = []
    for item1 in output:
        for item in item1:
            nodes_source = {}
            nodes_target = {}
            name_ip_host = {}
            name_ip_net = {}
            # Assign the name of the node to ID
            nodes_source['Name'] = item['s']['Name']
            nodes_source['IPAddress'] = item['s']['IPAddress']
            nodes_source['Mask'] = item['s']['Mask']
            nodes_source['Comments'] = item['s']['Comments']
            if (item['s']['Mask'] == "NA"):
                nodes_source['Network'] = item['s']['IPAddress']
            # & (item['n']['IPAddress']!="10.15.208.0") & (item['n']['IPAddress']!="10.18.112.0")
            if (item['s']['Mask'] != "NA"):
                cip = item['s']['IPAddress']+"/"+item['s']['Mask']
                nodes_source['Network'] = cip
            # ab=ip_network(nodes_source['Network'],strict=False)
            # nodes_source['Network']=ab
            nodes_target['Name'] = item['d']['Name']
            nodes_target['IPAddress'] = item['d']['IPAddress']
            nodes_target['Mask'] = item['d']['Mask']
            nodes_target['Comments'] = item['d']['Comments']
            if (item['d']['Mask'] == "NA"):
                nodes_target['Network'] = item['d']['IPAddress']
            # & (item['n']['IPAddress']!="10.15.208.0") & (item['n']['IPAddress']!="10.18.112.0")
            if (item['d']['Mask'] != "NA"):
                cip = item['d']['IPAddress']+"/"+item['d']['Mask']
                nodes_target['Network'] = cip
            cd = ip_network(nodes_target['Network'], strict=False)
            nodes_target['Network'] = cd
            Node.append(nodes_source)
            Node.append(nodes_target)
    for x in Node:
        if x not in NoDupNode:
            NoDupNode.append(x)
    return NoDupNode

def FinalGrouping(  finalarray):
    print("Printing final array")
    NameAndIP =  Convert_to_IP_Network(finalarray)
    print(NameAndIP)
    ParentChild = []
    NoDupParentChild = []
    graph = Graph(password="myneo2")
    statement = "MERGE (d:Groups) RETURN d"
    # fetch the source, target and relationship details
    Grouping = graph.run(statement).data()
    number_of_colors = len(Grouping)
    

    Groups = []
    for rot in range(number_of_colors):
        grp = {}
        grp['Name'] = Grouping[rot]['d']['Name']
        grp['IPAddress'] = Grouping[rot]['d']['IPAddress']
        grp['color'] = Grouping[rot]['d']['color']
        Groups.append(grp)
    print(Groups)

    for y in NameAndIP:
        for Group in Groups:
            ab = ip_network(y['Network'], strict=False)
            print(IPv4Network(ab))
            print(IPv4Network(Group['IPAddress']))
            c = ip_network(IPv4Network(ab), strict=False)
            d = ip_network(IPv4Network(Group['IPAddress']), strict=False)
            # if IPv4Network(ab) in IPv4Network(Group['d']['IPAddress']):
            if c.subnet_of(d):
                par_child = {}
                print(IPv4Network(ab))
                print(IPv4Network(Group['IPAddress']))
                # par_child="sdsadsa"
                par_child['ChildName'] = y['Name']
                par_child['ParentName'] = Group['Name']
                par_child['Parent_IP'] = Group['IPAddress']
                par_child['color'] = Group['color']
                ParentChild.append(par_child)
    for x in ParentChild:
        if x not in NoDupParentChild:
            NoDupParentChild.append(x)
    print("==============Printing NoDupParentChild===============")
    return (NoDupParentChild)

def FinalGroupingv2(  finalarray):
    try:
        print("================Printing final array==================")
        NameAndIP =  Convert_to_IP_Network(finalarray)
        # print(NameAndIP)
        ParentChild = []
        NoDupParentChild = []
        user=config.get('neo4j', 'user')
        password=config.get('neo4j', 'passwd')
        graph = Graph(host=config.get('neo4j', 'host'),auth=(user,password))
        # graph = Graph(password="myneo2")
        statement = "MERGE (d:Groups) RETURN d"
        
        # fetch the source, target and relationship details
        Grouping = graph.run(statement).data()
        number_of_colors = len(Grouping)
        Groups = []
        AllIPNetwork = []
        for rot in range(number_of_colors):
            grp = {}
            grp['Name'] = Grouping[rot]['d']['Name']
            grp['IPAddress'] = Grouping[rot]['d']['IPAddress']
            grp['color'] = Grouping[rot]['d']['color']
            Groups.append(grp)
            # if not for strict=false, typeerror will be raised as "with hostbits set"!
            ab = ip_network(Grouping[rot]['d']['IPAddress'], strict=False)
            AllIPNetwork.append(ab)

        arrangedones =  ArrangeNodesv2(Grouping)
        #arrangedones = self.ArrangeNodes(AllIPNetwork)
        print("=====================  Printing the arranged ones  =============")
        print(arrangedones)
        print("=====================  Printed the arranged ones  =============")
        GrpParChd = []

        # this is to access the pair {depth0:[xx]}
        for evry in arrangedones:
            print(evry)  # key values
            # this is to access the array in values of key/value pairs
            for evry2 in arrangedones[evry]:
                print(evry2)
                x = len(evry2)-1
                print(x)  # no of elements in values array

                while (x >= 0):
                    grpparchild = {}
                    if (x == 0):
                        y = x
                        print(x, evry2[x], y, evry2[y])
                        print(evry2[x], " is subnet of ", evry2[y])
                        grpparchild[evry2[x]] = evry2[y]
                        GrpParChd.append(grpparchild)
                    else:
                        y = x-1
                        print(x, evry2[x], y, evry2[y])
                        while (y >= 0):
                            if (evry2[x].subnet_of(evry2[y])):
                                print(evry2[x], " is subnet of ", evry2[y])
                                grpparchild[evry2[x]] = evry2[y]
                                GrpParChd.append(grpparchild)
                                break
                            y -= 1
                    x -= 1
        print("========== Parent Child pair in Groups=======")
        print(GrpParChd)

        GrpNodes = []

        for Group in Groups:
            d = ip_network(Group['IPAddress'], strict=False)
            grp_item = {}
            # print("========== Printing only keys in Groups=======")
            # print(k)
            for evrypair in GrpParChd:
                for k, v in evrypair.items():  # for k,v in list(a.items():
                    if(d == k):
                        print("&&&&&&&&&&&& Comparing &&&&&&&&&&&&")
                        print(d, k, v)
                        for grpk in Group.keys():
                            grp_item[grpk] = Group[grpk]
                        grp_item['id'] = Group['Name']
                        grp_item['isgrp'] = "true"
                        print(
                            "!!!!!!!!!!!!!!!! Key-value pairs so far !!!!!!!!!!!!!!!!11")
                        print(grp_item)
                        for Grouppar in Groups:
                            print(
                                "*****************All values from groups********************")
                            print(Grouppar)
                            d_par = ip_network(
                                Grouppar['IPAddress'], strict=False)
                            if(d_par == v):
                                print(
                                    "*****************Entered into matched parent group********************")
                                print(d_par, v)
                                grp_item['parent'] = Grouppar['Name']
                        GrpNodes.append(grp_item)


        print(
            "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^Nodes format for groups^^^^^^^^^^^^^^^^")
        logger.info("GrpNodes:")
        logger.info(GrpNodes)
        print(GrpNodes)

        print("========== Parent Child pair in Groups (reverse)=======")
        #GrpParChdreverse = GrpParChd.reverse()
        print(list(reversed(GrpParChd)))
        print("========== Print Groups=======")
        print(Groups)
        print("========== All IP Network=======")
        print(AllIPNetwork)
        ip_list_sorted = sorted(AllIPNetwork)
        SortedReversedAllIPNetwork = list(reversed(ip_list_sorted))
        print("================Printing SortedReversedAllIPNetwork===============")
        print(SortedReversedAllIPNetwork)

        for y in NameAndIP:
            ab = ip_network(y['Network'], strict=False)
            c = ip_network(IPv4Network(ab), strict=False)
            for matchsortedIpnetwork in SortedReversedAllIPNetwork:
                e = ip_network(IPv4Network(
                    matchsortedIpnetwork), strict=False)
                if c.subnet_of(e):
                    # print(c,e)
                    i = 0
                    while(i < len(Groups)):
                        #d = ip_network(IPv4Network(Groups[i]['IPAddress']), strict=False)
                        d = ip_network(
                            Groups[i]['IPAddress'], strict=False)
                        #print(d, " ; ",e)
                        if (d == e):
                            print(d, e, i)
                            print(Groups[i]['Name'], Groups[i]['color'])
                            par_child = {}
                            par_child['ChildName'] = y['Name']
                            par_child['ParentName'] = Groups[i]['Name']
                            par_child['Parent_IP'] = Groups[i]['IPAddress']
                            par_child['color'] = Groups[i]['color']
                            ParentChild.append(par_child)
                        i += 1
        # node_any = {}
        # node_any['Name'] = "Any"
        # node_any['color'] = "#ffff80"
        # ParentChild.append(node_any)
        for x in ParentChild:
            if x not in NoDupParentChild:
                NoDupParentChild.append(x)
        print("==============Printing NoDupParentChild===============")
        print(NoDupParentChild)
        return (NoDupParentChild, GrpNodes)

        print("========== End of new attempt=======")
    except Exception as e:
        logger.exception("%s", e)


def groupheirarchy(  statement):
    try:
        user=config.get('neo4j', 'user')
        password=config.get('neo4j', 'passwd')
        graph = Graph(host=config.get('neo4j', 'host'),auth=(user,password))
        Grouping = graph.run(statement).data()

        number_of_colors = len(Grouping)
        Groups = []
        AllIPNetwork = []
        for rot in range(number_of_colors):
            grp = {}
            grp['Name'] = Grouping[rot]['d']['Name']
            grp['IPAddress'] = Grouping[rot]['d']['IPAddress']
            grp['color'] = Grouping[rot]['d']['color']
            Groups.append(grp)
            # if not for strict=false, typeerror will be raised as "with hostbits set"!
            ab = ip_network(Grouping[rot]['d']['IPAddress'], strict=False)
            AllIPNetwork.append(ab)

        arrangedones =  ArrangeNodesv2(Grouping)


        GrpParChd = []

        # this is to access the pair {depth0:[xx]}
        for evry in arrangedones:
            print(evry)  # key values
            # this is to access the array in values of key/value pairs
            for evry2 in arrangedones[evry]:
                print(evry2)
                x = len(evry2)-1
                print(x)  # no of elements in values array

                while (x >= 0):
                    grpparchild = {}
                    if (x == 0):
                        y = x
                        print(x, evry2[x], y, evry2[y])
                        print(evry2[x], " is subnet of ", evry2[y])
                        grpparchild[evry2[x]] = evry2[y]
                        GrpParChd.append(grpparchild)
                    else:
                        y = x-1
                        print(x, evry2[x], y, evry2[y])
                        while (y >= 0):
                            if (evry2[x].subnet_of(evry2[y])):
                                print(evry2[x], " is subnet of ", evry2[y])
                                grpparchild[evry2[x]] = evry2[y]
                                GrpParChd.append(grpparchild)
                                break
                            y -= 1
                    x -= 1
        print("========== Parent Child pair in Groups=======")
        print(GrpParChd)

        GrpNodes = []

        for Group in Groups:
            d = ip_network(Group['IPAddress'], strict=False)
            grp_item = {}
            # print("========== Printing only keys in Groups=======")
            # print(k)
            for evrypair in GrpParChd:
                for k, v in evrypair.items():  # for k,v in list(a.items():
                    if(d == k):
                        print("&&&&&&&&&&&& Comparing &&&&&&&&&&&&")
                        print(d, k, v)
                        for grpk in Group.keys():
                            grp_item[grpk] = Group[grpk]
                        grp_item['id'] = Group['Name']
                        grp_item['label'] = Group['Name'] +" ("+ Group['IPAddress']+")"
                        grp_item['isgrp'] = "true"
                        print(
                            "!!!!!!!!!!!!!!!! Key-value pairs so far !!!!!!!!!!!!!!!!11")
                        print(grp_item)
                        for Grouppar in Groups:
                            print(
                                "*****************All values from groups********************")
                            print(Grouppar)
                            d_par = ip_network(
                                Grouppar['IPAddress'], strict=False)
                            if(d_par == v):
                                print(
                                    "*****************Entered into matched parent group********************")
                                print(d_par, v)
                                # grp_item['parent'] = Grouppar['Name']
                        GrpNodes.append(grp_item)
        print(
            "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^Nodes format for groups^^^^^^^^^^^^^^^^")
        print(GrpNodes)
        Node = []
        NoDupNode = []

        for eve in GrpNodes:
            print("+++++++++++++++++++ Printing every nodes in groups+++++++++++")
            print(eve)
            nodes_datawrapper_grp = {}
            nodes_datawrapper_grp['data'] = eve
            Node.append(nodes_datawrapper_grp)
        for x in Node:
            if x not in NoDupNode:
                NoDupNode.append(x)



        print("========== Parent Child pair in Groups (reverse)=======")
        Link = []
        for evrypair in GrpParChd:
            for k, v in evrypair.items():  # for k,v in list(a.items():
                if (k!=v):
                    links_datawrapper = {}
                    grp_link = {}
                    for Group in Groups:
                        d = ip_network(Group['IPAddress'], strict=False)                            
                        if (d==k):
                            grp_link['target'] = Group['Name']
                        if (d==v):
                            grp_link['source'] = Group['Name']
                    # Group_Link.append(grp_link)
                    links_datawrapper['data'] = grp_link
                    Link.append(links_datawrapper)
        print("========================== Built the LInk ==================")
        print(Link)


        print("========== Print Groups=======")
        print(Groups)
        print("========== All IP Network=======")
        print(AllIPNetwork)
        ip_list_sorted = sorted(AllIPNetwork)
        SortedReversedAllIPNetwork = list(reversed(ip_list_sorted))
        print("================Printing SortedReversedAllIPNetwork===============")
        print(SortedReversedAllIPNetwork)

        print("==============Printing NoDupParentChild===============")
        print (NoDupNode, Link)

        return (NoDupNode, Link)

        print("========== End of new attempt=======")
    except Exception as e:
        logger.exception("%s", e)


def ArrangeNodesv2(  newlist):
    ax = ip_network('10.0.0.0/8', strict=False)
    b = ip_network('192.168.4.0/25', strict=False)
    c = ip_network('192.168.9.0/25', strict=False)
    # 192.168.10.0/22 is considered as 192.168.8.0/22 #CHECKTHIS
    d = ip_network('10.0.0.0/8', strict=False)
    e = ip_network('192.168.9.0/26', strict=False)
    f = ip_network('192.168.9.0/24', strict=False)
    #newlist = self.GetAllNodes(statement)
    ip_list = newlist
    print("===========================printing the incoming groups array===========================")
    print(ip_list)
    AllIPNetwork = []
    for rotate in ip_list:
        # if not for strict=false, typeerror will be raised as "with hostbits set"!
        ab = ip_network(rotate['d']['IPAddress'], strict=False)
        AllIPNetwork.append(ab)

    ip_list_sorted = sorted(AllIPNetwork)
    print("===========================printing the SORTED incoming groups array===========================")
    print(ip_list_sorted)

    x = 0
    y = 0

    z = 0
    a = dict()
    depth_z = []
    firstentry = 1
    firstfirstentry = 1
    index = x
    while y < len(ip_list_sorted):

        ipx = ip_network((ip_list_sorted[x]), strict=False) #this uses ipaddress module
        ipy = ip_network((ip_list_sorted[y]), strict=False)
        ipindex = ip_network((ip_list_sorted[index]), strict=False)

        print("ipindex: ", ipindex, " ipx: ", ipx, " ipy: ", ipy)

        if ipy.subnet_of(ipx):
            print("it is a subnet")
            depth_z.append(ip_list_sorted[y])
            if y == len(ip_list_sorted)-1:
                a["depth_"+str(z)] = []
                a["depth_"+str(z)].append(depth_z)
                z += 1
            # x=y
            # print(x)

        if not ipy.subnet_of(ipx):

            if ipy.subnet_of(ipindex):
                print("it is not a subnet")
                x = y
                print(x)

            if not ipy.subnet_of(ipindex):
                a["depth_"+str(z)] = []
                a["depth_"+str(z)].append(depth_z)
                z += 1
                depth_z = []
                print(
                    "it is not a subnet of ipx and ipindex, so adding a new entry to the depth_z")
                depth_z.append(ip_list_sorted[y])
                index = y
                x = y
            if y == len(ip_list_sorted)-1:
                a["depth_"+str(z)] = []
                a["depth_"+str(z)].append(depth_z)
                z += 1

        y += 1
        print("=====================  a  ====")
    print(a)
    return (a)

def GetAllNodes(  statement):
    user=config.get('neo4j', 'user')
    password=config.get('neo4j', 'passwd')
    graph = Graph(host=config.get('neo4j', 'host'),auth=(user,password))
    # graph = Graph(password="myneo2")
    output = graph.run(statement).data()
    Node = []
    NameAndIP = []
    NoDupNode = []
    AllIPNetwork = []
    MatchNodes = []
    print("========================================================================================================")
    print(output)
    for item in output:
        nodes_source = {}
        name_ip = {}
        nodes_source['Name'] = item['n']['Name']
        nodes_source['IPAddress'] = item['n']['IPAddress']
        nodes_source['Mask'] = item['n']['Mask']
        nodes_source['Comments'] = item['n']['Comments']
        Node.append(nodes_source)
        # & (item['n']['IPAddress']!="10.15.208.0") & (item['n']['IPAddress']!="10.18.112.0")
        if (item['n']['Mask'] != "NA"):
            cip = item['n']['IPAddress']+"/"+item['n']['Mask']
            name_ip['Name'] = item['n']['Name']
            name_ip['Network'] = cip
            NameAndIP.append(name_ip)
    for y in NameAndIP:
        # if not for strict=false, typeerror will be raised as "with hostbits set"!
        ab = ip_network(y['Network'], strict=False)
        AllIPNetwork.append(ab)
    AllIPNetwork.sort()
    out = {}
    out = {"NameAndIP": AllIPNetwork}
    # newhelo ="helo"
    # return(AllIPNetwork)
    return(out)

def GetRelationshipFromNeo4jv3(  statement):
    user=config.get('neo4j', 'user')
    password=config.get('neo4j', 'passwd')
    graph = Graph(host=config.get('neo4j', 'host'),auth=(user,password))
    # graph = Graph(password="myneo2")
    # fetch the source, target and relationship details
    print(statement)
    output = graph.run(statement).data()
    output1 = []
    output1.append(output)
    finalgrouping, GrpNodes =  FinalGroupingv2(output1)
    # print("################################################################3")
    # print(finalgrouping)
    return(output1, finalgrouping, GrpNodes)

