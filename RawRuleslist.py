import sqlite3
import csv
import pandas as pd
import os
import time
import logging
import traceback
import configparser


# Gets or creates a logger
logger = logging.getLogger(__name__)
 
# # set log level
logger.setLevel(logging.INFO)

#config object to pull the password from conf file
config = configparser.ConfigParser()
config.read('conf/creds.ini')

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

db_location=config.get('sqliteDB', 'database_folder')

# Create target Directory if don't exist
if not os.path.exists(db_location):
    os.mkdir(db_location)
    print("[*] Directory \'"+db_location+"\' Created ")
else:    
    print("[*] Directory \'"+db_location+"\' already exists")
 
#Get all databasenames,tablenames for dropdown menu
def getalltablenames():
    # sqlitedb = db
    
    db=config.get('sqliteDB', 'DATABASES').split(',')
    db_array =[]
    table_array=[]
    for x in db:
        # sqlite_file = db_location+x+'.db' 
        sqlite_file = db_location+"\\\\"+x+'.db'   
        # Connecting to the database file
        conn = sqlite3.connect(sqlite_file)
        c = conn.cursor()
        c.execute("SELECT name from sqlite_master where type= 'table' and name NOT LIKE 'service_%';")
        
        tablenames = c.fetchall()
        db_array.append(x)
        table_array.append(tablenames)
    return(db_array,table_array)
 
def updatedbsinconfig(db):
    CurrentDBs = config.get('sqliteDB', 'DATABASES').split(',')
    print(CurrentDBs)
    inArray = 0
    if(db in CurrentDBs):
        inArray = 1
        logger.info(str(db)+"already in the config file")
    else:
        if CurrentDBs!="": #If there are other databases entries in the config file, add the new db after comma
            DATABASES = config.get('sqliteDB', 'DATABASES')+','+db
        if CurrentDBs==['']: #If there are no databases entries in the config file, add the new db as first entry
            DATABASES = db
        config.set("sqliteDB","DATABASES",DATABASES)
        with open('conf/creds.ini', 'w') as configfile:
            config.write(configfile)            
            

#Create table in the database
def CreateTable(db,table,typeoffile,header_lst):
    if typeoffile=='rules':
        try:
            updatedbsinconfig(db)            
            sqlite_file = db_location+"\\\\"+db+'.db'     
            table_name1 = table  # name of the table to be created
            #  No.	Type	Name	Source	Destination	VPN	Services & Applications	Content	Action	Track	Install On

            new_field1 = 'No'  # name of the column
            new_field2 = 'Type'  # name of the column
            new_field3 = 'Name'  # name of the column
            new_field4 = 'Source'  # name of the column
            new_field5 = 'Destination'  # name of the column
            new_field6 = 'Service'  # name of the column
            new_field7 = 'Action'  # name of the column
            new_field8 = 'Risk'  # name of the column
            new_field9 = 'InttoInt'  # name of the column
            new_field10 = 'InttoExt'  # name of the column
            new_field11 = 'ExttoInt'  # name of the column
            new_field12 = 'ExttoExt'  # name of the column
            new_field13 = 'RiskReason'  # name of the column
            new_field14 = 'ExcludeIP'  # name of the column
            new_field15 = 'ExcludeRule'  # name of the column

            field_type = 'STRING'  # column data type

            # Connecting to the database file
            conn = sqlite3.connect(sqlite_file)
            c = conn.cursor()

            c.execute('CREATE TABLE {tn} ({nf1} {ft1},{nf2} {ft2},{nf3} {ft3},{nf4} {ft4},{nf5} {ft5},{nf6} {ft6},{nf7} {ft7},{nf8} {ft8},{nf9} {ft9},{nf10} {ft10},{nf11} {ft11},{nf12} {ft12},{nf13} {ft13},{nf14} {ft14},{nf15} {ft15})'.format(tn=table_name1, nf1=new_field1,
                                                                                                    ft1=field_type, nf2=new_field2, ft2=field_type, nf3=new_field3, ft3=field_type, nf4=new_field4, ft4=field_type, nf5=new_field5, ft5=field_type, nf6=new_field6, ft6=field_type, nf7=new_field7, ft7=field_type,nf8=new_field8, ft8=field_type, nf9=new_field9, ft9=field_type, nf10=new_field10, ft10=field_type, nf11=new_field11, ft11=field_type,nf12=new_field12, ft12=field_type,nf13=new_field13, ft13=field_type,nf14=new_field14, ft14=field_type,nf15=new_field15, ft15=field_type))

            # # Creating a new SQLite table with 1 column
            # c.execute('CREATE TABLE {tn} ({nf1} {ft1},{nf2} {ft2})'\
            #         .format(tn=table_name1,nf1=new_field1,ft1=field_type1,nf2=new_field2,ft2=field_type2))

            '''
            # Creating a second table with 1 column and set it as PRIMARY KEY
            # note that PRIMARY KEY column must consist of unique values!
            c.execute('CREATE TABLE {tn} ({nf} {ft} PRIMARY KEY)'\
                    .format(tn=table_name2, nf=new_field, ft=field_type))
            '''
            # Committing changes and closing the connection to the database file
            conn.commit()
            conn.close()
            return("Table created")

        # except sqlite3.OperationalError as e:
        except Exception as e:
            return("Error creating table. Please check if the table already exists")

    if typeoffile=='netobj':
        try:
            updatedbsinconfig(db)
            print("reached netobj")
            print(db,table,typeoffile,header_lst)
            # sqlite_file = db_location+"\\\\"+db+'.db' 
            sqlite_file = db_location+"\\\\"+db+'.db'     
            table_name1 = "netobj"
            field_type = 'STRING'  # column data type
            # Connecting to the database file
            conn = sqlite3.connect(sqlite_file)
            c = conn.cursor()
            base=""
            base1=""
            base2=""

            a = {}
            k = 0
            while k < len(header_lst):
                a['key'+str(k)]=header_lst[k]
                k+=1
            print(a)

            requery2 = ""   
            for i in range(len(header_lst)):
                j=i+1

                if j==len(header_lst):
                    base1 = base1+"{nf"+str(j)+"} {ft"+str(j)+"}"
                    base2= base2+"nf"+str(j)+"=\'"+header_lst[i]+"\',ft"+str(j)+"=field_type"
                    requery2 = requery2+"\'" +header_lst[i]+"\'"+" STRING DEFAULT \"\""
                else:
                    base1 = base1+"{nf"+str(j)+"} {ft"+str(j)+"},"
                    base2= base2+"nf"+str(j)+"=\'"+header_lst[i]+"\',ft"+str(j)+"=field_type,"
                    
                    requery2 = requery2+"\'"+ header_lst[i]+"\'"+" STRING DEFAULT \"\","
            requery2 =requery2 +",'Internal' STRING DEFAULT \"\",'External' STRING DEFAULT \"\""
            #query = "'CREATE TABLE {tn} ("+base1+")'.format(tn=table_name1, "+base2+")"
            requery1 = "CREATE TABLE IF NOT EXISTS "+table_name1+" ("
            requery3=")"
            requery=requery1+requery2+requery3
            logger.info("SQL Query:"+requery)
            # print(query)
            c.execute(requery)
            conn.commit()
            conn.close()
            return("Table created")          

            # c.execute('CREATE TABLE {tn} ({nf1} {ft1},{nf2} {ft2},{nf3} {ft3})'.format(tn=table_name1, nf1=new_field1,ft1=field_type, nf2=new_field2, ft2=field_type))
        except Exception as e:
            return("Error creating table. Please check if the table already exists")
      
    
    if typeoffile=='services':
        try:
            updatedbsinconfig(db)
            print("reached services")
            print(db,table,typeoffile,header_lst)
            # sqlite_file = db_location+"\\\\"+db+'.db' 
            sqlite_file = db_location+"\\\\"+db+'.db'     
            table_name1 = "services"
            field_type = 'STRING'  # column data type
            # Connecting to the database file
            conn = sqlite3.connect(sqlite_file)
            c = conn.cursor()
            base=""
            base1=""
            base2=""

            a = {}
            k = 0
            while k < len(header_lst):
                a['key'+str(k)]=header_lst[k]
                k+=1
            print(a)

            requery2 = "'Protocol' STRING,'Proto:Port'  STRING,"   
            for i in range(len(header_lst)):
                j=i+1

                if j==len(header_lst):
                    base1 = base1+"{nf"+str(j)+"} {ft"+str(j)+"}"
                    base2= base2+"nf"+str(j)+"=\'"+header_lst[i]+"\',ft"+str(j)+"=field_type"
                    requery2 = requery2+"\'" +header_lst[i]+"\'"+" STRING  DEFAULT \"\""
                else:
                    base1 = base1+"{nf"+str(j)+"} {ft"+str(j)+"},"
                    base2= base2+"nf"+str(j)+"=\'"+header_lst[i]+"\',ft"+str(j)+"=field_type,"
                    
                    requery2 = requery2+"\'"+ header_lst[i]+"\'"+" STRING  DEFAULT \"\","
            requery2 =requery2 +",'Insecure' STRING  DEFAULT \"\",'ItoE' STRING  DEFAULT \"\",'EtoI' STRING  DEFAULT \"\""
            #query = "'CREATE TABLE {tn} ("+base1+")'.format(tn=table_name1, "+base2+")"
            requery1 = "CREATE TABLE IF NOT EXISTS "+table_name1+" ("
            requery3=")"
            requery=requery1+requery2+requery3
            logger.info("SQL Query:"+requery)
            # print(query)
            c.execute(requery)
            conn.commit()
            conn.close()
            return("Table created")          

            # c.execute('CREATE TABLE {tn} ({nf1} {ft1},{nf2} {ft2},{nf3} {ft3})'.format(tn=table_name1, nf1=new_field1,ft1=field_type, nf2=new_field2, ft2=field_type))
        except Exception as e:
            return("Error creating table. Please check if the table already exists")
      
#Upload data to the table
def uploadSqlite(uploadfilename,db, tablename, src_select, dst_select, ser_select):
    print("#############################")
    touploadfile = "uploads\\"+uploadfilename
    print(touploadfile)
    df = pd.read_csv(touploadfile, index_col=False)
    df.fillna(value='NA', inplace=True)
    x = 0  # x is to traverse all lineitems in dataframe
    headers = list(df)  # header values
    sqlite_file = db_location+"\\\\"+db+'.db'     
    # sqlite_file = db_location+db+'.db'
    conn = sqlite3.connect(sqlite_file)
    print(df)
    
    while x < len(df):
        #  No.	Type	Name	Source	Destination	VPN	Services & Applications	Content	Action	Track	Install On
        
        # logger.info(str(df.loc[x][0]))
        if (df.loc[x][0]!="NA"):
            Num = str(df.loc[x][0])
            Type = str(df.loc[x][1])
            Name = str(df.loc[x][2])
            src = df.loc[x][3]
            dst = df.loc[x][4]
            service = df.loc[x][6]
            action = df.loc[x][8]
            risk =0
            inttoint = ""
            inttoext = ""
            exttoint = ""
            exttoext = ""
            riskreason = ""
            excludeip = ""
            excluderule = ""
            # logger.info("Uploading Rules data to sqlite")
            # logger.info(Num,src,dst,service)
            conn.execute('INSERT INTO {tn} (No,Type,Name,Source,Destination,Service,Action,Risk,InttoInt,InttoExt,ExttoInt,ExttoExt,RiskReason,ExcludeIP,ExcludeRule)\
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'.format(tn=tablename),(Num,Type,Name,src,dst,service,action,risk,inttoint,inttoext,exttoint,exttoext,riskreason,excludeip,excluderule))
            conn.commit()
        x+=1
    conn.close()

def uploadSqlitenetobj(uploadfilename,db):
    tablename = "netobj" # name of the table     
    touploadfile = "uploads\\"+uploadfilename
    df = pd.read_csv(touploadfile, index_col=False) 
    df.fillna(value='NA', inplace=True)
    x = 0  # x is to traverse all lineitems in dataframe
    y = 0
    headers = list(df)  # header values
    sqlite_file = db_location+"\\\\"+db+'.db'     
    # sqlite_file = db_location+db+'.db'
    conn = sqlite3.connect(sqlite_file)
    # headers_query="'Protocol','Proto:Port',"
    headers_query=""
    while y <len(headers):
        if y==(len(headers)-1):
            headers_query=headers_query+"'"+headers[y]+"'"
        else:
            headers_query=headers_query+"'"+headers[y]+"'"+","
        y+=1
    # headers_query=headers_query+","+"'Internal'"+","+"'External'"
    while x < len(df):
        if(df.loc[x][1])!="NA":            
            query2=""
            #query2_protoport="'"+protocol+":"+df.loc[x][1]+"'"+","
            z=0
            while z <len(headers):
                if z==(len(headers)-1):
                    query2=query2+"'"+str(df.loc[x][z])+"'"                
                else:
                    query2=query2+"'"+str(df.loc[x][z])+"'"+","
                z+=1
            # query2=query2+","+""+","+""
            # VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'.format(tn=tablename),(Num,Type,Name,src,dst,service,action,risk,inttoint,inttoext,exttoint,exttoext,riskreason,excludeip,excluderule))
            query1= "INSERT INTO "+tablename+" ("+headers_query+") VALUES ("+query2+")"
            logger.info("SQL Query:"+query1)
            conn.execute(query1)
            conn.commit()        
        x+=1
    conn.close()
    
    

def uploadSqliteservices(uploadfilename,db, tablename):
    touploadfile = "uploads\\"+uploadfilename
    print(touploadfile)
    protocol = os.path.splitext(tablename)[0]
    # tablename = "services_"+os.path.splitext(tablename)[0]  # name of the table     
    tablename = "services" # name of the table     
    # df = pd.read_csv(touploadfile,index=False)
    df = pd.read_csv(touploadfile, index_col=False) 
    df.fillna(value='NA', inplace=True)
    df = df.replace({'\'': '"'}, regex=True) #to replace all instances of single quotes with double quotes
    x = 0  # x is to traverse all lineitems in dataframe
    y = 0
    headers = list(df)  # header values

    sqlite_file = db_location+"\\\\"+db+'.db'     
    # sqlite_file = db_location+db+'.db'
    conn = sqlite3.connect(sqlite_file)
    headers_query="'Protocol','Proto:Port',"
    while y <len(headers):
        if y==(len(headers)-1):
            headers_query=headers_query+"'"+headers[y]+"'"
        else:
            headers_query=headers_query+"'"+headers[y]+"'"+","
        y+=1
    
    while x < len(df):
        query2="'"+protocol+"'"+","
        query2_protoport="'"+protocol+":"+df.loc[x][1]+"'"+","
        query2=query2+query2_protoport
        print(protocol)
        z=0
        while z <len(headers):
            if z==(len(headers)-1):
                query2=query2+"'"+df.loc[x][z]+"'"
            else:
                query2=query2+"'"+df.loc[x][z]+"'"+","
            z+=1
        query1= "INSERT INTO "+tablename+" ("+headers_query+") VALUES ("+query2+")"
        logger.info("SQL Query:"+query1)
        conn.execute(query1)
        conn.commit()        
        x+=1
    conn.close()
            
            # query1= "INSERT INTO "+tablename+" ("+headers_query") VALUES ("+df.loc[x][z]+")"
    
    # while x < len(df):
        
            

        # conn.execute('INSERT INTO {tn} (No,Type,Name,Source,Destination,Service,Action)\
        #     VALUES (?,?,?,?,?,?,?)'.format(tn=tablename),(Num,Type,Name,src,dst,service,action))

def retrieveriskreason(dbname,tablename,riskid):
    try:
        sqlite_file = db_location+"\\\\"+dbname+'.db'      
        conn = sqlite3.connect(sqlite_file)
        conn.row_factory = lambda cursor, row: row[0]
        c = conn.cursor()
        colname="No"
        retrieve_column = "RiskReason"
        c.execute('SELECT {rc} FROM {tn} WHERE {cn}={rid}'.format(rc=retrieve_column,tn=tablename,cn=colname,rid=riskid))
        all_rows = c.fetchall()
        conn.close() # Closing the connection to the database file
        return(all_rows)
    except:
        conn.rollback()
        print("Error in Insert")
    
 
def ReadSqlitenetobj(db,tablename):
    sqlite_file = db_location+"\\\\"+db+'.db'      
    print(sqlite_file)
    conn = sqlite3.connect(sqlite_file)
    #print(conn.execute('SELECT * FROM dubpol;'))
    c = conn.cursor()
    c.execute('SELECT * FROM {tn}'.format(tn=tablename))
    all_rows = c.fetchall()
    # Closing the connection to the database file
    
    allrows =[]
    for row in all_rows:
        #  No.	Type	Name	Source	Destination	VPN	Services & Applications	Content	Action	Track	Install On
        #  Name	IPv4 address	Mask	IPv6 address	Mask 6	NAT Properties	Comments	Tags	Modifier	Last Modified

        r = {}
        r['Name'] = row[0]
        r['IPv4'] = row[1]
        r['Mask'] = row[2]
        r['IPv6'] = row[3]        
        r['Mask6'] = row[4]
        r['NAT'] = row[5]
        r['Comments'] = row[6]
        r['Tags'] = row[7]
        r['Modifier'] = row[8]
        r['LastModified'] = row[9]
        
        allrows.append(r)
    
    conn.close()
    return(allrows)

#Read all data from the table in a particular database
def ReadSqlite(db,tablename):
    sqlite_file = db_location+"\\\\"+db+'.db'      
    print(sqlite_file)
    conn = sqlite3.connect(sqlite_file)
    #print(conn.execute('SELECT * FROM dubpol;'))
    c = conn.cursor()
    c.execute('SELECT * FROM {tn}'.format(tn=tablename))
    all_rows = c.fetchall()
    # Closing the connection to the database file
    
    allrows =[]
    for row in all_rows:
        #  No.	Type	Name	Source	Destination	VPN	Services & Applications	Content	Action	Track	Install On
        r = {}
        r['No'] = row[0]
        r['Type'] = row[1]
        r['Name'] = row[2]
        r['Source'] = row[3]        
        r['Destination'] = row[4]
        r['Service'] = row[5]
        r['Action'] = row[6]
        r['Risk'] = row[7]
        r['InttoInt'] = row[8]
        r['InttoExt'] = row[9]
        r['ExttoInt'] = row[10]
        r['ExttoExt'] = row[11]
        r['RiskReason'] = row[12]
        
        allrows.append(r)
    
    conn.close()
    return(allrows)


def ReadSqlitewSelected(db,tablename,colname):
    sqlite_file = db_location+"\\\\"+db+'.db'      
    print(sqlite_file)
    conn = sqlite3.connect(sqlite_file)
    #value='yes'
    value="\'yes\'" 
    #print(conn.execute('SELECT * FROM dubpol;'))
    c = conn.cursor()
    #"SELECT * from {tn} where {cn}={val}".format(tn=tablename, cn=colname,val=value)
    c.execute('SELECT * FROM {tn} WHERE {cn}={val}'.format(tn=tablename, cn=colname,val=value))
    all_rows = c.fetchall()
    # Closing the connection to the database file
    
    allrows =[]
    for row in all_rows:
        #  No.	Type	Name	Source	Destination	VPN	Services & Applications	Content	Action	Track	Install On
        r = {}
        r['No'] = row[0]
        r['Type'] = row[1]
        r['Name'] = row[2]
        r['Source'] = row[3]        
        r['Destination'] = row[4]
        r['Service'] = row[5]
        r['Action'] = row[6]
        r['Risk'] = row[7]
        r['InttoInt'] = row[8]
        r['InttoExt'] = row[9]
        r['ExttoInt'] = row[10]
        r['ExttoExt'] = row[11]
        r['RiskReason'] = row[12]        
        
        allrows.append(r)
    
    conn.close()
    return(allrows)
 

#Update the risk column 
def UpdateTable(db_name, table_name, column_name,riskvalue, id_column,  idvalue):
    sqlite_file = db_location+"\\\\"+db_name+'.db' 
    # db_name = db_name +'.db'
    conn = sqlite3.connect(sqlite_file)
    print("Opened database successfully")
    c = conn.cursor()
    
      
    print(db_name, table_name, column_name, riskvalue, id_column, idvalue)
    try:
        c.execute("UPDATE {tn} SET {cn}={rv} WHERE {idf}={iv}".\
                format(tn=table_name, cn=column_name, rv=riskvalue, idf=id_column, iv=idvalue))
            
        conn.commit()
        print("Inserted successfully")
    except:
        conn.rollback()
        print("Error in Insert")
    conn.close()

def updateinsecureproto(dbname, tablename, colname, toupdatearray):
    db_name = dbname
    table_name = tablename
    id_column = "Name"
    column_name = colname #Column to update
    toupdatevalue = "yes"

    sqlite_file = db_location+"\\\\"+db_name+'.db' 
    # db_name = db_name +'.db'
    conn = sqlite3.connect(sqlite_file)
    print("Opened database successfully")
    c = conn.cursor()
    print()

    for checkvalue in toupdatearray:
        try:
            print(table_name,column_name,toupdatevalue,id_column,checkvalue)
            query = "UPDATE "+table_name+" SET "+column_name+"='yes' WHERE Name='"+checkvalue+"'"
            logger.info("SQLQuery: "+query)
            c.execute(query)
            # c.execute("UPDATE {tn} SET {cn}={rv} WHERE {idf}={iv}".\
            #         format(tn=table_name, cn=column_name, rv=toupdatevalue, idf=id_column, iv=checkvalue))
            print("Inserted successfully")
        except:
            conn.rollback()
            print("Error in Insert")
        conn.commit()
    conn.close()
    return("updated")
    

def retrieveinsecureprotoconfig(dbname,tablename):
    sqlite_file = db_location+"\\\\"+dbname+'.db' 
    value="\'yes\'"  
    # Connecting to the database file
    conn = sqlite3.connect(sqlite_file)
    c = conn.cursor()
    allservices_array=[]
    queryresult_array=[]
    #SELECT * from services_UDP where Insecure='yes';

    # CREATE TABLE {tn} ({nf1} {ft1},{nf2} {ft2})'.format(tn=table_name1, nf1=new_field1,ft1=field_type, nf8=new_field8, ft8=field_type)
    # 'SELECT * from {tn} where {cn}={val}'.format(tn=tablename, cn=colname,val=value);
    # query='SELECT * from {tn} where {cn}={val}'.format(tn=tablename, cn=colname,val=value);
    c.execute("SELECT * from {tn}".format(tn=tablename))
    allservices =c.fetchall()

    colname="Insecure"    
    c.execute("SELECT * from {tn} where {cn}={val}".format(tn=tablename, cn=colname,val=value))
    queryresult1 =c.fetchall()

    colname="ItoE"    
    c.execute("SELECT * from {tn} where {cn}={val}".format(tn=tablename, cn=colname,val=value))
    queryresult2 =c.fetchall()

    colname="EtoI"    
    c.execute("SELECT * from {tn} where {cn}={val}".format(tn=tablename, cn=colname,val=value))
    queryresult3 =c.fetchall()

    return(allservices,queryresult1,queryresult2,queryresult3)
