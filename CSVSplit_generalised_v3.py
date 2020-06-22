import csv
import pandas as pd
import os
import time
import logging
import traceback
import configparser
import collections
 
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
formatter    = logging.Formatter('%(asctime)s | %(levelname)s | %(name)s | %(funcName)s | :%(lineno)s | %(message)s',datefmt='%y-%m-%d %H:%M:%S')
file_handler.setFormatter(formatter)
 
# add file handler to logger
logger.addHandler(file_handler)



 
def toSplit(splitfilename,src_select,dst_select,ser_select):
    try:
        #Create DataFrame
        tosplitfile = "uploads\\"+splitfilename
        #df = pd.read_csv(tosplitfile)
        # df = pd.read_csv(tosplitfile, index_col=False)
        df = pd.read_csv(tosplitfile,dtype=object, index_col=False)
        
        # df.astype(str)
        print(df)

 
        #Fill empty values with "NA", otherwise it will be filled with "nan" by pandas
        df.fillna(value='NA',inplace=True)

 
        x=0; #x is to traverse all lineitems in dataframe
        headers = list(df) #header values
 
        timestr = time.strftime("%Y%m%d_%H%M%S")
        # dirName = "output"
        dirName = config.get('output', 'OUTPUT_FOLDER')        
        fileName= "Rules_"+timestr
 
        logger.info("Filename: "+fileName)
 
        # Create target Directory if don't exist
        if not os.path.exists(dirName):
            os.mkdir(dirName)
            print("[*] Directory \'"+dirName+"\' Created ")
        else:    
            print("[*] Directory \'"+dirName+"\' already exists")
 
        print("[*] "+fileName+'.csv created in the output folder')
 
 
        # with open("./output/"+fileName+'.csv', 'w', newline='') as csvfile:
        files = config.get('output', 'OUTPUT_FOLDER')
        csvfilename = files+'\\'+fileName+'.csv'
        logger.info("csvFilename: "+str(csvfilename))

        with open(csvfilename, 'w', newline='') as csvfile:
            filewriter = csv.writer(csvfile, delimiter=',',)
            filewriter.writerow(headers) #write headers
 
        #Below three lines are the inputs from the user indicating source, destination and services fields
        selected_src = int(src_select)
        selected_dest = int(dst_select)
        selected_service = int(ser_select)
 
        # logger.info("selected_src: "+str(selected_src))
        # logger.info("selected_dest: "+str(selected_dest))
        # logger.info("selected_service: "+str(selected_service))

        print(df)
 
        while x < len(df):
            logger.info(df.loc[x][0])
            if (df.loc[x][0]!="NA"):
                cols = 0
                build_column = {}
    
                #Below loop is to assign each cell values into key,value pairs Example: 'col1':'xxx','col2':'yyy' etc..
                while cols < len(headers):
                    build_column['col'+str(cols)]=df.loc[x][cols]
                    cols+= 1
    
                srcsplit = build_column['col'+str(selected_src)].split(';')
                dstsplit = build_column['col'+str(selected_dest)].split(';')
                servicesplit = build_column['col'+str(selected_service)].split(';')
    
                
                s = 0    
                while s < len(srcsplit): #each section of ; in the source
                    newsrc = srcsplit[s];
                    s += 1
                    d = 0
                    while d < len(dstsplit): #each section of ; in the destination
                        newdst = dstsplit[d];
                        d += 1
                        ser = 0
                        while ser < len(servicesplit): #each section of ; in the service
                            newservice = servicesplit[ser];
                            ser += 1
                            # Appenddf = pd.read_csv("./output/"+fileName+'.csv')
                            Appenddf = pd.read_csv(csvfilename)
                            # with open(files+fileName+'.csv', 'w', newline='') as csvfile:
                            header_col=0
                            to_append_column = {}
                            while header_col < len(headers):
                                if header_col == selected_src:
                                    to_append_column[headers[(header_col)]]=newsrc
                                elif header_col == selected_dest:
                                    to_append_column[headers[(header_col)]]=newdst
                                elif header_col == selected_service:
                                    to_append_column[headers[(header_col)]]=newservice
                                else:
                                    to_append_column[headers[(header_col)]]=build_column['col'+str(header_col)]
                                header_col+=1
                            with open(csvfilename, 'a', newline='') as csvfileAppend:
                            # with open("./output/"+fileName+'.csv', 'a', newline='') as csvfileAppend:
                                filewriter_append = csv.DictWriter(csvfileAppend,fieldnames=headers)
                                filewriter_append.writerow(to_append_column) #write headers
                            #newdf = Appenddf.append(to_append_column, ignore_index=True) # creating new dataframe by appending the new data frame to the data already in the csv
                            #newdf.to_csv("./output/"+fileName+'.csv', index=False) #writing the new data frame to csv
            x += 1
            #print("[*] "+str(len(df))+" is converted to "+str(len(newdf)))
        return (fileName)
 
    except Exception as e:
        logger.exception("%s",e)
        
def savetoImportDir(fileName):
    try:
        #Create DataFrame
        tosavefile = "uploads\\"+fileName
        # tosavefile1 = "uploads\\"+"newone.csv"
        df = pd.read_csv(tosavefile, index_col=False) 
        
        
        #Fill empty values with "NA", otherwise it will be filled with "nan" by pandas
        df.fillna(value='NA',inplace=True)
        # headers = list(df) #header values
        # print(df)
        files = config.get('output', 'OUTPUT_FOLDER')
        csvfilename = files+'\\'+fileName
        df.to_csv(csvfilename,index=False) 
        logger.info("csvFilename: "+str(csvfilename))        
        # with open(csvfilename, 'w', newline='') as csvfile:
        #     filewriter = csv.writer(csvfile, delimiter=',')
        #     filewriter.writerow(headers) #write headers
        # with open(csvfilename, 'a', newline='') as f:
        #     df.to_csv(f, header=False,index= False)
        # df.to_csv(csvfilename, header=True,index= False) #writing the new data frame to csv      
        return(csvfilename)
    except Exception as e:
        logger.exception("%s",e)

    
 

 
 

